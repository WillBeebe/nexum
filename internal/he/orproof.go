package he

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"math/big"
)

const (
	bitORDomain      = "nexum/he/bit-or-v1\x00"
	maxBitProofBytes = 64 << 10 // 64 KiB
)

// ErrBitProof indicates a malformed, non-canonical, or mathematically invalid
// CDS94 disjunctive {0,1} Paillier OR-proof.
var ErrBitProof = errors.New("he: invalid bit proof")

// bitORProof is a Cramer-Damgård-Schoenmakers (CDS94) disjunctive proof that
// a Paillier ciphertext c in Z_{N^2}* encrypts 0 (c == r^N mod N^2) OR 1
// (c * g^-1 == r^N mod N^2) without revealing which branch holds.
type bitORProof struct {
	A0 []byte `json:"a0"`
	A1 []byte `json:"a1"`
	E0 []byte `json:"e0"`
	E1 []byte `json:"e1"`
	Z0 []byte `json:"z0"`
	Z1 []byte `json:"z1"`
}

func (p *Paillier) validPublic() bool {
	return p != nil && p.n != nil && p.n2 != nil && p.g != nil && p.n.Sign() > 0
}

func decodeBitORProof(proof []byte) (bitORProof, error) {
	if len(proof) < 2 || len(proof) > maxBitProofBytes || proof[0] != '{' || proof[len(proof)-1] != '}' {
		return bitORProof{}, ErrBitProof
	}
	var pf bitORProof
	dec := json.NewDecoder(bytes.NewReader(proof))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return bitORProof{}, ErrBitProof
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return bitORProof{}, ErrBitProof
	}
	return pf, nil
}

func bitORChallenge(mod *big.Int, domain, ct, a0, a1 []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(bitORDomain))
	writeLenFramed(h, mod.Bytes())
	writeLenFramed(h, domain)
	writeLenFramed(h, ct)
	writeLenFramed(h, a0)
	writeLenFramed(h, a1)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// EncryptBitWithR encrypts bit in {0, 1} using a fresh random unit r in Z_N*,
// returning the canonical ciphertext bytes and r. Works on public-key-only
// *Paillier instances from FromPublic.
func (p *Paillier) EncryptBitWithR(bit int) (ct []byte, r *big.Int, err error) {
	if !p.validPublic() || (bit != 0 && bit != 1) {
		return nil, nil, ErrEnc
	}
	r, err = randomUnit(p.n)
	if err != nil {
		return nil, nil, ErrEnc
	}
	ct, err = p.EncryptWithR(big.NewInt(int64(bit)), r)
	if err != nil {
		return nil, nil, err
	}
	return ct, r, nil
}

// MulUnits multiplies two Paillier blinding factors modulo N.
func (p *Paillier) MulUnits(r1, r2 *big.Int) *big.Int {
	if !p.validPublic() || r1 == nil || r2 == nil {
		return nil
	}
	out := new(big.Int).Mul(r1, r2)
	out.Mod(out, p.n)
	return out
}

// Scale computes homomorphic scalar multiplication ct^scalar mod N^2, validating
// ct as a canonical unit in Z_{N^2}* and returning canonical positive bytes.
// For scalar == 0, Scale returns []byte{1} (E(0; r=1)).
func (p *Paillier) Scale(ct []byte, scalar uint64) ([]byte, error) {
	if !p.validPublic() || !isCanonicalPositive(ct) || len(ct) > len(p.n2.Bytes()) {
		return nil, ErrAdd
	}
	c := new(big.Int).SetBytes(ct)
	if !unit(c, p.n2) {
		return nil, ErrAdd
	}
	if scalar == 0 {
		return []byte{1}, nil
	}
	out := new(big.Int).Exp(c, new(big.Int).SetUint64(scalar), p.n2)
	return out.Bytes(), nil
}

// ProveBit builds a CDS94 non-interactive zero-knowledge OR-proof that ct
// encrypts bit in {0, 1} with randomness r under domain separation bytes.
// Works on public-key-only *Paillier instances from FromPublic.
func (p *Paillier) ProveBit(ct, r *big.Int, bit int, domain []byte) ([]byte, error) {
	if !p.validPublic() || (bit != 0 && bit != 1) || !unit(ct, p.n2) || !unit(r, p.n) {
		return nil, ErrEnc
	}
	gInv := new(big.Int).ModInverse(p.g, p.n2)
	if gInv == nil {
		return nil, ErrEnc
	}
	u0 := new(big.Int).Set(ct)
	u1 := new(big.Int).Mod(new(big.Int).Mul(ct, gInv), p.n2)
	u := [2]*big.Int{u0, u1}

	// Ensure witness (ct, r) matches claimed branch before emitting a proof.
	if new(big.Int).Exp(r, p.n, p.n2).Cmp(u[bit]) != 0 {
		return nil, ErrEnc
	}

	sim := 1 - bit
	w, err := randomUnit(p.n)
	if err != nil {
		return nil, ErrEnc
	}
	zSim, err := randomUnit(p.n)
	if err != nil {
		return nil, ErrEnc
	}
	var eSimBytes [sha256.Size]byte
	if _, err := io.ReadFull(rand.Reader, eSimBytes[:]); err != nil {
		return nil, ErrEnc
	}

	var a [2]*big.Int
	a[bit] = new(big.Int).Exp(w, p.n, p.n2)

	uSimInv := new(big.Int).ModInverse(u[sim], p.n2)
	if uSimInv == nil {
		return nil, ErrEnc
	}
	eSim := new(big.Int).SetBytes(eSimBytes[:])
	aSim := new(big.Int).Exp(uSimInv, eSim, p.n2)
	aSim.Mul(aSim, new(big.Int).Exp(zSim, p.n, p.n2))
	aSim.Mod(aSim, p.n2)
	a[sim] = aSim

	ctBytes := ct.Bytes()
	a0Bytes := a[0].Bytes()
	a1Bytes := a[1].Bytes()
	if !isCanonicalPositive(ctBytes) || !isCanonicalPositive(a0Bytes) || !isCanonicalPositive(a1Bytes) {
		return nil, ErrEnc
	}

	challenge := bitORChallenge(p.n, domain, ctBytes, a0Bytes, a1Bytes)

	var e [2][]byte
	e[sim] = append([]byte(nil), eSimBytes[:]...)
	eRealBytes := make([]byte, sha256.Size)
	for i := range eRealBytes {
		eRealBytes[i] = challenge[i] ^ eSimBytes[i]
	}
	e[bit] = eRealBytes

	eReal := new(big.Int).SetBytes(eRealBytes)
	var z [2]*big.Int
	z[sim] = zSim
	zReal := new(big.Int).Exp(r, eReal, p.n)
	zReal.Mul(zReal, w)
	zReal.Mod(zReal, p.n)
	if !unit(zReal, p.n) {
		return nil, ErrEnc
	}
	z[bit] = zReal

	out, err := json.Marshal(bitORProof{
		A0: a0Bytes,
		A1: a1Bytes,
		E0: e[0],
		E1: e[1],
		Z0: z[0].Bytes(),
		Z1: z[1].Bytes(),
	})
	if err != nil {
		return nil, ErrEnc
	}
	return out, nil
}

// VerifyBit verifies a CDS94 disjunctive {0,1} Paillier OR-proof against
// canonical ciphertext ct and domain separation bytes using only the public key.
func (p *Paillier) VerifyBit(ct []byte, proof []byte, domain []byte) error {
	if !p.validPublic() {
		return ErrBitProof
	}
	nLen := len(p.n.Bytes())
	n2Len := len(p.n2.Bytes())
	if !isCanonicalPositive(ct) || len(ct) > n2Len {
		return ErrBitProof
	}
	c := new(big.Int).SetBytes(ct)
	if !unit(c, p.n2) {
		return ErrBitProof
	}
	pf, err := decodeBitORProof(proof)
	if err != nil {
		return err
	}
	if !isCanonicalPositive(pf.A0) || len(pf.A0) > n2Len ||
		!isCanonicalPositive(pf.A1) || len(pf.A1) > n2Len ||
		!isCanonicalPositive(pf.Z0) || len(pf.Z0) > nLen ||
		!isCanonicalPositive(pf.Z1) || len(pf.Z1) > nLen {
		return ErrBitProof
	}
	if len(pf.E0) != sha256.Size || len(pf.E1) != sha256.Size {
		return ErrBitProof
	}
	a0 := new(big.Int).SetBytes(pf.A0)
	a1 := new(big.Int).SetBytes(pf.A1)
	z0 := new(big.Int).SetBytes(pf.Z0)
	z1 := new(big.Int).SetBytes(pf.Z1)
	if !unit(a0, p.n2) || !unit(a1, p.n2) || !unit(z0, p.n) || !unit(z1, p.n) {
		return ErrBitProof
	}

	expected := bitORChallenge(p.n, domain, ct, pf.A0, pf.A1)
	var xor [sha256.Size]byte
	for i := range xor {
		xor[i] = pf.E0[i] ^ pf.E1[i]
	}
	if subtle.ConstantTimeCompare(xor[:], expected[:]) != 1 {
		return ErrBitProof
	}

	gInv := new(big.Int).ModInverse(p.g, p.n2)
	if gInv == nil {
		return ErrBitProof
	}
	u0 := c
	u1 := new(big.Int).Mod(new(big.Int).Mul(c, gInv), p.n2)

	if !verifyORBranch(p.n, p.n2, u0, a0, new(big.Int).SetBytes(pf.E0), z0) {
		return ErrBitProof
	}
	if !verifyORBranch(p.n, p.n2, u1, a1, new(big.Int).SetBytes(pf.E1), z1) {
		return ErrBitProof
	}
	return nil
}

func verifyORBranch(n, n2, u, a, e, z *big.Int) bool {
	lhs := new(big.Int).Exp(z, n, n2)
	rhs := new(big.Int).Exp(u, e, n2)
	rhs.Mul(rhs, a)
	rhs.Mod(rhs, n2)
	return lhs.Cmp(rhs) == 0
}

// DecryptAndProve decrypts a ciphertext with the private key and returns its
// plaintext together with a GMR-backed ProveEqual transcript for that aggregate
// ciphertext without needing the caller to supply the encryption randomness.
func (p *Paillier) DecryptAndProve(ct []byte) (*big.Int, []byte, error) {
	if !p.validPublic() || p.lambda == nil || p.mu == nil {
		return nil, nil, ErrDec
	}
	m, err := p.Decrypt(ct)
	if err != nil {
		return nil, nil, err
	}
	c := new(big.Int).SetBytes(ct)
	gm := new(big.Int).Exp(p.g, m, p.n2)
	gminv := new(big.Int).ModInverse(gm, p.n2)
	if gminv == nil {
		return nil, nil, ErrDec
	}
	u := new(big.Int).Mul(c, gminv)
	u.Mod(u, p.n2)
	rBase := new(big.Int).Mod(u, p.n)
	dN := new(big.Int).ModInverse(p.n, p.lambda)
	if dN == nil {
		return nil, nil, ErrDec
	}
	r := new(big.Int).Exp(rBase, dN, p.n)
	if !unit(r, p.n) {
		return nil, nil, ErrDec
	}
	check, err := p.EncryptWithR(m, r)
	if err != nil || !bytes.Equal(check, ct) {
		return nil, nil, ErrDec
	}
	proof, err := p.ProveEqual(ct, m, r)
	if err != nil {
		return nil, nil, err
	}
	return m, proof, nil
}
