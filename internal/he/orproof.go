package he

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sync"
)

const (
	bitORDomain      = "github.com/WillBeebe/nexum/v2/he/bit-or-v2\x00"
	bitORRounds      = 8
	maxBitProofBytes = 128 << 10 // 128 KiB
)

// ErrBitProof indicates a malformed, non-canonical, or mathematically invalid
// CDS94 disjunctive {0,1} Paillier OR-proof.
var ErrBitProof = errors.New("he: invalid bit proof")

// bitORRound is one parallel Cramer-Damgård-Schoenmakers (CDS94) disjunctive
// Sigma round proving c == r^N mod N^2 OR c * g^-1 == r^N mod N^2.
type bitORRound struct {
	A0 []byte `json:"a0"`
	A1 []byte `json:"a1"`
	E0 []byte `json:"e0"`
	E1 []byte `json:"e1"`
	Z0 []byte `json:"z0"`
	Z1 []byte `json:"z1"`
}

// bitORProof binds bitORRounds (8) parallel CDS94 rounds under a single joint
// Fiat-Shamir hash so soundness against an untrusted modulus with smallest
// prime factor p > 65537 is <= (1/65539)^8 < 2^-128.
type bitORProof struct {
	Rounds []bitORRound `json:"rounds"`
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
	if len(pf.Rounds) != bitORRounds {
		return bitORProof{}, ErrBitProof
	}
	return pf, nil
}

func bitORChallenges(mod *big.Int, domain, ct []byte, a0s, a1s [][]byte) [bitORRounds][sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(bitORDomain))
	writeLenFramed(h, mod.Bytes())
	writeLenFramed(h, domain)
	writeLenFramed(h, ct)
	for i := 0; i < bitORRounds; i++ {
		writeLenFramed(h, a0s[i])
		writeLenFramed(h, a1s[i])
	}
	root := h.Sum(nil)

	var out [bitORRounds][sha256.Size]byte
	var idxBuf [4]byte
	for i := 0; i < bitORRounds; i++ {
		binary.BigEndian.PutUint32(idxBuf[:], uint32(i))
		rh := sha256.New()
		rh.Write([]byte(bitORDomain))
		rh.Write(root)
		rh.Write(idxBuf[:])
		copy(out[i][:], rh.Sum(nil))
	}
	return out
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

// ProveBit builds a bitORRounds-parallel CDS94 non-interactive zero-knowledge
// OR-proof bound under one joint Fiat-Shamir challenge that ct encrypts bit in
// {0, 1} with randomness r under domain separation bytes. Works on
// public-key-only *Paillier instances from FromPublic.
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
	uSimInv := new(big.Int).ModInverse(u[sim], p.n2)
	if uSimInv == nil {
		return nil, ErrEnc
	}
	ctBytes := ct.Bytes()
	if !isCanonicalPositive(ctBytes) {
		return nil, ErrEnc
	}

	ws := make([]*big.Int, bitORRounds)
	zSims := make([]*big.Int, bitORRounds)
	eSims := make([][sha256.Size]byte, bitORRounds)
	for i := 0; i < bitORRounds; i++ {
		w, err := randomUnit(p.n)
		if err != nil {
			return nil, ErrEnc
		}
		zSim, err := randomUnit(p.n)
		if err != nil {
			return nil, ErrEnc
		}
		if _, err := io.ReadFull(rand.Reader, eSims[i][:]); err != nil {
			return nil, ErrEnc
		}
		ws[i] = w
		zSims[i] = zSim
	}

	a0s := make([][]byte, bitORRounds)
	a1s := make([][]byte, bitORRounds)
	var wg sync.WaitGroup
	wg.Add(bitORRounds)
	for i := 0; i < bitORRounds; i++ {
		go func(idx int) {
			defer wg.Done()
			var a [2]*big.Int
			a[bit] = new(big.Int).Exp(ws[idx], p.n, p.n2)

			eSim := new(big.Int).SetBytes(eSims[idx][:])
			aSim := new(big.Int).Exp(uSimInv, eSim, p.n2)
			aSim.Mul(aSim, new(big.Int).Exp(zSims[idx], p.n, p.n2))
			aSim.Mod(aSim, p.n2)
			a[sim] = aSim

			a0s[idx] = a[0].Bytes()
			a1s[idx] = a[1].Bytes()
		}(i)
	}
	wg.Wait()

	for i := 0; i < bitORRounds; i++ {
		if !isCanonicalPositive(a0s[i]) || !isCanonicalPositive(a1s[i]) {
			return nil, ErrEnc
		}
	}

	challenges := bitORChallenges(p.n, domain, ctBytes, a0s, a1s)

	rounds := make([]bitORRound, bitORRounds)
	for i := 0; i < bitORRounds; i++ {
		var e [2][]byte
		e[sim] = append([]byte(nil), eSims[i][:]...)
		eRealBytes := make([]byte, sha256.Size)
		for j := range eRealBytes {
			eRealBytes[j] = challenges[i][j] ^ eSims[i][j]
		}
		e[bit] = eRealBytes

		eReal := new(big.Int).SetBytes(eRealBytes)
		var z [2]*big.Int
		z[sim] = zSims[i]
		zReal := new(big.Int).Exp(r, eReal, p.n)
		zReal.Mul(zReal, ws[i])
		zReal.Mod(zReal, p.n)
		if !unit(zReal, p.n) {
			return nil, ErrEnc
		}
		z[bit] = zReal

		rounds[i] = bitORRound{
			A0: a0s[i],
			A1: a1s[i],
			E0: e[0],
			E1: e[1],
			Z0: z[0].Bytes(),
			Z1: z[1].Bytes(),
		}
	}

	out, err := json.Marshal(bitORProof{Rounds: rounds})
	if err != nil {
		return nil, ErrEnc
	}
	return out, nil
}

// VerifyBit verifies a bitORRounds-parallel CDS94 disjunctive {0,1} Paillier
// OR-proof against canonical ciphertext ct and domain separation bytes using
// only the public key.
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

	a0Bytes := make([][]byte, bitORRounds)
	a1Bytes := make([][]byte, bitORRounds)
	a0s := make([]*big.Int, bitORRounds)
	a1s := make([]*big.Int, bitORRounds)
	z0s := make([]*big.Int, bitORRounds)
	z1s := make([]*big.Int, bitORRounds)

	for i, rd := range pf.Rounds {
		if !isCanonicalPositive(rd.A0) || len(rd.A0) > n2Len ||
			!isCanonicalPositive(rd.A1) || len(rd.A1) > n2Len ||
			!isCanonicalPositive(rd.Z0) || len(rd.Z0) > nLen ||
			!isCanonicalPositive(rd.Z1) || len(rd.Z1) > nLen {
			return ErrBitProof
		}
		if len(rd.E0) != sha256.Size || len(rd.E1) != sha256.Size {
			return ErrBitProof
		}
		a0 := new(big.Int).SetBytes(rd.A0)
		a1 := new(big.Int).SetBytes(rd.A1)
		z0 := new(big.Int).SetBytes(rd.Z0)
		z1 := new(big.Int).SetBytes(rd.Z1)
		if !unit(a0, p.n2) || !unit(a1, p.n2) || !unit(z0, p.n) || !unit(z1, p.n) {
			return ErrBitProof
		}
		a0Bytes[i] = rd.A0
		a1Bytes[i] = rd.A1
		a0s[i] = a0
		a1s[i] = a1
		z0s[i] = z0
		z1s[i] = z1
	}

	expected := bitORChallenges(p.n, domain, ct, a0Bytes, a1Bytes)

	var xor [sha256.Size]byte
	for i, rd := range pf.Rounds {
		for j := range xor {
			xor[j] = rd.E0[j] ^ rd.E1[j]
		}
		if subtle.ConstantTimeCompare(xor[:], expected[i][:]) != 1 {
			return ErrBitProof
		}
	}

	gInv := new(big.Int).ModInverse(p.g, p.n2)
	if gInv == nil {
		return ErrBitProof
	}
	u0 := c
	u1 := new(big.Int).Mod(new(big.Int).Mul(c, gInv), p.n2)

	var roundOK [bitORRounds]bool
	var wg sync.WaitGroup
	wg.Add(bitORRounds)
	for i := 0; i < bitORRounds; i++ {
		go func(idx int) {
			defer wg.Done()
			rd := pf.Rounds[idx]
			if !verifyORBranch(p.n, p.n2, u0, a0s[idx], new(big.Int).SetBytes(rd.E0), z0s[idx]) {
				return
			}
			if !verifyORBranch(p.n, p.n2, u1, a1s[idx], new(big.Int).SetBytes(rd.E1), z1s[idx]) {
				return
			}
			roundOK[idx] = true
		}(i)
	}
	wg.Wait()

	for _, ok := range roundOK {
		if !ok {
			return ErrBitProof
		}
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
