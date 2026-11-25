package he

// Paillier additive homomorphic encryption using Go's math/big implementation.
// This experimental implementation is not independently audited, is not
// constant-time and does not implement general FHE or encrypted control flow.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"math"
	"math/big"
)

const (
	maxTrialPrime         = 65537
	coprimeChallengeCount = 8
	coprimeDomain         = "nexum/he/coprime-v1\x00"
	zkChallengeDomain     = "nex/zk-equal-v2\x00"
)

var smallPrimeProducts []uint64

func init() {
	sieve := make([]bool, maxTrialPrime+1)
	var prod uint64 = 1
	for i := 3; i <= maxTrialPrime; i += 2 {
		if sieve[i] {
			continue
		}
		if i <= maxTrialPrime/i {
			for j := i * i; j <= maxTrialPrime; j += 2 * i {
				sieve[j] = true
			}
		}
		p := uint64(i)
		if prod > math.MaxUint64/p {
			smallPrimeProducts = append(smallPrimeProducts, prod)
			prod = p
		} else {
			prod *= p
		}
	}
	if prod > 1 {
		smallPrimeProducts = append(smallPrimeProducts, prod)
	}
}

func gcdUint64(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func hasSmallOddPrimeFactor(n *big.Int) bool {
	var mod, rem big.Int
	for _, prod := range smallPrimeProducts {
		mod.SetUint64(prod)
		rem.Rem(n, &mod)
		if gcdUint64(rem.Uint64(), prod) != 1 {
			return true
		}
	}
	return false
}

func isCanonicalPositive(b []byte) bool {
	return len(b) > 0 && b[0] != 0
}

func writeLenFramed(h hash.Hash, b []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
	h.Write(lenBuf[:])
	h.Write(b)
}

func validatePublicModulus(modulus []byte) (*big.Int, error) {
	bad := errors.New("he: invalid public modulus")
	if !isCanonicalPositive(modulus) || len(modulus) < 128 || len(modulus) > 1024 {
		return nil, bad
	}
	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() < 1024 || n.Bit(0) == 0 {
		return nil, bad
	}
	if hasSmallOddPrimeFactor(n) {
		return nil, bad
	}
	if n.ProbablyPrime(20) {
		return nil, bad
	}
	s := new(big.Int).Sqrt(n)
	if new(big.Int).Mul(s, s).Cmp(n) == 0 {
		return nil, bad
	}
	return n, nil
}

func coprimeChallenges(n *big.Int) ([]*big.Int, error) {
	if n == nil || n.Cmp(big.NewInt(3)) < 0 || n.Bit(0) == 0 {
		return nil, ErrEnc
	}
	nBytes := n.Bytes()
	needBytes := len(nBytes)
	excess := uint(needBytes*8 - n.BitLen())
	one := big.NewInt(1)

	ys := make([]*big.Int, coprimeChallengeCount)
	buf := make([]byte, needBytes)
	var meta [12]byte
	for i := 0; i < coprimeChallengeCount; i++ {
		binary.BigEndian.PutUint32(meta[0:4], uint32(i))
		var found *big.Int
		for ctr := uint32(0); ctr < 1<<16; ctr++ {
			binary.BigEndian.PutUint32(meta[4:8], ctr)
			for off, blk := 0, uint32(0); off < needBytes; off, blk = off+sha256.Size, blk+1 {
				binary.BigEndian.PutUint32(meta[8:12], blk)
				h := sha256.New()
				h.Write([]byte(coprimeDomain))
				writeLenFramed(h, nBytes)
				h.Write(meta[:])
				copy(buf[off:], h.Sum(nil))
			}
			if excess > 0 {
				buf[0] &= byte(0xff >> excess)
			}
			cand := new(big.Int).SetBytes(buf)
			if cand.Cmp(one) > 0 && cand.Cmp(n) < 0 && new(big.Int).GCD(nil, nil, cand, n).Cmp(one) == 0 {
				found = cand
				break
			}
		}
		if found == nil {
			return nil, ErrEnc
		}
		ys[i] = found
	}
	return ys, nil
}

var (
	ErrKeyGen = errors.New("he: paillier keygen failed")
	ErrEnc    = errors.New("he: paillier encrypt failed")
	ErrDec    = errors.New("he: paillier decrypt failed")
	ErrAdd    = errors.New("he: paillier add failed")
)

// Paillier is a concrete additive-PHE scheme.
type Paillier struct {
	n  *big.Int // public modulus
	n2 *big.Int // n^2
	g  *big.Int // generator (n+1)
	// private
	lambda *big.Int // Carmichael lambda(n)
	mu     *big.Int // L(g^lambda mod n^2)^-1 mod n
}

// NewPaillier generates a fresh keypair with a modulus of bits
// (2048 default; 3072 for a stronger budget).
func NewPaillier(bits int) (*Paillier, error) {
	if bits < 1024 {
		bits = 2048
	}
	if bits > 8192 {
		return nil, ErrKeyGen
	}
	pBits := bits / 2
	qBits := bits - pBits
	one := big.NewInt(1)
	// p, q distinct primes (big.Int.ProbablyPrime via rand.Prime)
	for {
		p, err := rand.Prime(rand.Reader, pBits)
		if err != nil {
			return nil, ErrKeyGen
		}
		q, err := rand.Prime(rand.Reader, qBits)
		if err != nil {
			return nil, ErrKeyGen
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		lambda := lcm(pMinus1(p), pMinus1(q))
		if new(big.Int).GCD(nil, nil, n, lambda).Cmp(one) != 0 {
			continue
		}
		n2 := new(big.Int).Mul(n, n)
		g := new(big.Int).Add(n, one) // n+1
		// mu = (L(g^lambda mod n^2))^-1 mod n
		x := new(big.Int).Exp(g, lambda, n2)
		L := new(big.Int).Div(new(big.Int).Sub(x, one), n)
		mu := new(big.Int).ModInverse(L, n)
		if mu == nil {
			continue // rare; retry with fresh primes
		}
		return &Paillier{n: n, n2: n2, g: g, lambda: lambda, mu: mu}, nil
	}
}

func pMinus1(x *big.Int) *big.Int { return new(big.Int).Sub(x, big.NewInt(1)) }

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	return new(big.Int).Div(new(big.Int).Mul(a, b), g)
}

// unit checks membership in the multiplicative group, not just its range.
// The equality proof relies on cancellation in this group. Nonunits can make
// both sides of its equation zero without proving anything about a message.
func unit(value, modulus *big.Int) bool {
	return value != nil && value.Sign() > 0 && value.Cmp(modulus) < 0 &&
		new(big.Int).GCD(nil, nil, value, modulus).Cmp(big.NewInt(1)) == 0
}

func randomUnit(modulus *big.Int) (*big.Int, error) {
	for {
		value, err := rand.Int(rand.Reader, modulus)
		if err != nil {
			return nil, err
		}
		if unit(value, modulus) {
			return value, nil
		}
	}
}

// Encrypt m (0 <= m < n) to a ciphertext in Z_{n^2}*.
func (p *Paillier) Encrypt(m *big.Int) ([]byte, error) {
	if m == nil || m.Sign() < 0 || m.Cmp(p.n) >= 0 {
		return nil, ErrEnc
	}
	r, err := randomUnit(p.n)
	if err != nil {
		return nil, ErrEnc
	}
	// c = g^m * r^n mod n^2
	gm := new(big.Int).Exp(p.g, m, p.n2)
	rn := new(big.Int).Exp(r, p.n, p.n2)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, p.n2)
	return c.Bytes(), nil
}

// ValidCiphertext reports whether c is a canonically encoded unit in Z_{n^2}*.
func (p *Paillier) ValidCiphertext(c []byte) bool {
	if p == nil || p.n2 == nil || !isCanonicalPositive(c) {
		return false
	}
	ct := new(big.Int).SetBytes(c)
	return unit(ct, p.n2)
}

// Add homomorphically adds two ciphertexts: E(a)*E(b) mod n^2.
func (p *Paillier) Add(a, b []byte) ([]byte, error) {
	if p == nil || p.n2 == nil || !isCanonicalPositive(a) || !isCanonicalPositive(b) {
		return nil, ErrAdd
	}
	ca := new(big.Int).SetBytes(a)
	cb := new(big.Int).SetBytes(b)
	if !unit(ca, p.n2) || !unit(cb, p.n2) {
		return nil, ErrAdd
	}
	out := new(big.Int).Mul(ca, cb)
	out.Mod(out, p.n2)
	return out.Bytes(), nil
}

// Decrypt a ciphertext back to plaintext.
func (p *Paillier) Decrypt(c []byte) (*big.Int, error) {
	if p == nil || p.n == nil || p.n2 == nil || p.lambda == nil || p.mu == nil || !isCanonicalPositive(c) {
		return nil, ErrDec
	}
	ct := new(big.Int).SetBytes(c)
	if !unit(ct, p.n2) {
		return nil, ErrDec
	}
	x := new(big.Int).Exp(ct, p.lambda, p.n2)
	L := new(big.Int).Div(new(big.Int).Sub(x, big.NewInt(1)), p.n)
	m := new(big.Int).Mul(L, p.mu)
	m.Mod(m, p.n)
	return m, nil
}

// FromPublic builds a verification-only key. Decrypt and proving are unavailable.
func FromPublic(modulus []byte) (*Paillier, error) {
	n, err := validatePublicModulus(modulus)
	if err != nil {
		return nil, err
	}
	return &Paillier{n: n, n2: new(big.Int).Mul(n, n), g: new(big.Int).Add(n, big.NewInt(1))}, nil
}

// Scheme implements Eval.
func (p *Paillier) Scheme() Scheme { return SchemePaillier }

// Mul is not supported by additive PHE — fail closed.
func (p *Paillier) Mul(a, b []byte) ([]byte, error) {
	return nil, ErrNoise
}

// KeySize reports the modulus bit length (for fleet inventory).
func (p *Paillier) KeySize() int { return p.n.BitLen() }

// Equal is a constant-time compare for ciphertexts (tests/audit).
func (p *Paillier) Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// N returns a copy of the public modulus (proof randomness lives mod n).
func (p *Paillier) N() *big.Int { return new(big.Int).Set(p.n) }

// EncryptWithR encrypts m with explicit randomness r. This is the prover
// side of the equality proof: whoever holds r can later prove (zero-knowledge) what
// the ciphertext encrypts, without revealing m or r.
func (p *Paillier) EncryptWithR(m, r *big.Int) ([]byte, error) {
	if m == nil || m.Sign() < 0 || m.Cmp(p.n) >= 0 {
		return nil, ErrEnc
	}
	// r must be a unit mod n: r^n mod n^2 is the blinding factor and the
	// proof consumes r^e, so a non-unit would leak the factorization path.
	if !unit(r, p.n) {
		return nil, ErrEnc
	}
	gm := new(big.Int).Exp(p.g, m, p.n2)
	rn := new(big.Int).Exp(r, p.n, p.n2)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, p.n2)
	return c.Bytes(), nil
}

// zkProof is a non-interactive (Fiat-Shamir) proof that a ciphertext
// encrypts a claimed message, without revealing the message or the
// randomness, paired with a Gennaro-Micciancio-Rabin coprimality NIZK
// proving gcd(N, phi(N)) == 1.
// Wire: commit a = s^n mod n^2; challenge e = H(N,ct,m,a);
// response z = s * r^e mod n; roots r[i] = y_i^(N^-1 mod lambda) mod N.
// Verifier checks r[i]^N == y_i mod N and z^n == a*(ct/g^m)^e mod n^2.
// Public-key-only: VerifyEqual never touches lambda/mu.
type zkProof struct {
	A []byte   `json:"a"` // commitment
	Z []byte   `json:"z"` // response
	R [][]byte `json:"r"` // GMR coprimality NIZK N-th roots mod N
}

func decodeZKProof(proof []byte) (zkProof, error) {
	if len(proof) == 0 || proof[0] != '{' || proof[len(proof)-1] != '}' {
		return zkProof{}, errors.New("he: malformed proof")
	}
	var pf zkProof
	dec := json.NewDecoder(bytes.NewReader(proof))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return zkProof{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return zkProof{}, errors.New("he: trailing bytes in proof")
	}
	return pf, nil
}

// ProveEqual proves ct encrypts m and proves gcd(N, phi(N)) == 1 via a
// Gennaro-Micciancio-Rabin coprimality NIZK. The prover must hold both the
// private key (lambda) and the randomness r that created ct (EncryptWithR).
func (p *Paillier) ProveEqual(ct []byte, m *big.Int, r *big.Int) ([]byte, error) {
	if p == nil || p.n == nil || p.n2 == nil || p.g == nil || p.lambda == nil {
		return nil, ErrEnc
	}
	if !isCanonicalPositive(ct) {
		return nil, ErrEnc
	}
	c := new(big.Int).SetBytes(ct)
	if !unit(c, p.n2) {
		return nil, ErrEnc
	}
	if m == nil || m.Sign() < 0 || m.Cmp(p.n) >= 0 {
		return nil, ErrEnc
	}
	if !unit(r, p.n) {
		return nil, ErrEnc
	}
	dN := new(big.Int).ModInverse(p.n, p.lambda)
	if dN == nil {
		return nil, ErrEnc
	}
	ys, err := coprimeChallenges(p.n)
	if err != nil {
		return nil, ErrEnc
	}
	roots := make([][]byte, coprimeChallengeCount)
	for i, y := range ys {
		x := new(big.Int).Exp(y, dN, p.n)
		roots[i] = x.Bytes()
	}
	s, err := randomUnit(p.n)
	if err != nil {
		return nil, ErrEnc
	}
	a := new(big.Int).Exp(s, p.n, p.n2)
	e := zkChallenge(c.Bytes(), m.Bytes(), a.Bytes(), p.n)
	// z = s * r^e mod n
	z := new(big.Int).Exp(r, e, p.n)
	z.Mul(z, s)
	z.Mod(z, p.n)
	out, err := json.Marshal(zkProof{A: a.Bytes(), Z: z.Bytes(), R: roots})
	if err != nil {
		return nil, ErrEnc
	}
	return out, nil
}

// VerifyEqual checks a ProveEqual transcript (including the GMR coprimality NIZK)
// with the PUBLIC key only — lambda and mu are never touched.
func (p *Paillier) VerifyEqual(ct []byte, m *big.Int, proof []byte) (bool, error) {
	if p == nil || p.n == nil || p.n2 == nil || p.g == nil {
		return false, nil
	}
	pf, err := decodeZKProof(proof)
	if err != nil {
		return false, nil // malformed proof: not an error, just no branch
	}
	if !isCanonicalPositive(ct) || !isCanonicalPositive(pf.A) || !isCanonicalPositive(pf.Z) {
		return false, nil
	}
	if len(pf.R) != coprimeChallengeCount {
		return false, nil
	}
	c := new(big.Int).SetBytes(ct)
	if !unit(c, p.n2) {
		return false, nil
	}
	if m == nil || m.Sign() < 0 || m.Cmp(p.n) >= 0 {
		return false, nil
	}
	a := new(big.Int).SetBytes(pf.A)
	z := new(big.Int).SetBytes(pf.Z)
	if !unit(a, p.n2) || !unit(z, p.n) {
		return false, nil
	}
	ys, err := coprimeChallenges(p.n)
	if err != nil {
		return false, nil
	}
	one := big.NewInt(1)
	for i := 0; i < coprimeChallengeCount; i++ {
		if !isCanonicalPositive(pf.R[i]) {
			return false, nil
		}
		xi := new(big.Int).SetBytes(pf.R[i])
		if xi.Cmp(one) <= 0 || xi.Cmp(p.n) >= 0 {
			return false, nil
		}
		if new(big.Int).GCD(nil, nil, xi, p.n).Cmp(one) != 0 {
			return false, nil
		}
		if new(big.Int).Exp(xi, p.n, p.n).Cmp(ys[i]) != 0 {
			return false, nil
		}
	}
	e := zkChallenge(c.Bytes(), m.Bytes(), a.Bytes(), p.n)
	// z^n mod n^2
	lhs := new(big.Int).Exp(z, p.n, p.n2)
	// (ct * g^-m)^e mod n^2  — ct/g^m is r^n iff ct encrypts m
	gm := new(big.Int).Exp(p.g, m, p.n2)
	gminv := new(big.Int).ModInverse(gm, p.n2)
	if gminv == nil {
		return false, nil
	}
	rn := new(big.Int).Mul(c, gminv)
	rn.Mod(rn, p.n2)
	rhs := new(big.Int).Exp(rn, e, p.n2)
	rhs.Mul(rhs, a)
	rhs.Mod(rhs, p.n2)
	return lhs.Cmp(rhs) == 0, nil
}

// zkChallenge is the domain-separated, length-framed Fiat-Shamir hash:
// binds the modulus, ciphertext, claimed message, and commitment so the
// transcript is collision-free and non-malleable.
func zkChallenge(ct, m, commit []byte, mod *big.Int) *big.Int {
	h := sha256.New()
	h.Write([]byte(zkChallengeDomain))
	writeLenFramed(h, mod.Bytes())
	writeLenFramed(h, ct)
	writeLenFramed(h, m)
	writeLenFramed(h, commit)
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, mod)
	if e.Sign() == 0 {
		e.SetInt64(1) // degenerate 256-bit collision; soundness unaffected
	}
	return e
}
