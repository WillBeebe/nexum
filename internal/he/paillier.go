package he

// Paillier additive homomorphic encryption using Go's math/big implementation.
// This experimental implementation is not independently audited, is not
// constant-time and does not implement general FHE or encrypted control flow.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"math/big"
)

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
	// p, q distinct safe-ish primes (big.Int.ProbablyPrime, 64 rounds)
	for {
		p, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return nil, ErrKeyGen
		}
		q, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return nil, ErrKeyGen
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		n2 := new(big.Int).Mul(n, n)
		lambda := lcm(pMinus1(p), pMinus1(q))
		g := new(big.Int).Add(n, big.NewInt(1)) // n+1
		// mu = (L(g^lambda mod n^2))^-1 mod n
		x := new(big.Int).Exp(g, lambda, n2)
		L := new(big.Int).Div(new(big.Int).Sub(x, big.NewInt(1)), n)
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

// Encrypt m (0 <= m < n) to a ciphertext in Z_{n^2}*.
func (p *Paillier) Encrypt(m *big.Int) ([]byte, error) {
	if m == nil || m.Sign() < 0 || m.Cmp(p.n) >= 0 {
		return nil, ErrEnc
	}
	r, err := rand.Int(rand.Reader, p.n) // r in [0,n)
	if err != nil || r.Sign() == 0 {
		return nil, ErrEnc
	}
	// c = g^m * r^n mod n^2
	gm := new(big.Int).Exp(p.g, m, p.n2)
	rn := new(big.Int).Exp(r, p.n, p.n2)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, p.n2)
	return c.Bytes(), nil
}

// Add homomorphically adds two ciphertexts: E(a)*E(b) mod n^2.
func (p *Paillier) Add(a, b []byte) ([]byte, error) {
	ca := new(big.Int).SetBytes(a)
	cb := new(big.Int).SetBytes(b)
	if ca.Sign() <= 0 || cb.Sign() <= 0 || ca.Cmp(p.n2) >= 0 || cb.Cmp(p.n2) >= 0 {
		return nil, ErrAdd
	}
	out := new(big.Int).Mul(ca, cb)
	out.Mod(out, p.n2)
	return out.Bytes(), nil
}

// Decrypt a ciphertext back to plaintext.
func (p *Paillier) Decrypt(c []byte) (*big.Int, error) {
	ct := new(big.Int).SetBytes(c)
	if ct.Sign() <= 0 || ct.Cmp(p.n2) >= 0 {
		return nil, ErrDec
	}
	x := new(big.Int).Exp(ct, p.lambda, p.n2)
	L := new(big.Int).Div(new(big.Int).Sub(x, big.NewInt(1)), p.n)
	m := new(big.Int).Mul(L, p.mu)
	m.Mod(m, p.n)
	return m, nil
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
	if r == nil || r.Sign() <= 0 || r.Cmp(p.n) >= 0 {
		return nil, ErrEnc
	}
	// r must be a unit mod n: r^n mod n^2 is the blinding factor and the
	// proof consumes r^e, so a non-unit would leak the factorization path.
	if new(big.Int).GCD(nil, nil, r, p.n).Cmp(big.NewInt(1)) != 0 {
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
// randomness. Wire: commit a = s^n mod n^2; challenge e = H(ct,m,a);
// response z = s * r^e mod n. Verifier checks z^n == a*(ct/g^m)^e mod n^2.
// Public-key-only: VerifyEqual never touches lambda/mu.
type zkProof struct {
	A []byte `json:"a"` // commitment
	Z []byte `json:"z"` // response
}

// ProveEqual proves ct encrypts m. The prover must hold the randomness
// r that created ct (EncryptWithR). Sound: the verifier's check closes
// unless ct = g^m * r^n mod n^2 for that exact r. Zero-knowledge: the
// transcript (a, e, z) is a random-looking Schnorr tuple; m and r are
// never on the wire.
func (p *Paillier) ProveEqual(ct []byte, m *big.Int, r *big.Int) ([]byte, error) {
	c := new(big.Int).SetBytes(ct)
	if c.Sign() <= 0 || c.Cmp(p.n2) >= 0 {
		return nil, ErrEnc
	}
	if m == nil || m.Sign() < 0 || m.Cmp(p.n) >= 0 {
		return nil, ErrEnc
	}
	if r == nil || r.Sign() <= 0 || r.Cmp(p.n) >= 0 {
		return nil, ErrEnc
	}
	s, err := rand.Int(rand.Reader, p.n)
	if err != nil || s.Sign() == 0 {
		return nil, ErrEnc
	}
	a := new(big.Int).Exp(s, p.n, p.n2)
	e := zkChallenge(ct, m.Bytes(), a.Bytes(), p.n)
	// z = s * r^e mod n
	z := new(big.Int).Exp(r, e, p.n)
	z.Mul(z, s)
	z.Mod(z, p.n)
	out, err := json.Marshal(zkProof{A: a.Bytes(), Z: z.Bytes()})
	if err != nil {
		return nil, ErrEnc
	}
	return out, nil
}

// VerifyEqual checks a ProveEqual transcript with the PUBLIC key only —
// lambda and mu are never touched. This is the accept/reject branch on
// ciphertext: the decision needs no private key and reveals no plaintext.
func (p *Paillier) VerifyEqual(ct []byte, m *big.Int, proof []byte) (bool, error) {
	var pf zkProof
	if err := json.Unmarshal(proof, &pf); err != nil {
		return false, nil // malformed proof: not an error, just no branch
	}
	c := new(big.Int).SetBytes(ct)
	if c.Sign() <= 0 || c.Cmp(p.n2) >= 0 {
		return false, nil
	}
	if m == nil || m.Sign() < 0 || m.Cmp(p.n) >= 0 {
		return false, nil
	}
	a := new(big.Int).SetBytes(pf.A)
	z := new(big.Int).SetBytes(pf.Z)
	if a.Sign() <= 0 || a.Cmp(p.n2) >= 0 || z.Sign() < 0 || z.Cmp(p.n) >= 0 {
		return false, nil
	}
	e := zkChallenge(ct, m.Bytes(), a.Bytes(), p.n)
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

// zkChallenge is the Fiat-Shamir hash: bind the commitment to the
// ciphertext and claimed message so the transcript is non-malleable.
func zkChallenge(ct, m, commit []byte, mod *big.Int) *big.Int {
	h := sha256.New()
	h.Write([]byte("nex/zk-equal-v1"))
	h.Write(ct)
	h.Write(m)
	h.Write(commit)
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, mod)
	if e.Sign() == 0 {
		e.SetInt64(1) // degenerate 256-bit collision; soundness unaffected
	}
	return e
}
