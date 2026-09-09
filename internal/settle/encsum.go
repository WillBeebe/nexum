package settle

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/WillBeebe/nexum/internal/he"
)

// EncryptedLedger holds local Paillier keys and encryption randomness. It
// encrypts positive lock amounts and aggregates ciphertexts. Its owner sees
// the plaintext inputs and can decrypt; this is not separate remote custody.
// Equality proofs bind the aggregate to a public committed amount.
type EncryptedLedger struct {
	p *he.Paillier
	// rs holds the encryption randomness of each sealed lock, in order.
	// The aggregate's randomness is the product (mod n): the prover side
	// of the equality proof. The private key is NOT used on the
	// accept/reject branch — see ProveEqual / VerifyEqual.
	rs []*big.Int
}

var (
	// ErrSumMismatch fires when the homomorphic sum does not equal the
	// committed Amount. The escrow does not settle "approximately".
	ErrSumMismatch = errors.New("settle: ciphertext sum != committed amount")
	// ErrNoLocks means Aggregate was called with nothing sealed.
	ErrNoLocks = errors.New("settle: no locks sealed")
	// ErrBadSum means the decrypted sum is not a positive amount.
	ErrBadSum = errors.New("settle: decrypted sum is not a positive amount")
	// ErrBadLock means a lock amount was not a positive integer.
	ErrBadLock = errors.New("settle: lock amount must be positive")
)

// NewEncryptedLedger mints a ledger with an `bits`-bit Paillier modulus.
func NewEncryptedLedger(bits int) (*EncryptedLedger, error) {
	p, err := he.NewPaillier(bits)
	if err != nil {
		return nil, fmt.Errorf("settle: %w", err)
	}
	return &EncryptedLedger{p: p}, nil
}

// SealLock encrypts one agent's partial lock amount. The plaintext never
// enters the kernel's hands.
func (l *EncryptedLedger) SealLock(amount int64) ([]byte, error) {
	if amount <= 0 {
		return nil, ErrBadLock
	}
	m := big.NewInt(amount)
	n := l.p.N()
	// Draw a unit r (the prover-side randomness); gcd(r,n)=1. With
	// 1024-bit p, q the non-unit probability is ~2^-1022 — the loop is
	// defense, not expectation.
	for attempt := 0; attempt < 8; attempt++ {
		r, err := rand.Int(rand.Reader, n)
		if err != nil || r.Sign() == 0 {
			continue
		}
		if new(big.Int).GCD(nil, nil, r, n).Cmp(big.NewInt(1)) != 0 {
			continue
		}
		ct, err := l.p.EncryptWithR(m, r)
		if err != nil {
			continue
		}
		l.rs = append(l.rs, r)
		return ct, nil
	}
	return nil, ErrBadLock
}

// Aggregate sums sealed locks homomorphically: ciphertext in, ciphertext
// out. Empty input fails closed.
func (l *EncryptedLedger) Aggregate(sealed [][]byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, ErrNoLocks
	}
	sum := sealed[0]
	var err error
	for _, c := range sealed[1:] {
		sum, err = l.p.Add(sum, c)
		if err != nil {
			return nil, fmt.Errorf("settle: aggregate: %w", err)
		}
	}
	return sum, nil
}

// Release decrypts the aggregate exactly once and holds it against the
// committed Amount. sum != committed, sum <= 0, or a tampered ciphertext
// all refuse to settle.
func (l *EncryptedLedger) Release(sealedSum []byte, committed int64) (int64, error) {
	total, err := l.p.Decrypt(sealedSum)
	if err != nil {
		return 0, fmt.Errorf("settle: release: %w", err)
	}
	if total.Sign() <= 0 {
		return 0, ErrBadSum
	}
	if !total.IsInt64() || total.Int64() != committed {
		return 0, fmt.Errorf("%w: got %s want %d", ErrSumMismatch, total.String(), committed)
	}
	return total.Int64(), nil
}

// ProveEqual builds a
// zero-knowledge transcript that the sealed aggregate encrypts the
// committed Amount, and verifies it with the PUBLIC key only — the
// accept/reject decision never calls Decrypt. The aggregate's
// randomness is the product of the per-lock randomness (mod n),
// because homomorphic addition multiplies blinding factors.
//
// The returned proof is wire-safe: it carries no plaintext and can be
// checked by any fleet node or auditor holding the public key.
func (l *EncryptedLedger) ProveEqual(sealedSum []byte, committed int64) ([]byte, error) {
	if len(l.rs) == 0 {
		return nil, ErrNoLocks
	}
	r := big.NewInt(1)
	n := l.p.N()
	for _, ri := range l.rs {
		r.Mul(r, ri)
		r.Mod(r, n)
	}
	return l.p.ProveEqual(sealedSum, big.NewInt(committed), r)
}

// VerifyEqual checks a ProveEqual transcript with the public key only.
// Proof reuse is refused: a transcript binds one (ciphertext, message)
// pair via the Fiat-Shamir challenge, but each call re-verifies from
// scratch so a replayed proof for different values fails.
func (l *EncryptedLedger) VerifyEqual(sealedSum []byte, committed int64, proof []byte) (bool, error) {
	return l.p.VerifyEqual(sealedSum, big.NewInt(committed), proof)
}

// Clone isolates mutable encryption randomness for a staged lock.
// Paillier key material is immutable and shared; operations never modify it.
func (l *EncryptedLedger) Clone() *EncryptedLedger {
	next := &EncryptedLedger{p: l.p, rs: make([]*big.Int, len(l.rs))}
	for i, r := range l.rs {
		next.rs[i] = new(big.Int).Set(r)
	}
	return next
}
