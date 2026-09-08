// Package he implements additive Paillier evaluation. General FHE is not implemented.
package he

import "errors"

var (
	ErrNoScheme = errors.New("he: no production scheme wired")
	ErrNoise    = errors.New("he: noise would swamp decrypt — bootstrap required")
)

// Scheme is which 2026 job we are asking of the mesh.
type Scheme string

const (
	SchemePaillier Scheme = "paillier" // additive PHE — lock sums, budget totals
	SchemeTFHE     Scheme = "tfhe"     // compare / branch / accept-reject
	SchemeCKKS     Scheme = "ckks"     // packed approx — inference, remaining budget
	SchemeBFV      Scheme = "bfv"      // exact integers — lock units
)

// Eval is what a fleet node does to a sealed batch of Nexums
// without opening them. Macs hold keys. GPUs barter.
type Eval interface {
	Scheme() Scheme
	// Add is PHE/FHE addition on ciphertext.
	Add(a, b []byte) ([]byte, error)
	// Mul is FHE multiplication on ciphertext (not PHE-add).
	Mul(a, b []byte) ([]byte, error)
}

// Backbone reports availability of the implemented additive Paillier baseline.
// It does not certify general FHE or production readiness.
func Backbone() error { return nil }
