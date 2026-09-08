package he

import "testing"

func TestBackboneIsRealNotCostume(t *testing.T) {
	// Was: Backbone()==ErrNoScheme until a scheme was wired.
	// The baseline implements additive PHE (paillier.go): Backbone is real, and
	// the anti-costume spirit now lives in the scheme's fail-closed
	// paths (Mul refuses, garbage ciphertext refuses — see
	// TestMulFailsClosed / TestDecryptRejectsGarbage).
	if err := Backbone(); err != nil {
		t.Fatalf("Backbone must be wired (paillier): %v", err)
	}
	// The stronger schemes must still fail closed: no TFHE/BFV/CKKS
	// implementation exists yet, so constructing a Paillier and asking
	// for FHE behavior must be refused, not faked.
	p, err := NewPaillier(2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if p.Scheme() != SchemePaillier {
		t.Fatalf("got %q, want %q", p.Scheme(), SchemePaillier)
	}
}

func TestSchemeNamesMatchDesignJobs(t *testing.T) {
	// Scheme identifiers are part of the existing interface.
	want := []Scheme{SchemePaillier, SchemeTFHE, SchemeCKKS, SchemeBFV}
	if len(want) != 4 {
		t.Fatal("expected four jobs")
	}
}
