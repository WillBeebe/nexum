package he

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func TestEqualityProofRejectsPublicModulusForgery(t *testing.T) {
	p, err := NewPaillier(1024)
	if err != nil {
		t.Fatal(err)
	}
	// This forgery needs only the public modulus. Previously c=n, a=n, z=0
	// made both sides zero modulo n² for every positive challenge, so it
	// passed for any claimed message despite c not being a ciphertext.
	n := p.N().Bytes()
	proof, err := json.Marshal(zkProof{A: n, Z: nil})
	if err != nil {
		t.Fatal(err)
	}
	for _, claimed := range []int64{1, 7, 9000} {
		if ok, err := p.VerifyEqual(n, big.NewInt(claimed), proof); err != nil || ok {
			t.Fatalf("nonunit forgery for %d: accepted=%v err=%v", claimed, ok, err)
		}
	}
}

func TestPaillierRejectsNonUnits(t *testing.T) {
	// Small known factors let this test exercise proper divisors, which are
	// inside the accepted range but outside the multiplicative group.
	p := &Paillier{n: big.NewInt(15), n2: big.NewInt(225), g: big.NewInt(16), lambda: big.NewInt(4), mu: big.NewInt(4)}
	m, r := big.NewInt(7), big.NewInt(2)
	ct, err := p.EncryptWithR(m, r)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := p.ProveEqual(ct, m, r)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.VerifyEqual(ct, m, proof); err != nil || !ok {
		t.Fatalf("honest proof rejected: %v %v", ok, err)
	}
	for _, value := range []int64{0, 3, 5, 15, 225} {
		bad := big.NewInt(value).Bytes()
		if _, err := p.Add(ct, bad); err != ErrAdd {
			t.Fatalf("Add accepted nonunit %d: %v", value, err)
		}
		if _, err := p.Add(bad, ct); err != ErrAdd {
			t.Fatalf("Add accepted first nonunit %d: %v", value, err)
		}
		if _, err := p.Decrypt(bad); err != ErrDec {
			t.Fatalf("Decrypt accepted nonunit %d: %v", value, err)
		}
		if _, err := p.ProveEqual(bad, m, r); err != ErrEnc {
			t.Fatalf("ProveEqual accepted nonunit ciphertext %d: %v", value, err)
		}
		if _, err := p.EncryptWithR(m, big.NewInt(value)); err != ErrEnc {
			t.Fatalf("EncryptWithR accepted nonunit randomness %d: %v", value, err)
		}
		if _, err := p.ProveEqual(ct, m, big.NewInt(value)); err != ErrEnc {
			t.Fatalf("ProveEqual accepted nonunit randomness %d: %v", value, err)
		}
		var original zkProof
		if err := json.Unmarshal(proof, &original); err != nil {
			t.Fatal(err)
		}
		for _, malformed := range []zkProof{{A: bad, Z: original.Z}, {A: original.A, Z: bad}} {
			encoded, err := json.Marshal(malformed)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := p.VerifyEqual(ct, m, encoded); err != nil || ok {
				t.Fatalf("VerifyEqual accepted nonunit component %d: %v %v", value, ok, err)
			}
		}
	}
	for range 128 {
		ciphertext, err := p.Encrypt(m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Decrypt(ciphertext)
		if err != nil || got.Cmp(m) != 0 {
			t.Fatalf("sampler emitted nonunit randomness: %v %v", got, err)
		}
	}
}

// TestBackboneIsReal: additive PHE is wired — but prove it, do not
// stamp it. Keygen, encrypt, homomorphic add, decrypt round-trip.
func TestBackboneIsReal(t *testing.T) {
	if err := Backbone(); err != nil {
		t.Fatalf("Backbone must be wired now (paillier): %v", err)
	}
	p, err := NewPaillier(2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if p.Scheme() != SchemePaillier {
		t.Fatalf("scheme = %q, want paillier", p.Scheme())
	}
	if got := p.KeySize(); got != 2048 {
		t.Fatalf("KeySize = %d, want 2048", got)
	}

	a := big.NewInt(350000)
	b := big.NewInt(999000)

	ca, err := p.Encrypt(a)
	if err != nil {
		t.Fatalf("encrypt a: %v", err)
	}
	cb, err := p.Encrypt(b)
	if err != nil {
		t.Fatalf("encrypt b: %v", err)
	}

	// Mesh sees only ciphertext: add without opening.
	sum, err := p.Add(ca, cb)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	m, err := p.Decrypt(sum)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	want := new(big.Int).Add(a, b)
	if m.Cmp(want) != 0 {
		t.Fatalf("homomorphic sum = %s, want %s", m, want)
	}

	// Ciphertexts must differ across encryptions (semantic security).
	ca2, err := p.Encrypt(a)
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	if p.Equal(ca, ca2) {
		t.Fatal("two encryptions of the same value are identical — not semantically secure")
	}
}

// TestMulFailsClosed: additive PHE must refuse multiplication,
// not silently return garbage.
func TestMulFailsClosed(t *testing.T) {
	p, err := NewPaillier(2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ca, _ := p.Encrypt(big.NewInt(7))
	cb, _ := p.Encrypt(big.NewInt(9))
	if _, err := p.Mul(ca, cb); err == nil {
		t.Fatal("Mul on additive PHE must return an error")
	}
}

// TestBudgetOnCiphertext is the additive aggregation behavior: a fleet node totals
// locked obligations without ever seeing them. Three encrypted
// locks, one homomorphic sum, decrypt at the parties only.
func TestBudgetOnCiphertext(t *testing.T) {
	p, err := NewPaillier(2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	locks := []*big.Int{big.NewInt(1200), big.NewInt(350000), big.NewInt(999000)}
	acc, err := p.Encrypt(big.NewInt(0))
	if err != nil {
		t.Fatalf("encrypt zero: %v", err)
	}
	for i, m := range locks {
		c, err := p.Encrypt(m)
		if err != nil {
			t.Fatalf("lock %d: %v", i, err)
		}
		if acc, err = p.Add(acc, c); err != nil {
			t.Fatalf("accumulate %d: %v", i, err)
		}
	}
	total, err := p.Decrypt(acc)
	if err != nil {
		t.Fatalf("decrypt total: %v", err)
	}
	want := big.NewInt(1350200)
	if total.Cmp(want) != 0 {
		t.Fatalf("budget total = %s, want %s", total, want)
	}
}

// TestDecryptRejectsGarbage: tampered/out-of-range ciphertexts
// fail closed rather than decode to attacker-chosen values.
func TestDecryptRejectsGarbage(t *testing.T) {
	p, err := NewPaillier(2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := p.Decrypt(nil); err == nil {
		t.Fatal("nil ciphertext must fail")
	}
	if _, err := p.Decrypt([]byte{0}); err == nil {
		t.Fatal("zero ciphertext must fail")
	}
	if _, err := p.Decrypt(new(big.Int).Set(p.n2).Bytes()); err == nil {
		t.Fatal("ciphertext >= n^2 must fail")
	}
	// Valid ciphertext tampered by one bit must not error the path —
	// integrity is the seal layer's job; decryption of corrupted c
	// must not panic or lie via error channel.
	c, _ := p.Encrypt(big.NewInt(42))
	c[len(c)-1] ^= 0x01
	if _, err := p.Decrypt(c); err != nil {
		t.Fatalf("corrupted c may decrypt to junk but must not error: %v", err)
	}
}

// Equality proof: zero-knowledge equality branch. The prover proves a ciphertext
// encrypts the claimed message WITHOUT revealing it; the verifier uses
// the public key only. Wrong claim must fail; tamper must fail.
func TestProveEqualBranchesOnCiphertext(t *testing.T) {
	p, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	m := big.NewInt(350_000)
	r := big.NewInt(1234567)
	ct, err := p.EncryptWithR(m, r)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := p.ProveEqual(ct, m, r)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := p.VerifyEqual(ct, m, proof)
	if err != nil || !ok {
		t.Fatalf("honest proof rejected: ok=%v err=%v", ok, err)
	}
	// Wrong claimed message must NOT verify — the branch is sound.
	bad, err := p.ProveEqual(ct, big.NewInt(349_999), r)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = p.VerifyEqual(ct, big.NewInt(349_999), bad)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("proof accepted for a false claim — branch is broken")
	}
	// Tampered proof must not verify.
	tampered := append([]byte(nil), proof...)
	tampered[len(tampered)-1] ^= 0xFF
	if ok, _ := p.VerifyEqual(ct, m, tampered); ok {
		t.Fatal("tampered proof accepted")
	}
	// Tampered ciphertext must not verify against the honest proof.
	ct2 := append([]byte(nil), ct...)
	ct2[0] ^= 0xFF
	if ok, _ := p.VerifyEqual(ct2, m, proof); ok {
		t.Fatal("tampered ciphertext accepted")
	}
	// The transcript must not carry the plaintext or the randomness.
	blob := string(proof)
	if strings.Contains(blob, "350000") || strings.Contains(blob, "1234567") {
		t.Fatal("proof leaks plaintext or randomness")
	}
}

// The aggregate of EncryptWithR ciphertexts is provable with the
// PRODUCT of the randomness (mod n) — the homomorphic-add rule the
// ledger relies on for the sealed escrow branch.
func TestAggregateProofViaRandomnessProduct(t *testing.T) {
	p, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	n := p.N()
	parts := []struct {
		m, r *big.Int
	}{{big.NewInt(200_000), big.NewInt(42)}, {big.NewInt(150_000), big.NewInt(1337)}}
	var cts [][]byte
	r := big.NewInt(1)
	for _, part := range parts {
		ct, err := p.EncryptWithR(part.m, part.r)
		if err != nil {
			t.Fatal(err)
		}
		cts = append(cts, ct)
		r.Mul(r, part.r)
		r.Mod(r, n)
	}
	sum := cts[0]
	for _, c := range cts[1:] {
		sum, err = p.Add(sum, c)
		if err != nil {
			t.Fatal(err)
		}
	}
	proof, err := p.ProveEqual(sum, big.NewInt(350_000), r)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.VerifyEqual(sum, big.NewInt(350_000), proof); err != nil || !ok {
		t.Fatalf("aggregate equality proof failed: ok=%v err=%v", ok, err)
	}
	if ok, _ := p.VerifyEqual(sum, big.NewInt(300_000), proof); ok {
		t.Fatal("aggregate proof accepted a false total")
	}
}
