package settle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/WillBeebe/nexum/v2/internal/he"
)

// TestV202_VerifyPublicRejectsMaliciousPrimePowerModuli verifies BUG-01:
// settle.VerifyPublic rejects both prime-power modulus N=3^650 (small prime factor)
// and N=65539^65 (all prime factors > 65537, blocked by GMR coprimality NIZK).
func TestV202_VerifyPublicRejectsMaliciousPrimePowerModuli(t *testing.T) {
	// Case 1: N = 3^650 rejected by FromPublic trial division / square checks.
	n3 := new(big.Int).Exp(big.NewInt(3), big.NewInt(650), nil)
	ct := []byte{1}
	dummyProof := []byte(`{"a":"AQ==","z":"AQ==","r":["Ag==","Ag==","Ag==","Ag==","Ag==","Ag==","Ag==","Ag=="]}`)
	if err := VerifyPublic(n3.Bytes(), [][]byte{ct}, ct, 3, dummyProof); err == nil {
		t.Fatal("VerifyPublic accepted prime-power modulus N=3^650")
	}

	// Case 2: N = 65539^65 passes FromPublic but fails GMR coprimality NIZK.
	p := big.NewInt(65539)
	nLarge := new(big.Int).Exp(p, big.NewInt(65), nil)
	if _, err := he.FromPublic(nLarge.Bytes()); err != nil {
		t.Fatalf("expected N=65539^65 to pass FromPublic so VerifyPublic tests GMR: %v", err)
	}
	for _, amount := range []int64{65539, 65539 * 1000} {
		if err := VerifyPublic(nLarge.Bytes(), [][]byte{ct}, ct, amount, dummyProof); err == nil {
			t.Fatalf("VerifyPublic accepted prime-power modulus N=65539^65 for amount=%d", amount)
		}
	}
}

// TestV202_VerifyPublicRejectsNonCanonicalCiphertextAndMalleatedProof verifies BUG-29:
// VerifyPublic rejects leading-zero-padded ciphertexts, leading-zero-padded aggregate,
// and malleated proof JSON (leading zeros in A/Z/R, unknown JSON fields, trailing bytes).
func TestV202_VerifyPublicRejectsNonCanonicalCiphertextAndMalleatedProof(t *testing.T) {
	l, err := NewEncryptedLedger(2048)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := l.SealLock(100)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := l.SealLock(250)
	if err != nil {
		t.Fatal(err)
	}
	agg, err := l.Aggregate([][]byte{c1, c2})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := l.ProveEqual(agg, 350)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: valid inputs must verify.
	if err := VerifyPublic(l.PublicModulus(), [][]byte{c1, c2}, agg, 350, proof); err != nil {
		t.Fatalf("valid VerifyPublic rejected: %v", err)
	}

	// Non-canonical leading-zero ciphertext.
	c1Padded := append([]byte{0x00, 0x00, 0x00}, c1...)
	if err := VerifyPublic(l.PublicModulus(), [][]byte{c1Padded, c2}, agg, 350, proof); err == nil {
		t.Fatal("VerifyPublic accepted leading-zero padded ciphertext")
	}

	// Non-canonical leading-zero aggregate.
	aggPadded := append([]byte{0x00}, agg...)
	if err := VerifyPublic(l.PublicModulus(), [][]byte{c1, c2}, aggPadded, 350, proof); err == nil {
		t.Fatal("VerifyPublic accepted leading-zero padded aggregate")
	}

	// Malleated proof JSON with leading zeros in A/Z and unknown field.
	var pf struct {
		A []byte   `json:"a"`
		Z []byte   `json:"z"`
		R [][]byte `json:"r"`
	}
	if err := json.Unmarshal(proof, &pf); err != nil {
		t.Fatal(err)
	}
	malleatedProof, err := json.Marshal(struct {
		A     []byte   `json:"a"`
		Z     []byte   `json:"z"`
		R     [][]byte `json:"r"`
		Extra string   `json:"extra"`
	}{
		A:     pf.A,
		Z:     pf.Z,
		R:     pf.R,
		Extra: "tamper",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublic(l.PublicModulus(), [][]byte{c1, c2}, agg, 350, malleatedProof); err == nil {
		t.Fatal("VerifyPublic accepted proof JSON with unknown field")
	}

	paddedAZProof, err := json.Marshal(struct {
		A []byte   `json:"a"`
		Z []byte   `json:"z"`
		R [][]byte `json:"r"`
	}{
		A: append([]byte{0x00}, pf.A...),
		Z: append([]byte{0x00}, pf.Z...),
		R: pf.R,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublic(l.PublicModulus(), [][]byte{c1, c2}, agg, 350, paddedAZProof); err == nil {
		t.Fatal("VerifyPublic accepted proof JSON with leading-zero A/Z")
	}

	if err := VerifyPublic(l.PublicModulus(), [][]byte{c1, c2}, agg, 350, append(bytes.Clone(proof), []byte("{}")...)); err == nil {
		t.Fatal("VerifyPublic accepted proof JSON with trailing bytes")
	}
}

// TestV202_AggregateSingleLockValidatesUnitCanonicalAndCopies verifies BUG-32:
// EncryptedLedger.Aggregate validates canonical unit membership on single-element input
// and returns a defensive copy that does not alias the caller's slice.
func TestV202_AggregateSingleLockValidatesUnitCanonicalAndCopies(t *testing.T) {
	l, err := NewEncryptedLedger(2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Aggregate([][]byte{{0}}); err == nil {
		t.Fatal("Aggregate accepted non-unit 0")
	}
	if _, err := l.Aggregate([][]byte{nil}); err == nil {
		t.Fatal("Aggregate accepted empty ciphertext")
	}
	if _, err := l.Aggregate([][]byte{l.PublicModulus()}); err == nil {
		t.Fatal("Aggregate accepted non-unit N")
	}

	ct, err := l.SealLock(10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Aggregate([][]byte{append([]byte{0x00}, ct...)}); err == nil {
		t.Fatal("Aggregate accepted leading-zero non-canonical single ciphertext")
	}

	orig := append([]byte(nil), ct...)
	sum, err := l.Aggregate([][]byte{ct})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sum, orig) {
		t.Fatal("single-lock Aggregate did not preserve ciphertext value")
	}
	sum[0] ^= 0xff
	if !bytes.Equal(ct, orig) {
		t.Fatal("single-lock Aggregate aliased caller input slice")
	}
}

// TestV202_RootMerkleDomainSeparationAndCollisionResistance verifies BUG-31:
// settle.Root prevents odd-leaf duplication, leaf/internal confusion,
// variable-length hex split collisions, and empty-slice vs empty-string collisions.
func TestV202_RootMerkleDomainSeparationAndCollisionResistance(t *testing.T) {
	h := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	a, b, c := h("receipt-1"), h("receipt-2"), h("receipt-3")

	if Root([]string{a, b, c}) == Root([]string{a, b, c, c}) {
		t.Fatal("settle.Root suffered CVE-2012-2459 odd-leaf duplication collision")
	}
	ab := Root([]string{a, b})
	if ab == Root([]string{ab}) {
		t.Fatal("settle.Root suffered leaf-vs-internal confusion collision")
	}
	if Root([]string{a}) == a {
		t.Fatal("settle.Root returned raw single leaf without domain separation")
	}
	if Root([]string{"aa", "bbcc"}) == Root([]string{"aabb", "cc"}) {
		t.Fatal("settle.Root suffered variable-length hex split collision")
	}
	if Root(nil) == Root([]string{""}) {
		t.Fatal("settle.Root collided empty slice with single empty string")
	}
}
