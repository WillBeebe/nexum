package l2

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/he"
	"github.com/WillBeebe/nexum/v2/internal/nexum"
	"github.com/WillBeebe/nexum/v2/internal/pow"
	"github.com/WillBeebe/nexum/v2/quarry/keccak"
)

// TestV202_EmptyBatchRejected verifies BUG-35:
// Root, Seal, Verify, and VerifyBatch reject empty agreement slices (len(as) == 0).
func TestV202_EmptyBatchRejected(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	if _, err := Root(nil); err == nil {
		t.Fatal("Root(nil) accepted empty batch")
	}
	if _, err := Root([]*nexum.Agreement{}); err == nil {
		t.Fatal("Root(empty slice) accepted empty batch")
	}
	if _, err := Seal(nil, 4, now); err == nil {
		t.Fatal("Seal(nil) accepted empty batch")
	}

	// Even with a validly mined header committing to keccak256(""), Verify/VerifyBatch must reject.
	st := keccak.NewLegacyKeccak256()
	var emptyRoot [32]byte
	copy(emptyRoot[:], st.Sum(nil))
	h, _, err := pow.Search(pow.Header{BatchRoot: emptyRoot, TimeUnix: now.Unix(), DiffBits: 4}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(nil, h, 4); err == nil {
		t.Fatal("Verify accepted empty agreement slice")
	}
	if err := VerifyBatch(Batch{Agreements: nil, Header: h}, 4); err == nil {
		t.Fatal("VerifyBatch accepted empty agreement slice")
	}
}

// TestV202_ZeroDifficultyAndNonPositiveMinBitsRejected verifies BUG-36:
// Seal rejects bits < 1, and Verify/VerifyBatch reject minBits < 1 and DiffBits < 1.
func TestV202_ZeroDifficultyAndNonPositiveMinBitsRejected(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	a := closed(t, "zero-pow", 100, now)
	as := []*nexum.Agreement{a}

	if _, err := Seal(as, 0, now); err == nil {
		t.Fatal("Seal accepted bits=0")
	}
	if _, err := Seal(as, -1, now); err == nil {
		t.Fatal("Seal accepted bits=-1")
	}

	validBatch, err := Seal(as, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBatch(validBatch, 0); err == nil {
		t.Fatal("VerifyBatch accepted minBits=0")
	}
	if err := VerifyBatch(validBatch, -5); err == nil {
		t.Fatal("VerifyBatch accepted minBits=-5")
	}

	root, err := Root(as)
	if err != nil {
		t.Fatal(err)
	}
	zeroHeader := pow.Header{BatchRoot: root, TimeUnix: now.Unix(), DiffBits: 0}
	if err := Verify(as, zeroHeader, 0); err == nil {
		t.Fatal("Verify accepted DiffBits=0 and minBits=0")
	}
	if err := Verify(as, zeroHeader, 1); err == nil {
		t.Fatal("Verify accepted DiffBits=0")
	}
}

// TestV202_VerifySealedRejectsMaliciousPrimePowerModuli verifies BUG-01 end-to-end
// in l2.VerifySealed for both N=3^650 and N=65539^65 (above trial-division bound).
func TestV202_VerifySealedRejectsMaliciousPrimePowerModuli(t *testing.T) {
	ct := []byte{1}
	commit := sha256.Sum256(ct)
	digestHex := hex.EncodeToString(commit[:])
	dummyProof := []byte(`{"a":"AQ==","z":"AQ==","r":["Ag==","Ag==","Ag==","Ag==","Ag==","Ag==","Ag==","Ag=="]}`)

	// Case 1: N = 3^650 (small prime factor).
	nSmall := new(big.Int).Exp(big.NewInt(3), big.NewInt(650), nil)
	bSmall := nexum.SealedProofBundle{
		Version:       1,
		Scheme:        nexum.SchemePaillier,
		PublicKey:     nSmall.Bytes(),
		Ciphertexts:   [][]byte{ct},
		Commitments:   [][]byte{commit[:]},
		Aggregate:     ct,
		Amount:        3,
		EqualityProof: dummyProof,
		TermsDigest:   digestHex,
		ReceiptHead:   digestHex,
	}
	if err := VerifySealed(bSmall); err == nil {
		t.Fatal("l2.VerifySealed accepted prime-power modulus N=3^650")
	}

	// Case 2: N = 65539^65 (all factors > 65537, blocked by GMR coprimality NIZK).
	nLarge := new(big.Int).Exp(big.NewInt(65539), big.NewInt(65), nil)
	if _, err := he.FromPublic(nLarge.Bytes()); err != nil {
		t.Fatalf("expected N=65539^65 to pass FromPublic: %v", err)
	}
	for _, amount := range []int64{65539, 65539 * 1000} {
		bLarge := nexum.SealedProofBundle{
			Version:       1,
			Scheme:        nexum.SchemePaillier,
			PublicKey:     nLarge.Bytes(),
			Ciphertexts:   [][]byte{ct},
			Commitments:   [][]byte{commit[:]},
			Aggregate:     ct,
			Amount:        amount,
			EqualityProof: dummyProof,
			TermsDigest:   digestHex,
			ReceiptHead:   digestHex,
		}
		if err := VerifySealed(bLarge); err == nil {
			t.Fatalf("l2.VerifySealed accepted prime-power modulus N=65539^65 for amount=%d", amount)
		}
	}
}
