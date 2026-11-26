package nexum

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func fuzzFlipHexChar(s string) string {
	if len(s) == 0 {
		return "0"
	}
	b := []byte(s)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

func fuzzBuildSealedSeeds(tb testing.TB) ([]Agreement, []SealedProofBundle) {
	tb.Helper()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	// 1. Legacy Format 0 sealed agreement (OpenEscrow + StartSealed).
	a1, err := OpenEscrow("fuzz-sealed-v1", "buyer", "seller", 350_000, Meter{}, now)
	if err != nil {
		tb.Fatal(err)
	}
	if err := a1.StartSealed(2048); err != nil {
		tb.Fatal(err)
	}
	if err := a1.Apply(Move{Actor: "buyer", Action: "seal", Partial: 200_000}, now.Add(time.Minute)); err != nil {
		tb.Fatal(err)
	}
	if err := a1.Apply(Move{Actor: "buyer", Action: "seal", Partial: 150_000}, now.Add(2*time.Minute)); err != nil {
		tb.Fatal(err)
	}
	if err := a1.Accept("seller", now.Add(3*time.Minute)); err != nil {
		tb.Fatal(err)
	}
	b1, err := a1.PublicSealedProof()
	if err != nil {
		tb.Fatal(err)
	}
	pub1 := *a1
	pub1.Sealed = nil
	if err := pub1.VerifySealedSettlement(b1); err != nil {
		tb.Fatalf("v1 sealed seed failed verification: %v", err)
	}

	// 2. FormatV2 sealed agreement with signed Ed25519 receipts.
	_, buyerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	_, sellerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	a2, err := OpenAgreementV2("fuzz-sealed-v2", KindHouseEscrow, "buyer", "seller", 42_000, Meter{BudgetUSD: 5, MaxSteps: 32}, now, ModeSealed, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	if err := a2.SignReceipts(map[Party]ed25519.PrivateKey{"buyer": buyerKey, "seller": sellerKey}); err != nil {
		tb.Fatal(err)
	}
	if err := a2.Apply(Move{Actor: "buyer", Action: "seal", Partial: 42_000}, now.Add(time.Minute)); err != nil {
		tb.Fatal(err)
	}
	if err := a2.Accept("seller", now.Add(2*time.Minute)); err != nil {
		tb.Fatal(err)
	}
	b2, err := a2.PublicSealedProof()
	if err != nil {
		tb.Fatal(err)
	}
	pub2 := *a2
	pub2.Sealed = nil
	if err := pub2.VerifySealedSettlement(b2); err != nil {
		tb.Fatalf("v2 sealed seed failed verification: %v", err)
	}

	return []Agreement{pub1, pub2}, []SealedProofBundle{b1, b2}
}

func fuzzCloneBundle(b SealedProofBundle) SealedProofBundle {
	out := b
	out.PublicKey = append([]byte(nil), b.PublicKey...)
	out.Ciphertexts = cloneBytes(b.Ciphertexts)
	out.Commitments = cloneBytes(b.Commitments)
	out.Aggregate = append([]byte(nil), b.Aggregate...)
	out.EqualityProof = append([]byte(nil), b.EqualityProof...)
	return out
}

func FuzzVerifySealedSettlement(f *testing.F) {
	agreements, bundles := fuzzBuildSealedSeeds(f)

	for i := range agreements {
		aRaw, err := json.Marshal(agreements[i])
		if err != nil {
			f.Fatal(err)
		}
		bRaw, err := json.Marshal(bundles[i])
		if err != nil {
			f.Fatal(err)
		}
		f.Add(aRaw, bRaw)
	}

	// Mutated & edge-case seeds.
	a1Raw, _ := json.Marshal(agreements[0])
	b1Raw, _ := json.Marshal(bundles[0])

	forgedProof := fuzzCloneBundle(bundles[0])
	forgedProof.EqualityProof[0] ^= 0xff
	if raw, err := json.Marshal(forgedProof); err == nil {
		f.Add(a1Raw, raw)
	}

	swappedCT := fuzzCloneBundle(bundles[0])
	swappedCT.Ciphertexts[0][0] ^= 0xff
	swappedCT.Commitments = commitCiphertexts(swappedCT.Ciphertexts)
	if raw, err := json.Marshal(swappedCT); err == nil {
		f.Add(a1Raw, raw)
	}

	badAmount := fuzzCloneBundle(bundles[0])
	badAmount.Amount++
	if raw, err := json.Marshal(badAmount); err == nil {
		f.Add(a1Raw, raw)
	}

	badAgg := fuzzCloneBundle(bundles[0])
	badAgg.Aggregate[0] ^= 0x01
	if raw, err := json.Marshal(badAgg); err == nil {
		f.Add(a1Raw, raw)
	}

	tamperedAgreement := agreements[1]
	tamperedAgreement.PublicKey = append([]byte(nil), agreements[1].PublicKey...)
	tamperedAgreement.PublicKey[0] ^= 0xff
	if raw, err := json.Marshal(tamperedAgreement); err == nil {
		b2Raw, _ := json.Marshal(bundles[1])
		f.Add(raw, b2Raw)
	}

	// Cross-agreement bundle mismatch.
	if b2Raw, err := json.Marshal(bundles[1]); err == nil {
		f.Add(a1Raw, b2Raw)
	}

	f.Add([]byte(`{`), b1Raw)
	f.Add(a1Raw, []byte(`{`))
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte(`null`), []byte(`null`))
	f.Add([]byte{}, []byte{})

	f.Fuzz(func(t *testing.T, agreementJSON, bundleJSON []byte) {
		var a Agreement
		var b SealedProofBundle
		aErr := json.Unmarshal(agreementJSON, &a)
		bErr := json.Unmarshal(bundleJSON, &b)

		// Nil receiver must always fail closed.
		if err := (*Agreement)(nil).VerifySealedSettlement(b); err == nil {
			t.Fatal("nil Agreement verified sealed settlement")
		}

		// Independent bundle verification must never panic.
		bundleValid := false
		if bErr == nil {
			bundleValid = VerifySealedProofBundle(b) == nil
		}

		if aErr != nil || bErr != nil {
			if aErr == nil {
				_, _ = a.PublicSealedProof()
			}
			return
		}

		// PublicSealedProof must never panic on arbitrary unmarshaled agreements.
		_, _ = a.PublicSealedProof()

		err := a.VerifySealedSettlement(b)
		if err != nil {
			return
		}

		// Fail-closed invariants on every accepted (Agreement, SealedProofBundle) pair.
		if !bundleValid {
			t.Fatal("VerifySealedSettlement accepted a bundle rejected by VerifySealedProofBundle")
		}
		if a.Status != StatusAccepted || a.Amount <= 0 || b.Amount != a.Amount {
			t.Fatalf("accepted invalid status/amount: status=%s a.Amount=%d b.Amount=%d", a.Status, a.Amount, b.Amount)
		}
		if b.TermsDigest != a.TermsDigest() || b.ReceiptHead != a.head() {
			t.Fatal("accepted mismatched terms digest or receipt head")
		}
		if len(b.Ciphertexts) == 0 || len(b.Ciphertexts) != len(a.SealedLocks) {
			t.Fatal("accepted mismatched ciphertext count")
		}
		if err := a.VerifyReceipts(); err != nil {
			t.Fatalf("VerifySealedSettlement accepted agreement with invalid receipts: %v", err)
		}

		// Mutating any cryptographic or binding field must fail closed.
		mutProof := fuzzCloneBundle(b)
		mutProof.EqualityProof[0] ^= 0x01
		if a.VerifySealedSettlement(mutProof) == nil {
			t.Fatal("VerifySealedSettlement accepted flipped EqualityProof bit")
		}
		if VerifySealedProofBundle(mutProof) == nil {
			t.Fatal("VerifySealedProofBundle accepted flipped EqualityProof bit")
		}

		mutAgg := fuzzCloneBundle(b)
		mutAgg.Aggregate[len(mutAgg.Aggregate)-1] ^= 0x01
		if a.VerifySealedSettlement(mutAgg) == nil {
			t.Fatal("VerifySealedSettlement accepted mutated Aggregate")
		}

		mutCT := fuzzCloneBundle(b)
		mutCT.Ciphertexts[0][0] ^= 0x01
		if a.VerifySealedSettlement(mutCT) == nil {
			t.Fatal("VerifySealedSettlement accepted mutated ciphertext")
		}
		mutCT.Commitments = commitCiphertexts(mutCT.Ciphertexts)
		if a.VerifySealedSettlement(mutCT) == nil {
			t.Fatal("VerifySealedSettlement accepted mutated ciphertext with recomputed commitment")
		}

		mutAmt := fuzzCloneBundle(b)
		mutAmt.Amount++
		if a.VerifySealedSettlement(mutAmt) == nil {
			t.Fatal("VerifySealedSettlement accepted mutated Amount")
		}

		mutTerms := fuzzCloneBundle(b)
		mutTerms.TermsDigest = fuzzFlipHexChar(mutTerms.TermsDigest)
		if a.VerifySealedSettlement(mutTerms) == nil {
			t.Fatal("VerifySealedSettlement accepted mutated TermsDigest")
		}

		mutHead := fuzzCloneBundle(b)
		mutHead.ReceiptHead = fuzzFlipHexChar(mutHead.ReceiptHead)
		if a.VerifySealedSettlement(mutHead) == nil {
			t.Fatal("VerifySealedSettlement accepted mutated ReceiptHead")
		}

		mutAgreement := a
		mutAgreement.Status = StatusRejected
		if mutAgreement.VerifySealedSettlement(b) == nil {
			t.Fatal("VerifySealedSettlement accepted non-accepted Agreement status")
		}
	})
}
