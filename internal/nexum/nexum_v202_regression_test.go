package nexum

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/he"
)

func rehashAgreementV202(a *Agreement) {
	view := *a
	view.Receipts = nil
	view.Unit = Unit{}
	var prev string
	for i := range a.Receipts {
		r := &a.Receipts[i]
		r.Seq = i + 1
		r.PrevHash = prev
		terms := view.TermsDigest()
		r.Hash = hashSignedReceipt("receipt", terms, *r)
		prev = r.Hash
		applyMaterialReceipt(&view, *r)
	}
}

// TestV202_VerifySealedSettlementRejectsNonAcceptedAndMismatchedProof verifies
// BUG-02: PublicSealedProof and VerifySealedSettlement require StatusAccepted,
// a valid "accept" receipt with committed equality proof, and exact equality
// when SealedEqualityProof is also populated.
func TestV202_VerifySealedSettlementRejectsNonAcceptedAndMismatchedProof(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	newLocked := func(id string) *Agreement {
		a, err := OpenAgreementV2(id, "work", "buyer", "seller", 100, Meter{MaxSteps: 16}, now, ModeSealed, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.SetDeadline("buyer", now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
		if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 100}, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		return a
	}

	craftBundle := func(a *Agreement, pf []byte) SealedProofBundle {
		agg := a.SealedAggregate
		if len(agg) == 0 {
			agg = a.SealedSum
		}
		return SealedProofBundle{
			Version:       1,
			Scheme:        SchemePaillier,
			PublicKey:     append([]byte(nil), a.PublicKey...),
			Ciphertexts:   cloneBytes(a.SealedLocks),
			Commitments:   commitCiphertexts(a.SealedLocks),
			Aggregate:     append([]byte(nil), agg...),
			Amount:        a.Amount,
			EqualityProof: append([]byte(nil), pf...),
			TermsDigest:   a.TermsDigest(),
			ReceiptHead:   a.head(),
		}
	}

	// Case 1: REJECTED agreement must be refused by both PublicSealedProof and VerifySealedSettlement.
	rej := newLocked("sealed-rejected")
	if err := rej.Reject("seller", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	pfRej, err := rej.Sealed.ProveEqual(rej.SealedSum, rej.Amount)
	if err != nil {
		t.Fatal(err)
	}
	rej.SealedEqualityProof = pfRej
	if _, err := rej.PublicSealedProof(); err == nil {
		t.Fatal("PublicSealedProof accepted rejected agreement")
	}
	if err := rej.VerifySealedSettlement(craftBundle(rej, pfRej)); err == nil {
		t.Fatal("VerifySealedSettlement accepted rejected agreement")
	}

	// Case 2: EXPIRED agreement must be refused.
	exp := newLocked("sealed-expired")
	if err := exp.Expire("buyer", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	pfExp, err := exp.Sealed.ProveEqual(exp.SealedSum, exp.Amount)
	if err != nil {
		t.Fatal(err)
	}
	exp.SealedEqualityProof = pfExp
	if _, err := exp.PublicSealedProof(); err == nil {
		t.Fatal("PublicSealedProof accepted expired agreement")
	}
	if err := exp.VerifySealedSettlement(craftBundle(exp, pfExp)); err == nil {
		t.Fatal("VerifySealedSettlement accepted expired agreement")
	}

	// Case 3: Still-LOCKED (unaccepted) agreement must be refused.
	lck := newLocked("sealed-locked")
	pfLck, err := lck.Sealed.ProveEqual(lck.SealedSum, lck.Amount)
	if err != nil {
		t.Fatal(err)
	}
	lck.SealedEqualityProof = pfLck
	if _, err := lck.PublicSealedProof(); err == nil {
		t.Fatal("PublicSealedProof accepted locked agreement")
	}
	if err := lck.VerifySealedSettlement(craftBundle(lck, pfLck)); err == nil {
		t.Fatal("VerifySealedSettlement accepted locked agreement")
	}

	// Case 4: Accepted agreement with swapped SealedEqualityProof contradicting "accept" receipt.
	acc := newLocked("sealed-accepted-mismatch")
	if err := acc.Accept("seller", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	// Baseline valid accepted agreement passes, including legacy cleared SealedEqualityProof.
	goodBundle, err := acc.PublicSealedProof()
	if err != nil {
		t.Fatalf("valid accepted PublicSealedProof failed: %v", err)
	}
	if err := acc.VerifySealedSettlement(goodBundle); err != nil {
		t.Fatalf("valid accepted VerifySealedSettlement failed: %v", err)
	}
	legacyAcc := *acc
	legacyAcc.Sealed = nil
	legacyAcc.SealedEqualityProof = nil
	if _, err := legacyAcc.PublicSealedProof(); err != nil {
		t.Fatalf("legacy accepted snapshot without SealedEqualityProof failed: %v", err)
	}
	if err := legacyAcc.VerifySealedSettlement(goodBundle); err != nil {
		t.Fatalf("legacy accepted VerifySealedSettlement failed: %v", err)
	}

	altProof, err := acc.Sealed.ProveEqual(acc.SealedAggregate, acc.Amount)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(altProof, acc.SealedEqualityProof) {
		t.Fatal("fresh ZK proof unexpectedly equal to receipt proof")
	}
	acc.SealedEqualityProof = altProof
	if _, err := acc.PublicSealedProof(); err == nil {
		t.Fatal("PublicSealedProof accepted mismatched SealedEqualityProof")
	}
	if err := acc.VerifySealedSettlement(craftBundle(acc, altProof)); err == nil {
		t.Fatal("VerifySealedSettlement accepted proof contradicting accept receipt")
	}
	// Even passing the original bundle must fail while acc.SealedEqualityProof contradicts receipt.
	if err := acc.VerifySealedSettlement(goodBundle); err == nil {
		t.Fatal("VerifySealedSettlement ignored contradicting SealedEqualityProof field")
	}
}

// TestV202_VerifySealedProofBundleRejectsMaliciousPrimePowerModulus verifies
// BUG-01 across the nexum boundary: VerifySealedProofBundle must reject the
// non-coprime prime-power modulus N = 3^650 and prevent amount equivocation.
func TestV202_VerifySealedProofBundleRejectsMaliciousPrimePowerModulus(t *testing.T) {
	n := new(big.Int).Exp(big.NewInt(3), big.NewInt(650), nil)
	n2 := new(big.Int).Mul(n, n)
	y := new(big.Int).Exp(big.NewInt(4), n, n2)
	l := new(big.Int).Div(new(big.Int).Sub(y, big.NewInt(1)), n)
	u := new(big.Int).Div(l, big.NewInt(3))
	uInv := new(big.Int).ModInverse(u, n)
	w := new(big.Int).Exp(big.NewInt(4), uInv, n)
	wInv := new(big.Int).ModInverse(w, n)

	ct := []byte{1}
	commit := sha256.Sum256(ct)
	digestHex := hex.EncodeToString(commit[:])

	pub, err := he.FromPublic(n.Bytes())
	if err != nil {
		// he.FromPublic rejects N=3^650; confirm VerifySealedProofBundle also rejects it.
		b := SealedProofBundle{
			Version:       1,
			Scheme:        SchemePaillier,
			PublicKey:     n.Bytes(),
			Ciphertexts:   [][]byte{ct},
			Commitments:   [][]byte{commit[:]},
			Aggregate:     ct,
			Amount:        3,
			EqualityProof: []byte(`{"a":"AQ==","z":"AQ=="}`),
			TermsDigest:   digestHex,
			ReceiptHead:   digestHex,
		}
		if err := VerifySealedProofBundle(b); err == nil {
			t.Fatal("VerifySealedProofBundle accepted prime-power modulus N=3^650")
		}
		return
	}

	for _, amount := range []int64{3, 300_000_000} {
		r := new(big.Int).Exp(wInv, big.NewInt(amount/3), n)
		pf, err := pub.ProveEqual(ct, big.NewInt(amount), r)
		if err != nil {
			continue
		}
		b := SealedProofBundle{
			Version:       1,
			Scheme:        SchemePaillier,
			PublicKey:     n.Bytes(),
			Ciphertexts:   [][]byte{ct},
			Commitments:   [][]byte{commit[:]},
			Aggregate:     ct,
			Amount:        amount,
			EqualityProof: pf,
			TermsDigest:   digestHex,
			ReceiptHead:   digestHex,
		}
		if err := VerifySealedProofBundle(b); err == nil {
			t.Fatalf("VerifySealedProofBundle accepted malicious prime-power modulus N=3^650 for Amount=%d", amount)
		}
	}
}

// TestV202_VerifyReceiptsRejectsModeViolationsPastDeadlinesAndInvalidTerms
// verifies BUG-14: Agreement.VerifyReceipts enforces terms, Format/Mode,
// mode-specific lock/seal transitions, no mixing lock+seal, and future deadlines.
func TestV202_VerifyReceiptsRejectsModeViolationsPastDeadlinesAndInvalidTerms(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	t1 := now.Add(time.Second)
	t2 := now.Add(2 * time.Second)

	// (a) FormatV2 ModePlaintext with a "seal" receipt.
	plainWithSeal := &Agreement{
		ID: "mode-plain-seal", Kind: "work", Buyer: "buyer", Seller: "seller",
		Amount: 10, Format: FormatV2, Mode: ModePlaintext,
		Status: StatusLocked, CreatedAt: now, LockedAt: &t1,
		Receipts: []Receipt{
			{At: now, Action: "open", Actor: "buyer", Note: "agreement opened"},
			{At: t1, Action: "seal", Actor: "buyer", Note: "not-even-ciphertext"},
		},
	}
	rehashAgreementV202(plainWithSeal)
	if err := plainWithSeal.VerifyReceipts(); err == nil {
		t.Fatal("VerifyReceipts accepted seal receipt on ModePlaintext")
	}

	// (b) FormatV2 ModeSealed with a plaintext "lock" receipt.
	sealedWithLock := &Agreement{
		ID: "mode-sealed-lock", Kind: "work", Buyer: "buyer", Seller: "seller",
		Amount: 10, Format: FormatV2, Mode: ModeSealed, Scheme: SchemePaillier,
		PublicKey: bytes.Repeat([]byte{1}, 128),
		Status:    StatusLocked, CreatedAt: now, LockedAt: &t1,
		Receipts: []Receipt{
			{At: now, Action: "open", Actor: "buyer", Note: "agreement opened"},
			{At: t1, Action: "lock", Actor: "buyer", Note: "value locked"},
		},
	}
	rehashAgreementV202(sealedWithLock)
	if err := sealedWithLock.VerifyReceipts(); err == nil {
		t.Fatal("VerifyReceipts accepted plaintext lock receipt on ModeSealed")
	}

	// (c) Plaintext "lock" followed by "seal" on the same agreement.
	mixedLockSeal := &Agreement{
		ID: "mixed-lock-seal", Kind: "work", Buyer: "buyer", Seller: "seller",
		Amount: 10, Status: StatusLocked, CreatedAt: now, LockedAt: &t2,
		Receipts: []Receipt{
			{At: now, Action: "open", Actor: "buyer", Note: "agreement opened"},
			{At: t1, Action: "lock", Actor: "buyer", Note: "value locked"},
			{At: t2, Action: "seal", Actor: "buyer", Note: "AAAA"},
		},
	}
	rehashAgreementV202(mixedLockSeal)
	if err := mixedLockSeal.VerifyReceipts(); err == nil {
		t.Fatal("VerifyReceipts accepted lock followed by seal")
	}

	// (d) Backdated "deadline" receipt (1970) followed by immediate "expire".
	pastDeadline := &Agreement{
		ID: "past-deadline", Kind: "work", Buyer: "buyer", Seller: "seller",
		Amount: 10, Status: StatusExpired, CreatedAt: now, ClosedAt: &now, ReleasedTo: "buyer",
		Receipts: []Receipt{
			{At: now, Action: "open", Actor: "buyer", Note: "agreement opened"},
			{At: now, Action: "deadline", Actor: "buyer", Note: "1970-01-01T00:00:00Z"},
			{At: now, Action: "expire", Actor: "buyer", Note: "deadline passed, value unlocked"},
		},
	}
	rehashAgreementV202(pastDeadline)
	if err := pastDeadline.VerifyReceipts(); err == nil {
		t.Fatal("VerifyReceipts accepted backdated deadline receipt")
	}

	// (e) Invalid terms: empty ID, empty Kind, Buyer==Seller, negative Amount, bad Format/Mode.
	invalidCases := map[string]func(*Agreement){
		"empty-id":     func(a *Agreement) { a.ID = "" },
		"empty-kind":   func(a *Agreement) { a.Kind = "" },
		"empty-buyer":  func(a *Agreement) { a.Buyer = "" },
		"empty-seller": func(a *Agreement) { a.Seller = "" },
		"same-party":   func(a *Agreement) { a.Seller = a.Buyer },
		"neg-amount":   func(a *Agreement) { a.Amount = -999 },
		"zero-amount":  func(a *Agreement) { a.Amount = 0 },
		"bad-format":   func(a *Agreement) { a.Format = 99 },
		"bad-v2-mode":  func(a *Agreement) { a.Format = FormatV2; a.Mode = "bogus" },
		"v0-with-mode": func(a *Agreement) { a.Format = 0; a.Mode = ModePlaintext },
	}
	for name, mutate := range invalidCases {
		t.Run(name, func(t *testing.T) {
			a := &Agreement{
				ID: "valid-id", Kind: "work", Buyer: "buyer", Seller: "seller",
				Amount: 10, Status: StatusOpen, CreatedAt: now,
				Receipts: []Receipt{{At: now, Action: "open", Actor: "buyer", Note: "opened"}},
			}
			mutate(a)
			rehashAgreementV202(a)
			if err := a.VerifyReceipts(); err == nil {
				t.Fatalf("VerifyReceipts accepted invalid terms (%s)", name)
			}
		})
	}
}

// TestV202_MeterRejectsNaNInfAndNegativeAcrossLedgers verifies BUG-33 across
// constructors, post-open transitions, and VerifyReceipts for Agreement,
// Council, Delegate, and Workflow.
func TestV202_MeterRejectsNaNInfAndNegativeAcrossLedgers(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	nodes := map[string]Node{
		"start": {ID: "start", Kind: "gate", Next: []string{"done"}},
		"done":  {ID: "done", Kind: "action"},
	}

	badMeters := []struct {
		name  string
		meter Meter
	}{
		{"cost-nan", Meter{BudgetUSD: 1.0, CostUSD: math.NaN(), MaxSteps: 8}},
		{"budget-nan", Meter{BudgetUSD: math.NaN(), CostUSD: 1e9, MaxSteps: 8}},
		{"cost-pos-inf", Meter{BudgetUSD: 1.0, CostUSD: math.Inf(1), MaxSteps: 8}},
		{"cost-neg-inf", Meter{BudgetUSD: 1.0, CostUSD: math.Inf(-1), MaxSteps: 8}},
		{"budget-pos-inf", Meter{BudgetUSD: math.Inf(1), CostUSD: 1.0, MaxSteps: 8}},
		{"budget-neg-inf", Meter{BudgetUSD: math.Inf(-1), CostUSD: 1.0, MaxSteps: 8}},
		{"cost-neg", Meter{BudgetUSD: 1.0, CostUSD: -0.5, MaxSteps: 8}},
		{"budget-neg", Meter{BudgetUSD: -1.0, CostUSD: 0, MaxSteps: 8}},
	}

	for _, tc := range badMeters {
		t.Run("open/"+tc.name, func(t *testing.T) {
			if _, err := OpenAgreement("m-agr", "work", "buyer", "seller", 10, tc.meter, now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenAgreement(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if _, err := OpenAgreementV2("m-agr2", "work", "buyer", "seller", 10, tc.meter, now, ModePlaintext, 0); !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenAgreementV2(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if _, err := OpenEscrow("m-esc", "buyer", "seller", 10, tc.meter, now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenEscrow(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if _, err := OpenCouncil("m-c", []Party{"a", "b", "c"}, []Requirement{{ID: "r1", Holder: "a"}}, "ship", tc.meter, now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenCouncil(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if _, err := OpenDelegate("m-d", "parent", "intern", 10, Task{Offer: "do work"}, tc.meter, now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenDelegate(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if _, err := OpenWorkflow("m-w", "runner", "start", nodes, tc.meter, now); !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenWorkflow(%s): got %v, want ErrInvalid", tc.name, err)
			}
		})
	}

	// Post-open mutation to NaN/Inf/negative must fail both transition and VerifyReceipts.
	for _, tc := range badMeters {
		t.Run("post-open/"+tc.name, func(t *testing.T) {
			a, err := OpenAgreement("mut-a", "work", "buyer", "seller", 10, Meter{BudgetUSD: 1, MaxSteps: 8}, now)
			if err != nil {
				t.Fatal(err)
			}
			a.Meter = tc.meter
			if err := a.Lock("buyer", now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Agreement.Lock(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if err := a.VerifyReceipts(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Agreement.VerifyReceipts(%s): got %v, want ErrInvalid", tc.name, err)
			}

			c, err := OpenCouncil("mut-c", []Party{"a", "b", "c"}, []Requirement{{ID: "r1", Holder: "a"}}, "ship", Meter{BudgetUSD: 1, MaxSteps: 8}, now)
			if err != nil {
				t.Fatal(err)
			}
			c.Meter = tc.meter
			if err := c.Satisfy("a", "r1", "cite", now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Council.Satisfy(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if err := c.VerifyReceipts(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Council.VerifyReceipts(%s): got %v, want ErrInvalid", tc.name, err)
			}

			d, err := OpenDelegate("mut-d", "parent", "intern", 10, Task{Offer: "do work"}, Meter{BudgetUSD: 1, MaxSteps: 8}, now)
			if err != nil {
				t.Fatal(err)
			}
			d.Meter = tc.meter
			if err := d.Claim("intern", now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Delegate.Claim(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if err := d.VerifyReceipts(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Delegate.VerifyReceipts(%s): got %v, want ErrInvalid", tc.name, err)
			}

			w, err := OpenWorkflow("mut-w", "runner", "start", nodes, Meter{MaxSteps: 8}, now)
			if err != nil {
				t.Fatal(err)
			}
			w.Meter = tc.meter
			if err := w.Execute("runner", map[string]bool{}, now.Add(time.Second)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Workflow.Execute(%s): got %v, want ErrInvalid", tc.name, err)
			}
			if err := w.VerifyReceipts(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Workflow.VerifyReceipts(%s): got %v, want ErrInvalid", tc.name, err)
			}
		})
	}
}

// TestV202_SignReceiptsRejectsCorruptedKeyAndDeepClones verifies BUG-15 across
// Agreement, Council, Delegate, and Workflow.
func TestV202_SignReceiptsRejectsCorruptedKeyAndDeepClones(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	_, goodKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	corruptKey := append(ed25519.PrivateKey(nil), goodKey...)
	corruptKey[len(corruptKey)-1] ^= 0x01

	// 1. Corrupted 64-byte ed25519 key must be rejected with ErrInvalid on all 4 ledgers.
	a, err := OpenAgreement("sig-corrupt-agr", "work", "buyer", "seller", 10, Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SignReceipts(map[Party]ed25519.PrivateKey{"buyer": corruptKey}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Agreement.SignReceipts corrupted key: got %v, want ErrInvalid", err)
	}

	c, err := OpenCouncil("sig-corrupt-c", []Party{"a", "b", "c"}, []Requirement{{ID: "r1", Holder: "a"}}, "ship", Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SignReceipts(map[Party]ed25519.PrivateKey{"a": corruptKey}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Council.SignReceipts corrupted key: got %v, want ErrInvalid", err)
	}

	d, err := OpenDelegate("sig-corrupt-d", "parent", "intern", 10, Task{Offer: "job"}, Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SignReceipts(map[Party]ed25519.PrivateKey{"intern": corruptKey}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Delegate.SignReceipts corrupted key: got %v, want ErrInvalid", err)
	}

	nodes := map[string]Node{
		"start": {ID: "start", Kind: "gate", Next: []string{"done"}},
		"done":  {ID: "done", Kind: "action"},
	}
	w, err := OpenWorkflow("sig-corrupt-w", "runner", "start", nodes, Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SignReceipts(map[Party]ed25519.PrivateKey{"runner": corruptKey}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Workflow.SignReceipts corrupted key: got %v, want ErrInvalid", err)
	}

	// 2. Deep-cloning prevents caller map AND byte-slice mutations from aliasing ledger state.
	keyCopy := append(ed25519.PrivateKey(nil), goodKey...)
	keys := map[Party]ed25519.PrivateKey{"buyer": keyCopy}
	a2, err := OpenAgreement("sig-alias", "work", "buyer", "seller", 10, Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a2.SignReceipts(keys); err != nil {
		t.Fatal(err)
	}
	// Mutate both the underlying key bytes and the caller's map entry.
	for i := range keyCopy {
		keyCopy[i] ^= 0xff
	}
	keys["buyer"] = ed25519.PrivateKey("short")

	if err := a2.Lock("buyer", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(a2.Receipts[1].ActorSignature) != ed25519.SignatureSize {
		t.Fatal("caller map/slice mutation downgraded receipt to unsigned")
	}
	if err := a2.VerifyReceipts(); err != nil {
		t.Fatalf("VerifyReceipts failed after caller mutated original key slice: %v", err)
	}
}

// TestV202_DecodedSealedSnapshotEnforcesCustody verifies BUG-16: WithUnitAt
// enforces custody on decoded ModeSealed snapshots, and decoded Format-1
// StartSealed snapshots refuse plaintext Lock/Accept and second StartSealed.
func TestV202_DecodedSealedSnapshotEnforcesCustody(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	// (1) FormatV2 ModeSealed decoded snapshot refuses WithUnitAt.
	v2, err := OpenAgreementV2("v2-sealed-unit", "work", "buyer", "seller", 10, Meter{MaxSteps: 8}, now, ModeSealed, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rawV2, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	var decV2 Agreement
	if err := json.Unmarshal(rawV2, &decV2); err != nil {
		t.Fatal(err)
	}
	if err := decV2.WithUnitAt(TokenNEX, now.Add(time.Second)); !errors.Is(err, ErrBadState) {
		t.Fatalf("decoded ModeSealed WithUnitAt: got %v, want ErrBadState", err)
	}
	if decV2.Unit.Symbol != "" {
		t.Fatalf("failed WithUnitAt mutated Unit to %q", decV2.Unit.Symbol)
	}

	// (2) Format-1 agreement armed with StartSealed before first seal, then JSON decoded.
	v1, err := OpenEscrow("v1-armed-sealed", "buyer", "seller", 10, Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := v1.StartSealed(2048); err != nil {
		t.Fatal(err)
	}
	origPub := append([]byte(nil), v1.PublicKey...)
	rawV1, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	var decV1A, decV1B Agreement
	if err := json.Unmarshal(rawV1, &decV1A); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawV1, &decV1B); err != nil {
		t.Fatal(err)
	}
	if err := decV1A.Lock("buyer", now.Add(time.Second)); !errors.Is(err, ErrBadState) {
		t.Fatalf("decoded Format-1 StartSealed Lock: got %v, want ErrBadState", err)
	}
	if err := decV1A.WithUnitAt(TokenNEX, now.Add(time.Second)); !errors.Is(err, ErrBadState) {
		t.Fatalf("decoded Format-1 StartSealed WithUnitAt: got %v, want ErrBadState", err)
	}
	if err := decV1B.StartSealed(2048); !errors.Is(err, ErrBadState) {
		t.Fatalf("decoded Format-1 StartSealed second StartSealed: got %v, want ErrBadState", err)
	}
	if !bytes.Equal(origPub, decV1B.PublicKey) {
		t.Fatal("failed StartSealed replaced PublicKey")
	}
}

// TestV202_SiblingLedgersEnforceMaxSteps128Bound verifies BUG-42: OpenCouncil,
// OpenDelegate, and OpenWorkflow enforce MaxSteps <= 128 like Agreement.
func TestV202_SiblingLedgersEnforceMaxSteps128Bound(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	nodes := map[string]Node{
		"start": {ID: "start", Kind: "gate", Next: []string{"done"}},
		"done":  {ID: "done", Kind: "action"},
	}

	for _, steps := range []int{129, 1_000_000} {
		over := Meter{MaxSteps: steps}
		if _, err := OpenCouncil("cap-c", []Party{"a", "b", "c"}, nil, "ship", over, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("OpenCouncil(MaxSteps=%d): got %v, want ErrInvalid", steps, err)
		}
		if _, err := OpenDelegate("cap-d", "p", "i", 10, Task{Offer: "job"}, over, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("OpenDelegate(MaxSteps=%d): got %v, want ErrInvalid", steps, err)
		}
		if _, err := OpenWorkflow("cap-w", "runner", "start", nodes, over, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("OpenWorkflow(MaxSteps=%d): got %v, want ErrInvalid", steps, err)
		}
	}

	// Boundary value 128 remains accepted.
	atCap := Meter{MaxSteps: 128}
	if _, err := OpenCouncil("ok-c", []Party{"a", "b", "c"}, nil, "ship", atCap, now); err != nil {
		t.Fatalf("OpenCouncil(MaxSteps=128): %v", err)
	}
	if _, err := OpenDelegate("ok-d", "p", "i", 10, Task{Offer: "job"}, atCap, now); err != nil {
		t.Fatalf("OpenDelegate(MaxSteps=128): %v", err)
	}
	if _, err := OpenWorkflow("ok-w", "runner", "start", nodes, atCap, now); err != nil {
		t.Fatalf("OpenWorkflow(MaxSteps=128): %v", err)
	}
}

// TestV202_LegacyWorkflowDuplicateNextRetainsPathReplayAssurance verifies
// BUG-43: duplicate edges in Node.Next do not double-count an unambiguous
// Format-0 walk or downgrade ReceiptAssurance from path-replay.
func TestV202_LegacyWorkflowDuplicateNextRetainsPathReplayAssurance(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	nodes := map[string]Node{
		"start gate": {ID: "start gate", Kind: "gate", Next: []string{"finish", "finish"}},
		"finish":     {ID: "finish", Kind: "action"},
	}
	w, err := openWorkflow(0, "dup-next", "runner", "start gate", nodes, Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Execute("runner", map[string]bool{}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	assurance, err := w.ReceiptAssurance()
	if err != nil {
		t.Fatal(err)
	}
	if assurance != AssurancePathReplay {
		t.Fatalf("got assurance %q, want %q", assurance, AssurancePathReplay)
	}
}

// TestV202_EmptyAgreementIDRejectedAtOpen verifies BUG-44: OpenAgreement,
// OpenAgreementV2, and OpenEscrow reject id == "" with ErrInvalid.
func TestV202_EmptyAgreementIDRejectedAtOpen(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	if _, err := OpenAgreement("", "work", "buyer", "seller", 10, Meter{MaxSteps: 8}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("OpenAgreement empty ID: got %v, want ErrInvalid", err)
	}
	if _, err := OpenAgreementV2("", "work", "buyer", "seller", 10, Meter{MaxSteps: 8}, now, ModePlaintext, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("OpenAgreementV2 empty ID: got %v, want ErrInvalid", err)
	}
	if _, err := OpenEscrow("", "buyer", "seller", 10, Meter{MaxSteps: 8}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("OpenEscrow empty ID: got %v, want ErrInvalid", err)
	}
}
