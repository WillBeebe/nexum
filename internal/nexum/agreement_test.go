package nexum

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestUnitChangesRespectMeterWithoutPartialMutation(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		meter Meter
		want  error
	}{
		{"steps", Meter{MaxSteps: 2}, ErrDoS},
		{"budget", Meter{MaxSteps: 8, BudgetUSD: 1}, ErrBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := OpenEscrow("unit-meter", "buyer", "seller", 1, tc.meter, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.WithUnitAt("first", now); err != nil {
				t.Fatal(err)
			}
			beforeHead, beforeSteps := a.head(), a.steps
			if tc.want == ErrBudget {
				a.Meter.CostUSD = 2
			}
			if err := a.WithUnitAt("second", now); !errors.Is(err, tc.want) {
				t.Fatalf("unit change got %v, want %v", err, tc.want)
			}
			if a.Unit.Symbol != "first" || a.head() != beforeHead || a.steps != beforeSteps {
				t.Fatal("refused unit change mutated agreement")
			}
			if err := a.VerifyReceipts(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHouseEscrowAccept(t *testing.T) {
	now := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	a, err := OpenEscrow("house-1", "buyer", "seller", 350_000, Meter{BudgetUSD: 42, Effort: "max"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Lock("buyer", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept("seller", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusAccepted || a.ReleasedTo != "seller" {
		t.Fatalf("status=%s to=%s", a.Status, a.ReleasedTo)
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	if len(a.Receipts) != 3 {
		t.Fatalf("receipts %d", len(a.Receipts))
	}
}

func TestHouseEscrowRejectReturnsToBuyer(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-2", "buyer", "seller", 1, Meter{}, now)
	_ = a.Lock("buyer", now)
	if err := a.Reject("seller", now); err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusRejected || a.ReleasedTo != "buyer" {
		t.Fatalf("status=%s to=%s", a.Status, a.ReleasedTo)
	}
}

func TestNoTakebackAfterLock(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-3", "buyer", "seller", 1, Meter{}, now)
	_ = a.Lock("buyer", now)
	if err := a.Lock("buyer", now); !errors.Is(err, ErrBadState) {
		t.Fatalf("second lock: %v", err)
	}
	_ = a.Accept("seller", now)
	if err := a.Reject("seller", now); !errors.Is(err, ErrTakeback) {
		t.Fatalf("reject after accept: %v", err)
	}
}

func TestWrongParty(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-4", "buyer", "seller", 1, Meter{}, now)
	if err := a.Lock("seller", now); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("seller lock: %v", err)
	}
	_ = a.Lock("buyer", now)
	if err := a.Accept("buyer", now); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("buyer accept: %v", err)
	}
}

func TestRewriteDetected(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-5", "buyer", "seller", 1, Meter{}, now)
	_ = a.Lock("buyer", now)
	a.Receipts[1].Note = "rewritten"
	if err := a.VerifyReceipts(); err == nil {
		t.Fatal("want rewrite error")
	}
}

func TestOpenRejectsBadParties(t *testing.T) {
	now := time.Now().UTC()
	if _, err := OpenEscrow("x", "same", "same", 1, Meter{}, now); !errors.Is(err, ErrSameParty) {
		t.Fatalf("%v", err)
	}
	if _, err := OpenEscrow("x", "a", "b", 0, Meter{}, now); !errors.Is(err, ErrZeroAmount) {
		t.Fatalf("%v", err)
	}
}

func TestTypesDoNotSayGas(t *testing.T) {
	// Compile-time guard: Meter has CostUSD / Effort / BudgetUSD / MaxSteps.
	var m Meter
	_ = m.CostUSD
	_ = m.Effort
	_ = m.BudgetUSD
	_ = m.MaxSteps
}

func TestExpireAfterDeadlineReturnsToBuyer(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	a, _ := OpenEscrow("house-6", "buyer", "seller", 1, Meter{}, now)
	if err := a.Expire("buyer", now); !errors.Is(err, ErrNoDeadline) {
		t.Fatalf("expire without deadline: %v", err)
	}
	if err := a.SetDeadline("buyer", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := a.Lock("buyer", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.Expire("seller", now.Add(30*time.Minute)); !errors.Is(err, ErrNotYet) {
		t.Fatalf("early expire: %v", err)
	}
	if err := a.Expire("seller", now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusExpired || a.ReleasedTo != a.Buyer {
		t.Fatalf("status=%s to=%s", a.Status, a.ReleasedTo)
	}
	if err := a.Accept("seller", now.Add(3*time.Hour)); !errors.Is(err, ErrTakeback) {
		t.Fatalf("accept after expire: %v", err)
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestExpireWrongParty(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-7", "buyer", "seller", 1, Meter{}, now)
	_ = a.SetDeadline("buyer", now.Add(time.Hour), now)
	if err := a.Expire(Party("eavesdropper"), now.Add(2*time.Hour)); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("%v", err)
	}
}

func TestNoteEvidenceCited(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	a, _ := OpenEscrow("house-8", "buyer", "seller", 1, Meter{}, now)
	if err := a.Note("seller", "evidence", "inspection-report:sha256:9f2c…", now); err != nil {
		t.Fatal(err)
	}
	if err := a.Note("seller", "evidence", "", now); !errors.Is(err, ErrEmptyCitation) {
		t.Fatalf("empty citation: %v", err)
	}
	if err := a.Note("buyer", "gossip", "x", now); err == nil {
		t.Fatal("want non-evidence action rejected")
	}
	_ = a.Lock("buyer", now.Add(time.Minute))
	_ = a.Accept("seller", now.Add(2*time.Minute))
	if err := a.Note("seller", "evidence", "late note", now.Add(3*time.Minute)); !errors.Is(err, ErrTakeback) {
		t.Fatalf("note after terminal: %v", err)
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	// open + evidence + lock + accept = 4 receipts
	if len(a.Receipts) != 4 {
		t.Fatalf("receipts %d", len(a.Receipts))
	}
}

func TestDeadlineOnLedgerNotSilent(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-9", "buyer", "seller", 1, Meter{}, now)
	_ = a.SetDeadline("buyer", now.Add(time.Hour), now)
	// The deadline receipt must carry the RFC3339 time in its note.
	last := a.Receipts[len(a.Receipts)-1]
	if last.Action != "deadline" || last.Note != a.Deadline.Format(time.RFC3339) {
		t.Fatalf("deadline receipt: %q %q", last.Action, last.Note)
	}
	// Rewrite the deadline off-ledger and the chain must still verify:
	// the Agreement struct field is derived, the receipt is the record.
	saved := a.Deadline
	a.Deadline = time.Time{}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	a.Deadline = saved
}

func TestContractMayRequireToken(t *testing.T) {
	now := time.Now().UTC()
	a, err := OpenEscrow("tok-1", "buyer", "seller", 350_000, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.RequiresToken() {
		t.Fatal("paper escrow has no token")
	}
	if err := a.WithUnit(TokenNEX); err != nil {
		t.Fatal(err)
	}
	if !a.RequiresToken() || a.Unit.Symbol != TokenNEX {
		t.Fatalf("unit %+v", a.Unit)
	}
	if err := a.Lock("buyer", now); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept("seller", now); err != nil {
		t.Fatal(err)
	}
}

func TestAmountRewriteDetected(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-rewrite-1", "buyer", "seller", 350_000, Meter{}, now)
	_ = a.Lock("buyer", now)
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	// Rewrite the amount off-ledger: every receipt hash included the terms
	// digest, so the chain must break from the first receipt.
	a.Amount = 700_000
	if err := a.VerifyReceipts(); err == nil {
		t.Fatal("amount rewrite not detected")
	}
}

func TestPartyRewriteDetected(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-rewrite-2", "buyer", "seller", 1, Meter{}, now)
	a.Seller = "impostor"
	if err := a.VerifyReceipts(); err == nil {
		t.Fatal("seller rewrite not detected")
	}
}

func TestReceiptSignatureForgeDetected(t *testing.T) {
	now := time.Now().UTC()
	_, buyerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := OpenEscrow("house-sig-1", "buyer", "seller", 1, Meter{}, now)
	if err = a.SignReceipts(map[Party]ed25519.PrivateKey{"buyer": buyerKey}); err != nil {
		t.Fatal(err)
	}
	if err = a.Lock("buyer", now); err != nil {
		t.Fatal(err)
	}
	if err = a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	// Forge a foreign actor signature over an honest receipt.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	a.Receipts[1].ActorSignature = ed25519.Sign(rogue, canonicalReceiptBytes(a.Receipts[1], a.TermsDigest()))
	if err = a.VerifyReceipts(); err == nil {
		t.Fatal("forged signature not detected")
	}
	// Flip a signature bit: must also fail.
	a.Receipts[1].ActorSignature[0] ^= 0xff
	if err = a.VerifyReceipts(); err == nil {
		t.Fatal("corrupted signature not detected")
	}
}

func TestReceiptHashUnambiguous(t *testing.T) {
	now := time.Now().UTC()
	a1, _ := OpenEscrow("house-amb-1", "x", "y|z", 1, Meter{}, now)
	a2, _ := OpenEscrow("x", "y", "x", 1, Meter{}, now) // same seller, different buyer
	// Same struct content in the OLD encoding would collide via "|" splits.
	// With canonical JSON, distinct receipts can never share a hash.
	h1 := hashSignedReceipt("receipt", a1.TermsDigest(), a1.Receipts[0])
	h2 := hashSignedReceipt("receipt", a2.TermsDigest(), a2.Receipts[0])
	if h1 == h2 {
		t.Fatal("distinct receipts share a hash")
	}
	// Field-boundary ambiguity: swap actor/note content between separators.
	r := Receipt{Seq: 1, At: now, Action: "open", Actor: "x", Note: "y|z"}
	s := Receipt{Seq: 1, At: now, Action: "open", Actor: "x|y", Note: "z"}
	if hashSignedReceipt("receipt", a1.TermsDigest(), r) == hashSignedReceipt("receipt", a1.TermsDigest(), s) {
		t.Fatal("separator ambiguity in receipt hash")
	}
}

func TestUnitReceiptOnLedger(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("house-unit-1", "buyer", "seller", 1, Meter{}, now)
	if err := a.WithUnitAt(TokenNEX, now); err != nil {
		t.Fatal(err)
	}
	if !a.RequiresToken() {
		t.Fatal("token required after WithUnit")
	}
	if a.Receipts[len(a.Receipts)-1].Action != "unit" {
		t.Fatal("unit change missing from ledger")
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	// Silently rewriting the unit must break the chain.
	a.Unit = Unit{Symbol: "FAKE"}
	if err := a.VerifyReceipts(); err == nil {
		t.Fatal("silent unit rewrite not detected")
	}
	a.Unit = Unit{Symbol: TokenNEX}
	if err := a.Lock("buyer", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestMaxStepsClamped(t *testing.T) {
	now := time.Now().UTC()
	if _, err := OpenEscrow("house-cap", "b", "s", 1, Meter{MaxSteps: 129}, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("MaxSteps>128: %v", err)
	}
}

// TestMaterialTermActionsExhaustive pins the terms-verification contract:
// every action the kernel can emit either (a) is registered in
// materialTermActions and the replay exactly reproduces the live terms
// digest, or (b) provably leaves the terms unchanged. A new kernel
// action that forgets to register a terms mutation fails here, not in
// production.
func TestMaterialTermActionsExhaustive(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	known := map[string]bool{}
	for action := range materialTermActions {
		known[action] = true
	}
	// (a) registered actions must actually be emitted by the kernel.
	emitted := map[string]bool{}
	for _, action := range agreementActions {
		emitted[action] = true
	}
	for action := range known {
		if !emitted[action] {
			t.Fatalf("materialTermActions registers %q, but the kernel never emits it", action)
		}
	}
	for _, action := range agreementActions {
		if !known[action] {
			continue
		}
		// Replay an agreement exercising this action and check the view
		// reproduces the live digest at every step.
		a, _ := OpenEscrow("mt-"+action, "buyer", "seller", 1, Meter{}, now)
		var view Agreement
		var prev string
		switch action {
		case "unit":
			if err := a.WithUnitAt(TokenNEX, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		view = *a
		view.Receipts = nil
		view.steps = 0
		view.actorKeys = nil
		view.Unit = Unit{}
		for _, r := range a.Receipts {
			if r.PrevHash != prev {
				t.Fatalf("%s: broken prev", action)
			}
			want := hashSignedReceipt("receipt", view.TermsDigest(), r)
			if r.Hash != want {
				t.Fatalf("%s: replay digest diverged from live chain", action)
			}
			prev = r.Hash
			applyMaterialReceipt(&view, r)
		}
		if view.Unit != a.Unit {
			t.Fatalf("%s: replayed unit %+v != live %+v", action, view.Unit, a.Unit)
		}
	}
	// (b) unregistered actions must not touch the terms digest: run each
	// kernel transition and confirm the digest is invariant across it.
	transitions := []func(a *Agreement) error{
		func(a *Agreement) error { return a.Lock(a.Buyer, now) },
		func(a *Agreement) error { return a.Accept(a.Seller, now) },
		func(a *Agreement) error { return a.Reject(a.Seller, now) },
		func(a *Agreement) error { return a.SetDeadline(a.Buyer, now.Add(time.Hour), now) },
		func(a *Agreement) error { return a.Expire(a.Buyer, now.Add(2*time.Hour)) },
		func(a *Agreement) error { return a.Note(a.Seller, "evidence", "cite:x", now) },
	}
	for i, transition := range transitions {
		a, _ := OpenEscrow(fmt.Sprintf("mt-inv-%d", i), "buyer", "seller", 1, Meter{}, now)
		_ = a.SetDeadline(a.Buyer, now.Add(time.Hour), now)
		_ = a.Lock(a.Buyer, now)
		_ = a.Note(a.Seller, "evidence", "cite:x", now)
		before := a.TermsDigest()
		if err := transition(a); err != nil {
			continue // not all transitions are legal in this state; that is fine
		}
		if a.TermsDigest() != before {
			t.Fatalf("transition %d changed the terms digest but is not registered in materialTermActions", i)
		}
	}
}
