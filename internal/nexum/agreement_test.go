package nexum

import (
	"errors"
	"testing"
	"time"
)

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
	a.WithUnit(TokenNEX)
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
