package nexum

import (
	"testing"
	"time"
)

func receiptStateAgreement(t *testing.T) *Agreement {
	t.Helper()
	now := time.Date(2026, 11, 6, 12, 0, 0, 123456789, time.UTC)
	a, err := OpenAgreement("state-replay", "work", "buyer", "seller", 7, Meter{MaxSteps: 32}, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func receiptStateAccepted(t *testing.T) *Agreement {
	t.Helper()
	a := receiptStateAgreement(t)
	if err := a.Lock(a.Buyer, a.CreatedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept(a.Seller, a.CreatedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestReceiptReplayRejectsOutcomeRewrites(t *testing.T) {
	for name, mutate := range map[string]func(*Agreement){
		"status":      func(a *Agreement) { a.Status = StatusRejected },
		"recipient":   func(a *Agreement) { a.ReleasedTo = a.Buyer },
		"missingLock": func(a *Agreement) { a.LockedAt = nil },
		"missingEnd":  func(a *Agreement) { a.ClosedAt = nil },
		"lockTime": func(a *Agreement) {
			changed := a.LockedAt.Add(time.Second)
			a.LockedAt = &changed
		},
		"closeTime": func(a *Agreement) {
			changed := a.ClosedAt.Add(time.Second)
			a.ClosedAt = &changed
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := receiptStateAccepted(t)
			if err := a.VerifyReceipts(); err != nil {
				t.Fatal(err)
			}
			mutate(a)
			if err := a.VerifyReceipts(); err == nil {
				t.Fatal("rewritten outcome verified")
			}
		})
	}
}

func TestReceiptReplayRejectsRehashedIllegalActions(t *testing.T) {
	for name, mutate := range map[string]func(*Agreement){
		"sellerLocks":      func(a *Agreement) { a.Receipts[1].Actor = a.Seller },
		"buyerAccepts":     func(a *Agreement) { a.Receipts[2].Actor = a.Buyer },
		"outsider":         func(a *Agreement) { a.Receipts[1].Actor = "outsider" },
		"acceptBeforeLock": func(a *Agreement) { a.Receipts[1].Action = "accept" },
		"unknown":          func(a *Agreement) { a.Receipts[1].Action = "authorize-everything" },
		"secondOpen":       func(a *Agreement) { a.Receipts[1].Action = "open" },
		"missingGenesis":   func(a *Agreement) { a.Receipts[0].Action = "lock" },
		"afterTerminal": func(a *Agreement) {
			a.Receipts = append(a.Receipts, Receipt{
				Seq: 4, At: a.CreatedAt.Add(3 * time.Second), Action: "evidence",
				Actor: a.Buyer, Note: "post-terminal mutation",
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := receiptStateAccepted(t)
			mutate(a)
			var prev string
			for i := range a.Receipts {
				r := &a.Receipts[i]
				r.PrevHash = prev
				r.Hash = hashReceipt(a, *r)
				prev = r.Hash
			}
			if err := a.VerifyReceipts(); err == nil {
				t.Fatal("illegal history verified after recomputing all hashes")
			}
		})
	}
}

func TestReceiptReplayPreservesSupportedTransitions(t *testing.T) {
	for _, action := range []string{"reject", "expireOpen", "expireLocked", "seal"} {
		t.Run(action, func(t *testing.T) {
			a := receiptStateAgreement(t)
			now := a.CreatedAt
			// Include a deadline with subsecond precision, which historical
			// receipts record only to the second.
			deadline := now.Add(10 * time.Second)
			if err := a.SetDeadline(a.Buyer, deadline, now); err != nil {
				t.Fatal(err)
			}
			if err := a.WithUnitAt("work-unit", now); err != nil {
				t.Fatal(err)
			}
			if err := a.WithUnitAt("", now); err != nil {
				t.Fatal(err)
			}
			if action == "seal" {
				if err := a.StartSealed(1024); err != nil {
					t.Fatal(err)
				}
				for i, partial := range []int64{3, 4} {
					if err := a.Apply(Move{Actor: a.Buyer, Action: "seal", Partial: partial}, now.Add(time.Duration(i+1)*time.Second)); err != nil {
						t.Fatal(err)
					}
				}
				if !a.LockedAt.Equal(now.Add(2 * time.Second)) {
					t.Fatal("sealing did not retain the latest lock time")
				}
				if err := a.Accept(a.Seller, now.Add(3*time.Second)); err != nil {
					t.Fatal(err)
				}
			} else {
				if action != "expireOpen" {
					if err := a.Lock(a.Buyer, now.Add(time.Second)); err != nil {
						t.Fatal(err)
					}
				}
				if action == "reject" {
					if err := a.Reject(a.Seller, now.Add(2*time.Second)); err != nil {
						t.Fatal(err)
					}
				} else if err := a.Expire(a.Buyer, deadline); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.VerifyReceipts(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
