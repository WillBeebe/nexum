package nexum

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/internal/settle"
)

func TestGeneralAgreementConstructor(t *testing.T) {
	now := time.Now()
	a, err := OpenAgreement("work", "work.bounty", "buyer", "seller", 10, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != "work.bounty" || a.Receipts[0].Note != "agreement opened" {
		t.Fatalf("%+v", a)
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAgreement("work", "", "buyer", "seller", 10, Meter{}, now); err == nil {
		t.Fatal("empty kind accepted")
	}
	escrow, err := OpenEscrow("house", "buyer", "seller", 10, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if escrow.Kind != KindHouseEscrow || escrow.Receipts[0].Note != "escrow opened" {
		t.Fatal("escrow compatibility lost")
	}
}

func TestSealedAcceptanceAndFailureAtomicity(t *testing.T) {
	for _, direct := range []bool{false, true} {
		t.Run(map[bool]string{false: "dispatch", true: "direct"}[direct], func(t *testing.T) {
			now := time.Now()
			a, err := OpenAgreement("work", "work", "buyer", "seller", 10, Meter{MaxSteps: 20}, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.StartSealed(1024); err != nil {
				t.Fatal(err)
			}
			if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 4}, now); err != nil {
				t.Fatal(err)
			}
			before := *a
			accept := func() error {
				if direct {
					return a.Accept("seller", now)
				}
				return a.Apply(Move{Actor: "seller", Action: "accept"}, now)
			}
			if err := accept(); !errors.Is(err, settle.ErrSumMismatch) {
				t.Fatalf("underfunded acceptance: %v", err)
			}
			if !reflect.DeepEqual(before, *a) {
				t.Fatal("failed acceptance changed state")
			}
			if err := a.AcceptWithEvidence("buyer", "seller", "proof", now); !errors.Is(err, settle.ErrSumMismatch) {
				t.Fatalf("underfunded settlement: %v", err)
			}
			if !reflect.DeepEqual(before, *a) {
				t.Fatal("failed settlement changed state")
			}

			// A rejected seal must not poison the randomness used by the next proof.
			a.Meter.BudgetUSD, a.Meter.CostUSD = 1, 2
			before = *a
			if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 6}, now); !errors.Is(err, ErrBudget) {
				t.Fatalf("budget: %v", err)
			}
			if !reflect.DeepEqual(before, *a) {
				t.Fatal("failed seal changed state")
			}
			a.Meter.CostUSD = 0
			if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 6}, now); err != nil {
				t.Fatal(err)
			}

			// One free step cannot commit a two-receipt settlement.
			a.Meter.MaxSteps = a.steps + 1
			before = *a
			if err := a.AcceptWithEvidence("buyer", "seller", "proof", now); !errors.Is(err, ErrDoS) {
				t.Fatalf("step limit: %v", err)
			}
			if !reflect.DeepEqual(before, *a) {
				t.Fatal("failed settlement consumed evidence or steps")
			}
			a.Meter.MaxSteps++
			if err := a.AcceptWithEvidence("buyer", "seller", "proof", now); err != nil {
				t.Fatal(err)
			}
			if a.Status != StatusAccepted {
				t.Fatal(a.Status)
			}
			if err := accept(); !errors.Is(err, ErrTakeback) {
				t.Fatalf("takeback: %v", err)
			}
			if err := a.VerifyReceipts(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
