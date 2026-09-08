package nexum

import (
	"errors"
	"testing"
	"time"
)

func TestRoomTwoAgentEscrow(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a, err := OpenEscrow("room-house", "buyer", "seller", 350_000, Meter{BudgetUSD: 42}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(Move{Actor: "buyer", Action: "lock"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(Move{Actor: "seller", Action: "accept"}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusAccepted || a.ReleasedTo != "seller" {
		t.Fatalf("status=%s to=%s", a.Status, a.ReleasedTo)
	}
	if err := a.Apply(Move{Actor: "buyer", Action: "takeback"}, now.Add(3*time.Minute)); !errors.Is(err, ErrTakeback) {
		t.Fatalf("takeback after accept: %v", err)
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestRoomTakebackAfterLock(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("room-lock", "buyer", "seller", 1, Meter{}, now)
	_ = a.Apply(Move{Actor: "buyer", Action: "lock"}, now)
	if err := a.Apply(Move{Actor: "buyer", Action: "takeback"}, now); !errors.Is(err, ErrTakeback) {
		t.Fatalf("takeback after lock: %v", err)
	}
	if a.Status != StatusLocked {
		t.Fatalf("status=%s want locked", a.Status)
	}
}
