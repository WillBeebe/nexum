package nexum

import (
	"errors"
	"testing"
	"time"
)

func testCouncil(t *testing.T) *Council {
	t.Helper()
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	c, err := OpenCouncil("c1",
		[]Party{"agent-a", "agent-b", "agent-c"},
		[]Requirement{
			{ID: "safety", Holder: "agent-a"},
			{ID: "cost", Holder: "agent-b"},
			{ID: "ciphertext", Holder: "agent-c"},
		},
		"ship-nex-gpu-node",
		Meter{BudgetUSD: 42, MaxSteps: 32},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCouncilExecuteUnanimous(t *testing.T) {
	c := testCouncil(t)
	now := c.CreatedAt
	if err := c.Satisfy("agent-a", "safety", "poison-check:ok", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Satisfy("agent-b", "cost", "budget<=42", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Satisfy("agent-c", "ciphertext", "sealed-amount-verified", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusReady {
		t.Fatalf("status=%s want ready", c.Status)
	}
	for i, p := range []Party{"agent-a", "agent-b", "agent-c"} {
		if err := c.OptIn(p, now.Add(time.Duration(4+i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Execute("agent-c", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusExecuted {
		t.Fatalf("status=%s", c.Status)
	}
	if err := c.Refuse("agent-a", now.Add(11*time.Minute)); !errors.Is(err, ErrTakeback) {
		t.Fatalf("refuse after execute: %v", err)
	}
	if err := c.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestCouncilExecuteNeedsEveryOptIn(t *testing.T) {
	c := testCouncil(t)
	now := c.CreatedAt
	_ = c.Satisfy("agent-a", "safety", "ok", now)
	_ = c.Satisfy("agent-b", "cost", "ok", now)
	_ = c.Satisfy("agent-c", "ciphertext", "ok", now)
	_ = c.OptIn("agent-a", now)
	_ = c.OptIn("agent-b", now)
	if err := c.Execute("agent-a", now); !errors.Is(err, ErrNotUnanimous) {
		t.Fatalf("execute missing agent-c: %v", err)
	}
	if c.Status == StatusExecuted {
		t.Fatal("must not execute")
	}
}

func TestCouncilOptInBeforeSatisfy(t *testing.T) {
	c := testCouncil(t)
	if err := c.OptIn("agent-a", c.CreatedAt); !errors.Is(err, ErrNotSatisfied) {
		t.Fatalf("opt-in early: %v", err)
	}
}

func TestCouncilRefuseBeforeExecute(t *testing.T) {
	c := testCouncil(t)
	now := c.CreatedAt
	_ = c.Satisfy("agent-a", "safety", "ok", now)
	if err := c.Refuse("agent-b", now); err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusRefused {
		t.Fatalf("status=%s", c.Status)
	}
	if err := c.Execute("agent-a", now); !errors.Is(err, ErrTakeback) {
		t.Fatalf("execute after refuse: %v", err)
	}
}

func TestCouncilPartyCount(t *testing.T) {
	now := time.Now().UTC()
	_, err := OpenCouncil("x", []Party{"a", "b"}, nil, "d", Meter{}, now)
	if !errors.Is(err, ErrPartyCount) {
		t.Fatalf("n=2: %v", err)
	}
	eight := []Party{"a", "b", "c", "d", "e", "f", "g", "h"}
	_, err = OpenCouncil("x", eight, nil, "d", Meter{}, now)
	if !errors.Is(err, ErrPartyCount) {
		t.Fatalf("n=8: %v", err)
	}
}

func TestCouncilWrongHolder(t *testing.T) {
	c := testCouncil(t)
	if err := c.Satisfy("agent-b", "safety", "ok", c.CreatedAt); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("cross-satisfy: %v", err)
	}
}

func TestCouncilRewriteDetected(t *testing.T) {
	c := testCouncil(t)
	c.Receipts[0].Note = "rewritten"
	if err := c.VerifyReceipts(); err == nil {
		t.Fatal("want rewrite error")
	}
}
