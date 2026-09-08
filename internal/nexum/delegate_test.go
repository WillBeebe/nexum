package nexum

import (
	"errors"
	"testing"
	"time"
)

func TestDelegatePayOnProof(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	d, err := OpenDelegate("d1", "agent-c", "worker-7", 100,
		Task{Offer: "digest:arxiv-cs-lg", ProofKind: "citation"},
		Meter{BudgetUSD: 5, MaxSteps: 16}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Claim("worker-7", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := d.Cancel("agent-c", now.Add(2*time.Minute)); !errors.Is(err, ErrTakeback) {
		t.Fatalf("cancel after claim: %v", err)
	}
	if err := d.SubmitProof("worker-7", "drop:sha256:abc", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := d.AcceptProof("agent-c", now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if d.Status != StatusPaid || d.ReleasedTo != "worker-7" {
		t.Fatalf("status=%s to=%s", d.Status, d.ReleasedTo)
	}
	if err := d.AcceptProof("agent-c", now.Add(5*time.Minute)); !errors.Is(err, ErrTakeback) {
		t.Fatalf("second pay: %v", err)
	}
	if err := d.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestDelegateCancelBeforeClaim(t *testing.T) {
	now := time.Now().UTC()
	d, _ := OpenDelegate("d2", "agent-a", "worker-1", 1, Task{Offer: "rss"}, Meter{}, now)
	if err := d.Cancel("agent-a", now); err != nil {
		t.Fatal(err)
	}
	if err := d.Claim("worker-1", now); !errors.Is(err, ErrTakeback) {
		t.Fatalf("claim after cancel: %v", err)
	}
}

func TestDelegateRejectProof(t *testing.T) {
	now := time.Now().UTC()
	d, _ := OpenDelegate("d3", "agent-a", "worker-1", 1, Task{Offer: "rss"}, Meter{}, now)
	_ = d.Claim("worker-1", now)
	_ = d.SubmitProof("worker-1", "empty", now)
	if err := d.RejectProof("agent-a", now); err != nil {
		t.Fatal(err)
	}
	if d.Status != StatusRejected || d.ReleasedTo != "agent-a" {
		t.Fatalf("status=%s to=%s", d.Status, d.ReleasedTo)
	}
}

func TestDelegateWrongParty(t *testing.T) {
	now := time.Now().UTC()
	d, _ := OpenDelegate("d4", "agent-a", "worker-1", 1, Task{Offer: "rss"}, Meter{}, now)
	if err := d.Claim("agent-a", now); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("parent claim: %v", err)
	}
}
