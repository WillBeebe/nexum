package nexum

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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

func TestDelegateReceiptSignatureForgeDetected(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	d, err := OpenDelegate("d-sig", "agent-c", "worker-7", 100,
		Task{Offer: "digest:arxiv-cs-lg", ProofKind: "citation"}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, worker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SignReceipts(map[Party]ed25519.PrivateKey{"worker-7": worker}); err != nil {
		t.Fatal(err)
	}
	if err = d.Claim("worker-7", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = d.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	d.Receipts[0].ActorSignature = ed25519.Sign(rogue, canonicalReceiptBytes(d.Receipts[0], d.termsDigest()))
	if err = d.VerifyReceipts(); err == nil {
		t.Fatal("forged delegate signature not detected")
	}
}

func TestDelegateClaimedRejectIsNotProofRejection(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	d, err := OpenDelegate("claimed", "agent-a", "worker-1", 3, Task{Offer: "rss"}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Claim("worker-1", now); err != nil {
		t.Fatal(err)
	}
	if err = d.RejectProof("agent-a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	last := d.Receipts[len(d.Receipts)-1]
	if d.Status != StatusRejected || d.Proof != "" || d.ReleasedTo != "agent-a" || d.RejectStage != RejectStageClaimed || last.Action != "reject" {
		t.Fatalf("status=%s proof=%q stage=%s action=%s", d.Status, d.Proof, d.RejectStage, last.Action)
	}
	if last.Note == "proof refused, no reward" {
		t.Fatal("v2 rejection before proof uses the proof-refusal sentence")
	}
	stage, err := d.DerivedRejectStage()
	if err != nil || stage != RejectStageClaimed {
		t.Fatalf("stage %s %v", stage, err)
	}
	legacy, err := openDelegate(0, "legacy-claimed", "agent-a", "worker-1", 3, Task{Offer: "rss"}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = legacy.Claim("worker-1", now); err != nil || legacy.RejectProof("agent-a", now) != nil {
		t.Fatal(err)
	}
	old := legacy.Receipts[len(legacy.Receipts)-1]
	if old.Action != "reject-proof" || old.Note != "proof refused, no reward" || legacy.RejectStage != "" {
		t.Fatalf("legacy receipt rewritten: action=%s note=%q stage=%q", old.Action, old.Note, legacy.RejectStage)
	}
	stage, err = legacy.DerivedRejectStage()
	if err != nil || stage != RejectStageClaimed {
		t.Fatalf("legacy stage %s %v", stage, err)
	}
	got, err := legacy.ReceiptAssurance()
	if err != nil || got != AssuranceStateReplay {
		t.Fatalf("assurance %s %v", got, err)
	}
}

func TestDelegateReplayPaidRejectAndAtomicity(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	d, err := OpenDelegate("pay", "agent-a", "worker-1", 9, Task{Offer: "rss"}, Meter{BudgetUSD: 2, MaxSteps: 6}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Claim("worker-1", now); err != nil {
		t.Fatal(err)
	}
	if err = d.SubmitProof("worker-1", "drop:sha256:abc", now); err != nil {
		t.Fatal(err)
	}
	if err = d.RejectProof("agent-a", now); err != nil {
		t.Fatal(err)
	}
	if d.RejectStage != RejectStageProven || d.Receipts[len(d.Receipts)-1].Action != "reject-proof" {
		t.Fatalf("proven rejection stage=%s action=%s", d.RejectStage, d.Receipts[len(d.Receipts)-1].Action)
	}
	d.Proof = "other"
	if err = d.VerifyReceipts(); err == nil {
		t.Fatal("wrong proof accepted")
	}

	paid, err := OpenDelegate("paid", "agent-a", "worker-1", 9, Task{Offer: "rss"}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = paid.Claim("worker-1", now); err != nil || paid.SubmitProof("worker-1", "cite", now) != nil || paid.AcceptProof("agent-a", now) != nil {
		t.Fatal(err)
	}
	head := paid.Receipts[len(paid.Receipts)-1].Hash
	paid.Status = StatusOffered
	paid.ReleasedTo = ""
	if paid.Receipts[len(paid.Receipts)-1].Hash != head {
		t.Fatal("hash changed")
	}
	if err = paid.VerifyReceipts(); err == nil {
		t.Fatal("tampered paid snapshot accepted")
	}
	paid.Status = StatusPaid
	paid.ReleasedTo = "worker-1"
	paid.ClosedAt = nil
	if err = paid.VerifyReceipts(); err == nil {
		t.Fatal("nil close time accepted")
	}
	paid.ClosedAt = &now
	if err = paid.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	frozen := len(paid.Receipts)
	for _, call := range []func() error{
		func() error { return paid.Claim("worker-1", now) },
		func() error { return paid.SubmitProof("worker-1", "more", now) },
		func() error { return paid.AcceptProof("agent-a", now) },
		func() error { return paid.RejectProof("agent-a", now) },
		func() error { return paid.Cancel("agent-a", now) },
	} {
		if err = call(); err == nil {
			t.Fatal("terminal mutation accepted")
		}
	}
	if len(paid.Receipts) != frozen || paid.Status != StatusPaid || paid.Proof != "cite" {
		t.Fatal("terminal delegation changed")
	}

	fresh, err := OpenDelegate("atom", "agent-a", "worker-1", 9, Task{Offer: "rss"}, Meter{BudgetUSD: 1, MaxSteps: 4}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = fresh.Claim("worker-1", now); err != nil {
		t.Fatal(err)
	}
	fresh.Meter.CostUSD = 3
	steps := fresh.steps
	n := len(fresh.Receipts)
	if err = fresh.SubmitProof("worker-1", "cite", now); !errors.Is(err, ErrBudget) {
		t.Fatalf("budget: %v", err)
	}
	if fresh.steps != steps || len(fresh.Receipts) != n || fresh.Proof != "" || fresh.Status != StatusClaimed {
		t.Fatal("budget failure changed proof or head")
	}
	fresh.Meter.CostUSD = 0
	fresh.Meter.MaxSteps = len(fresh.Receipts)
	if err = fresh.SubmitProof("worker-1", "cite", now); !errors.Is(err, ErrDoS) {
		t.Fatalf("steps: %v", err)
	}
	if fresh.steps != steps || fresh.Proof != "" || fresh.Status != StatusClaimed {
		t.Fatal("step failure changed proof")
	}
	bad, err := OpenDelegate("bad", "agent-a", "worker-1", 9, Task{Offer: "rss"}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	bad.Status = StatusAccepted
	if err = bad.Claim("worker-1", now); !errors.Is(err, ErrBadState) {
		t.Fatalf("foreign status: %v", err)
	}
	if err = (&Delegate{Status: StatusPaid, Kind: KindDelegate}).VerifyReceipts(); err == nil {
		t.Fatal("empty history established a paid delegation")
	}
}

func TestDelegateV2RoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 4, 3, 4, 5, 6, time.UTC)
	d, err := OpenDelegate("round", "agent-a", "worker-1", 9, Task{Offer: "rss:feed"}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Claim("worker-1", now); err != nil || d.SubmitProof("worker-1", "drop:1", now) != nil || d.AcceptProof("agent-a", now) != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Delegate
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err = back.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	if back.Status != StatusPaid || back.Proof != "drop:1" || back.ReleasedTo != "worker-1" || back.ClosedAt == nil {
		t.Fatalf("%+v", back)
	}
	got, err := back.ReceiptAssurance()
	if err != nil || got != AssuranceStateReplay {
		t.Fatalf("assurance %s %v", got, err)
	}
}
