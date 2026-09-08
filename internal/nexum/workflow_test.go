package nexum

import (
	"errors"
	"testing"
	"time"
)

func internTree() map[string]Node {
	return map[string]Node{
		"root":        {ID: "root", Kind: "gate", Next: []string{"poison-fail", "claimed"}},
		"poison-fail": {ID: "poison-fail", Kind: "action", Require: []string{"poison_fail"}},
		"claimed":     {ID: "claimed", Kind: "gate", Require: []string{"claimed"}, Next: []string{"pay", "reject"}},
		"pay":         {ID: "pay", Kind: "action", Require: []string{"proof_ok"}},
		"reject":      {ID: "reject", Kind: "action"},
	}
}

func TestWorkflowDeterministicPay(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	w, err := OpenWorkflow("w1", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]bool{"claimed": true, "proof_ok": true}
	path, action, err := w.Walk(facts)
	if err != nil {
		t.Fatal(err)
	}
	if action != "pay" {
		t.Fatalf("action=%s path=%v", action, path)
	}
	if err := w.Execute("agent-c", facts, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if w.Status != StatusExecuted || w.Action != "pay" {
		t.Fatalf("status=%s action=%s", w.Status, w.Action)
	}
	if err := w.Execute("agent-c", facts, now); !errors.Is(err, ErrTakeback) {
		t.Fatalf("second execute: %v", err)
	}
	if err := w.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowPoisonTakesFirstMatch(t *testing.T) {
	w, _ := OpenWorkflow("w2", "agent-a", "root", internTree(), Meter{}, time.Now().UTC())
	_, action, err := w.Walk(map[string]bool{"poison_fail": true, "claimed": true, "proof_ok": true})
	if err != nil {
		t.Fatal(err)
	}
	if action != "poison-fail" {
		t.Fatalf("want poison-fail first, got %s", action)
	}
}

func TestWorkflowNoPath(t *testing.T) {
	w, _ := OpenWorkflow("w3", "agent-a", "root", internTree(), Meter{}, time.Now().UTC())
	if _, _, err := w.Walk(map[string]bool{}); !errors.Is(err, ErrNoPath) {
		t.Fatalf("empty facts: %v", err)
	}
}

func TestWorkflowSameFactsSamePath(t *testing.T) {
	w, _ := OpenWorkflow("w4", "agent-a", "root", internTree(), Meter{}, time.Now().UTC())
	facts := map[string]bool{"claimed": true}
	p1, a1, err := w.Walk(facts)
	if err != nil {
		t.Fatal(err)
	}
	p2, a2, err := w.Walk(facts)
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 || a1 != "reject" {
		t.Fatalf("a1=%s a2=%s", a1, a2)
	}
	if len(p1) != len(p2) {
		t.Fatalf("path len %d vs %d", len(p1), len(p2))
	}
}
