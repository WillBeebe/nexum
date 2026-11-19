package nexum

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

func TestWorkflowReceiptSignatureForgeDetected(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	w, err := OpenWorkflow("w-sig", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.SignReceipts(map[Party]ed25519.PrivateKey{"agent-c": key}); err != nil {
		t.Fatal(err)
	}
	facts := map[string]bool{"claimed": true, "proof_ok": true}
	if _, _, err = w.Walk(facts); err != nil {
		t.Fatal(err)
	}
	// Only receipts appended after SignReceipts carry signatures.
	if err = w.Execute("agent-c", facts, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	last := len(w.Receipts) - 1
	if len(w.Receipts[last].ActorSignature) == 0 {
		t.Fatal("execute receipt not signed")
	}
	w.Receipts[last].ActorSignature[0] ^= 0xff
	if err = w.VerifyReceipts(); err == nil {
		t.Fatal("corrupted workflow signature not detected")
	}
	// Only the workflow actor may arm a key.
	other := Party("agent-x")
	if err = w.SignReceipts(map[Party]ed25519.PrivateKey{other: key}); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("foreign actor key: %v", err)
	}
}

func TestWorkflowCopiesNormalizedTree(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	nodes := internTree()
	w, err := OpenWorkflow("copy", "agent-c", "root", nodes, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	nodes["pay"].Require[0] = "mutated"
	nodes["root"].Next[0] = "mutated"
	if w.Nodes["pay"].Require[0] != "proof_ok" || w.Nodes["root"].Next[0] != "poison-fail" {
		t.Fatal("constructor kept the caller's slices")
	}
	if err = w.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	w.Nodes["root"].Next[0] = "zzz"
	if nodes["root"].Next[0] != "mutated" {
		t.Fatal("workflow slice writes through to the caller")
	}

	_, err = OpenWorkflow("disagree", "agent-c", "root", map[string]Node{
		"root":  {ID: "root", Kind: "gate", Next: []string{"label"}},
		"label": {ID: "act", Kind: "action"},
	}, Meter{}, now)
	if !errors.Is(err, ErrBadTree) {
		t.Fatalf("key/id: %v", err)
	}
	_, err = OpenWorkflow("dup", "agent-c", "root", map[string]Node{
		"root": {ID: "root", Kind: "gate", Next: []string{"a"}},
		"a":    {ID: "a", Kind: "action"},
		"a ":   {ID: "a", Kind: "action"},
	}, Meter{}, now)
	if !errors.Is(err, ErrBadTree) {
		t.Fatalf("duplicate id: %v", err)
	}
	_, err = OpenWorkflow("missing", "agent-c", "root", map[string]Node{
		"root": {ID: "root", Kind: "gate", Next: []string{"gone"}},
	}, Meter{}, now)
	if !errors.Is(err, ErrBadTree) {
		t.Fatalf("missing child: %v", err)
	}
	normalized, err := OpenWorkflow("norm", "agent-c", " root ", map[string]Node{
		" root ": {ID: "root", Kind: "gate", Next: []string{" act "}},
		" act ":  {ID: "act", Kind: "action"},
	}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Root != "root" || normalized.Nodes["act"].ID != "act" || normalized.Nodes["root"].Next[0] != "act" {
		t.Fatalf("normalized graph %+v", normalized.Nodes)
	}
	filled, err := OpenWorkflow("ids", "agent-c", "root", map[string]Node{
		"root": {Kind: "gate", Next: []string{"act"}},
		"act":  {Kind: "action"},
	}, Meter{}, now)
	if err != nil || filled.Nodes["root"].ID != "root" || filled.Nodes["act"].ID != "act" {
		t.Fatalf("blank ids: %v %+v", err, filled)
	}
}

func TestWorkflowReplayFactsAndAtomicity(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	facts := map[string]bool{"claimed": true, "proof_ok": true}
	w, err := OpenWorkflow("run", "agent-c", "root", internTree(), Meter{BudgetUSD: 1, MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	w.Meter.CostUSD = 9
	if err = w.Execute("agent-c", facts, now); err != nil {
		t.Fatalf("step-only meter rejected a budget: %v", err)
	}
	if w.FactsAssurance != FactsCommitted || w.FactsAssurance == FactsVerified {
		t.Fatalf("assurance %q", w.FactsAssurance)
	}
	got, err := w.ReceiptAssurance()
	if err != nil || got != AssuranceStateReplay {
		t.Fatalf("assurance %s %v", got, err)
	}
	head := w.Receipts[len(w.Receipts)-1].Hash
	w.Path = []string{"nope"}
	if w.Receipts[len(w.Receipts)-1].Hash != head {
		t.Fatal("hash changed")
	}
	if err = w.VerifyReceipts(); err == nil {
		t.Fatal("tampered path accepted")
	}
	w.Path = []string{"root", "claimed", "pay"}
	w.ClosedAt = nil
	if err = w.VerifyReceipts(); err == nil {
		t.Fatal("nil close time accepted")
	}

	limited, err := OpenWorkflow("limit", "agent-c", "root", internTree(), Meter{MaxSteps: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	steps := limited.steps
	if err = limited.Execute("agent-c", facts, now); !errors.Is(err, ErrDoS) {
		t.Fatalf("steps: %v", err)
	}
	if limited.steps != steps || limited.Path != nil || limited.Action != "" || limited.Status != StatusOpen || len(limited.Receipts) != 1 {
		t.Fatal("failed execute chose a path or advanced the head")
	}
	if err = limited.Execute("other", facts, now); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("actor: %v", err)
	}
	open, err := OpenWorkflow("nofact", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = open.Execute("agent-c", map[string]bool{}, now); !errors.Is(err, ErrNoPath) {
		t.Fatalf("empty walk: %v", err)
	}
	if len(open.Receipts) != 1 || open.Path != nil {
		t.Fatal("failed walk recorded a path")
	}

	committed, err := OpenWorkflow("commit-only", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	sum := commitString("facts", "not-supplied")
	if err = committed.recordExecution("agent-c", nil, []string{"root", "poison-fail"}, "poison-fail", FactsCommitmentOnly, sum, now); err != nil {
		t.Fatal(err)
	}
	if committed.FactsAssurance != FactsCommitmentOnly {
		t.Fatal(committed.FactsAssurance)
	}
	got, err = committed.ReceiptAssurance()
	if err != nil || got != AssuranceCommitmentOnly {
		t.Fatalf("commitment assurance %s %v", got, err)
	}
	deny, err := OpenWorkflow("deny", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = deny.recordExecution("agent-c", facts, []string{"root", "claimed", "pay"}, "pay", FactsVerified, sum, now); !errors.Is(err, ErrFactsUnverified) {
		t.Fatalf("verified claim: %v", err)
	}
	lie, err := OpenWorkflow("lie", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := encodeSiblingEvent(siblingEvent{
		V: FormatV2, Ledger: ledgerWorkflow, Action: "execute", Actor: "agent-c",
		FactsPresent: true, Facts: facts, FactsAssurance: FactsVerified,
		FactsCommitment: mustCommitFacts(t, facts), Path: []string{"root", "claimed", "pay"}, Result: "pay",
	})
	if err != nil {
		t.Fatal(err)
	}
	lie.Receipts = append(lie.Receipts, linkReceipt(lie.Receipts, "execute", "agent-c", ev, now, lie.termsDigest(), hashWorkflowReceipt))
	if err = lie.VerifyReceipts(); !errors.Is(err, ErrFactsUnverified) {
		t.Fatalf("verified payload: %v", err)
	}
}

func mustCommitFacts(t *testing.T, facts map[string]bool) string {
	t.Helper()
	sum, err := commitFacts(facts)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func TestWorkflowLegacyAndRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 4, 3, 4, 5, 6, time.UTC)
	facts := map[string]bool{"claimed": true, "proof_ok": true}
	legacy, err := openWorkflow(0, "old", "agent-c", "root", internTree(), Meter{BudgetUSD: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Meter.CostUSD = 4
	if err = legacy.Execute("agent-c", facts, now); err != nil {
		t.Fatal(err)
	}
	if legacy.Format != 0 || len(legacy.Receipts) != 2 || legacy.Receipts[1].Note == "" || legacy.Receipts[1].Note[0] == '{' {
		t.Fatalf("legacy note rewritten: %q", legacy.Receipts[1].Note)
	}
	got, err := legacy.ReceiptAssurance()
	if err != nil || got != AssurancePathReplay {
		t.Fatalf("assurance %s %v", got, err)
	}
	tampered := legacy.clone()
	tampered.Path = []string{"tampered"}
	tampered.Action = "tampered"
	if err = tampered.VerifyReceipts(); err == nil {
		t.Fatal("legacy execute accepted tampered path/action")
	}
	opened, err := openWorkflow(0, "opened", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	opened.Status = StatusExecuted
	if err = opened.VerifyReceipts(); err == nil {
		t.Fatal("format 0 open-only workflow accepted an executed snapshot")
	}

	w, err := OpenWorkflow("round", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Execute("agent-c", facts, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var back Workflow
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err = back.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	if back.Status != StatusExecuted || back.Action != "pay" || back.FactsAssurance != FactsCommitted || back.ClosedAt == nil {
		t.Fatalf("%+v", back)
	}
	frozen := append([]string(nil), back.Path...)
	if err = back.Execute("agent-c", facts, now); !errors.Is(err, ErrTakeback) {
		t.Fatalf("terminal: %v", err)
	}
	if back.Action != "pay" || len(back.Path) != len(frozen) {
		t.Fatal("terminal workflow changed")
	}
	if err = (&Workflow{Status: StatusExecuted, Kind: KindWorkflow}).VerifyReceipts(); err == nil {
		t.Fatal("empty history established an executed workflow")
	}
}

func TestWorkflowFormat0ExecuteReplayAndCollisions(t *testing.T) {
	now := time.Date(2026, 9, 4, 3, 4, 5, 6, time.UTC)

	// FormatV2 rejects internal whitespace or '[' / ']' in node IDs.
	for _, badID := range []string{"gate one", "act[1]", "act]", "[root"} {
		_, err := OpenWorkflow("bad-v2", "agent-c", "root", map[string]Node{
			"root": {ID: "root", Kind: "gate", Next: []string{badID}},
			badID:  {ID: badID, Kind: "action"},
		}, Meter{}, now)
		if !errors.Is(err, ErrBadTree) {
			t.Fatalf("FormatV2 accepted node id %q: %v", badID, err)
		}
	}

	// Format 0 preserves exact historical termsDigest and receipt hashes while
	// replaying exact Path, Action, Status, and ClosedAt.
	legacy, err := openWorkflow(0, "leg-wf", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	wantTermsBytes := wireDigest("workflow-terms", struct {
		ID        string          `json:"id"`
		Kind      string          `json:"kind"`
		Root      string          `json:"root"`
		Nodes     map[string]Node `json:"nodes"`
		Actor     Party           `json:"actor"`
		CreatedAt time.Time       `json:"created_at"`
	}{legacy.ID, legacy.Kind, legacy.Root, legacy.Nodes, legacy.Actor, legacy.CreatedAt})
	wantSum := sha256.Sum256(wantTermsBytes)
	wantTerms := hex.EncodeToString(wantSum[:])
	if got := legacy.termsDigest(); got != wantTerms {
		t.Fatalf("format 0 workflow termsDigest changed: got %s want %s", got, wantTerms)
	}
	if legacy.Receipts[0].Hash != hashSignedReceipt(hashWorkflowReceipt, wantTerms, legacy.Receipts[0]) {
		t.Fatal("format 0 workflow genesis receipt hash changed")
	}

	execAt := now.Add(2 * time.Minute)
	facts := map[string]bool{"claimed": true, "proof_ok": true}
	if err = legacy.Execute("agent-c", facts, execAt); err != nil {
		t.Fatal(err)
	}
	if legacy.Receipts[1].Note != "path=[root claimed pay] action=pay" {
		t.Fatalf("unexpected format 0 execute note: %q", legacy.Receipts[1].Note)
	}
	if legacy.termsDigest() != wantTerms {
		t.Fatal("format 0 workflow termsDigest drifted after execute")
	}
	for _, r := range legacy.Receipts {
		if r.Hash != hashSignedReceipt(hashWorkflowReceipt, wantTerms, r) {
			t.Fatalf("format 0 workflow receipt %d hash drifted", r.Seq)
		}
	}
	if got, err := legacy.ReceiptAssurance(); err != nil || got != AssurancePathReplay {
		t.Fatalf("assurance=%s err=%v, want %s", got, err, AssurancePathReplay)
	}

	// Tampering Path, Action, Status, ClosedAt, FactsAssurance, or duplicate execute all fail VerifyReceipts.
	for name, mutate := range map[string]func(*Workflow){
		"alt-valid-path": func(x *Workflow) {
			x.Path = []string{"root", "poison-fail"}
			x.Action = "poison-fail"
		},
		"path-only":   func(x *Workflow) { x.Path = []string{"root", "claimed"} },
		"action-only": func(x *Workflow) { x.Action = "reject" },
		"status":      func(x *Workflow) { x.Status = StatusOpen },
		"closed-nil":  func(x *Workflow) { x.ClosedAt = nil },
		"closed-shift": func(x *Workflow) {
			later := execAt.Add(time.Second)
			x.ClosedAt = &later
		},
		"facts-assurance": func(x *Workflow) { x.FactsAssurance = FactsCommitted },
		"duplicate-execute": func(x *Workflow) {
			x.Receipts = append(x.Receipts, linkReceipt(x.Receipts, "execute", "agent-c", x.Receipts[1].Note, execAt.Add(time.Minute), x.termsDigest(), hashWorkflowReceipt))
		},
	} {
		bad := legacy.clone()
		mutate(bad)
		if err = bad.VerifyReceipts(); err == nil {
			t.Fatalf("format 0 workflow accepted tampered %s", name)
		}
	}

	// Forged Format 0 execute note that matches 0 legal walks returns ErrInvalid.
	forged, err := openWorkflow(0, "forged-wf", "agent-c", "root", internTree(), Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	forged.Receipts = append(forged.Receipts, linkReceipt(forged.Receipts, "execute", "agent-c", "path=[root bogus] action=bogus", execAt, forged.termsDigest(), hashWorkflowReceipt))
	forged.Status = StatusExecuted
	forged.ClosedAt = &execAt
	forged.Path = []string{"root", "poison-fail"}
	forged.Action = "poison-fail"
	if err = forged.VerifyReceipts(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged execute note: got %v, want ErrInvalid", err)
	}

	// Format 0 with whitespace in node IDs that still uniquely walks achieves AssurancePathReplay.
	spacedUnique, err := openWorkflow(0, "spaced-unique", "agent-c", "root", map[string]Node{
		"root":     {ID: "root", Kind: "gate", Next: []string{"gate one"}},
		"gate one": {ID: "gate one", Kind: "gate", Require: []string{"ok"}, Next: []string{"leaf act"}},
		"leaf act": {ID: "leaf act", Kind: "action"},
	}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = spacedUnique.Execute("agent-c", map[string]bool{"ok": true}, execAt); err != nil {
		t.Fatal(err)
	}
	if got, err := spacedUnique.ReceiptAssurance(); err != nil || got != AssurancePathReplay {
		t.Fatalf("spaced unique assurance=%s err=%v, want %s", got, err, AssurancePathReplay)
	}

	// Format 0 with genuine whitespace-colliding walks ("root -> a -> b -> done" vs "root -> a b -> done")
	// reports AssuranceLegacyChain while verifying candidate membership, Status, and ClosedAt.
	colliding, err := openWorkflow(0, "spaced-coll", "agent-c", "root", map[string]Node{
		"root":  {ID: "root", Kind: "gate", Next: []string{"a", "a b", "other"}},
		"a":     {ID: "a", Kind: "gate", Require: []string{"split"}, Next: []string{"b"}},
		"b":     {ID: "b", Kind: "gate", Next: []string{"done"}},
		"a b":   {ID: "a b", Kind: "gate", Require: []string{"joined"}, Next: []string{"done"}},
		"done":  {ID: "done", Kind: "action"},
		"other": {ID: "other", Kind: "action", Require: []string{"other"}},
	}, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = colliding.Execute("agent-c", map[string]bool{"split": true}, execAt); err != nil {
		t.Fatal(err)
	}
	if got, err := colliding.ReceiptAssurance(); err != nil || got != AssuranceLegacyChain {
		t.Fatalf("colliding workflow assurance=%s err=%v, want %s", got, err, AssuranceLegacyChain)
	}
	altWalk := colliding.clone()
	altWalk.Path = []string{"root", "a b", "done"}
	if got, err := altWalk.ReceiptAssurance(); err != nil || got != AssuranceLegacyChain {
		t.Fatalf("alternate colliding walk assurance=%s err=%v", got, err)
	}
	for name, mutate := range map[string]func(*Workflow){
		"non-candidate-path": func(x *Workflow) {
			x.Path = []string{"root", "other"}
			x.Action = "other"
		},
		"status": func(x *Workflow) { x.Status = StatusOpen },
		"closed": func(x *Workflow) { x.ClosedAt = nil },
	} {
		bad := colliding.clone()
		mutate(bad)
		if err = bad.VerifyReceipts(); err == nil {
			t.Fatalf("colliding workflow accepted tampered %s", name)
		}
	}

	// Dense whitespace-colliding diamond graph stays bounded by the 4096 walk-visit cap.
	denseNodes := map[string]Node{
		"leaf": {ID: "leaf", Kind: "action"},
	}
	prev := "leaf"
	for layer := 14; layer >= 0; layer-- {
		step := fmt.Sprintf("s%d", layer)
		tail := fmt.Sprintf("u%d", layer)
		joined := fmt.Sprintf("%s %s", step, tail)
		gate := fmt.Sprintf("g%d", layer)
		denseNodes[step] = Node{ID: step, Kind: "gate", Require: []string{"left"}, Next: []string{tail}}
		denseNodes[tail] = Node{ID: tail, Kind: "gate", Next: []string{prev}}
		denseNodes[joined] = Node{ID: joined, Kind: "gate", Next: []string{prev}}
		denseNodes[gate] = Node{ID: gate, Kind: "gate", Next: []string{joined, step}}
		prev = gate
	}
	dense, err := openWorkflow(0, "dense", "agent-c", prev, denseNodes, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = dense.Execute("agent-c", map[string]bool{}, execAt); err != nil {
		t.Fatal(err)
	}
	if got, err := dense.ReceiptAssurance(); err != nil || got != AssuranceLegacyChain {
		t.Fatalf("dense assurance=%s err=%v, want %s", got, err, AssuranceLegacyChain)
	}
	denseBad := dense.clone()
	denseBad.Status = StatusOpen
	if err = denseBad.VerifyReceipts(); err == nil {
		t.Fatal("dense workflow accepted tampered status")
	}
	// A forged note on a capped dense graph that matches 0 leaves must still be rejected.
	denseForged, err := openWorkflow(0, "dense-forged", "agent-c", prev, denseNodes, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	badNote := dense.Receipts[1].Note + "-forged"
	denseForged.Receipts = append(denseForged.Receipts, linkReceipt(denseForged.Receipts, "execute", "agent-c", badNote, execAt, denseForged.termsDigest(), hashWorkflowReceipt))
	denseForged.Status = StatusExecuted
	denseForged.ClosedAt = &execAt
	denseForged.Path = append([]string(nil), dense.Path...)
	denseForged.Action = dense.Action
	if err = denseForged.VerifyReceipts(); err == nil {
		t.Fatal("dense workflow accepted forged capped note")
	}
}
