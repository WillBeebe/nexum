package nexum

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func TestCouncilReceiptSignatureForgeDetected(t *testing.T) {
	c := testCouncil(t)
	now := c.CreatedAt
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.SignReceipts(map[Party]ed25519.PrivateKey{"agent-a": key}); err != nil {
		t.Fatal(err)
	}
	if err = c.Satisfy("agent-a", "safety", "poison-check:ok", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = c.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	c.Receipts[0].ActorSignature = ed25519.Sign(rogue, canonicalReceiptBytes(c.Receipts[0], c.termsDigest()))
	if err = c.VerifyReceipts(); err == nil {
		t.Fatal("forged council signature not detected")
	}
	// Unknown parties cannot arm keys.
	if err = c.SignReceipts(map[Party]ed25519.PrivateKey{"outsider": key}); !errors.Is(err, ErrWrongParty) {
		t.Fatalf("outsider key: %v", err)
	}
}

func linkReceipt(prev []Receipt, action string, actor Party, note string, at time.Time, terms, kind string) Receipt {
	prevHash := ""
	if len(prev) > 0 {
		prevHash = prev[len(prev)-1].Hash
	}
	r := Receipt{Seq: len(prev) + 1, At: at, Action: action, Actor: actor, Note: note, PrevHash: prevHash}
	r.Hash = hashSignedReceipt(kind, terms, r)
	return r
}

func TestCouncilPhaseTablePreservesConsent(t *testing.T) {
	if !phaseAllows(councilPhaseTable, FormatV2, "refuse", StatusReady) || !phaseAllows(councilPhaseTable, 0, "refuse", StatusOpen) {
		t.Fatal("refusal after opt-in must stay legal")
	}
	if !phaseAllows(delegatePhaseTable, FormatV2, "reject", StatusClaimed) || !phaseAllows(delegatePhaseTable, FormatV2, "reject-proof", StatusProven) {
		t.Fatal("claimed and proven rejection must stay legal")
	}
	if phaseAllows(delegatePhaseTable, FormatV2, "reject-proof", StatusClaimed) {
		t.Fatal("v2 must not call a pre-proof rejection a proof rejection")
	}
	if !phaseAllows(delegatePhaseTable, 0, "reject-proof", StatusClaimed) {
		t.Fatal("format 0 keeps the historical reject-proof action")
	}
}

func TestCouncilAppendFailureIsAtomic(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	c, err := OpenCouncil("budget", []Party{"a", "b", "c"}, []Requirement{{ID: "s", Holder: "a"}}, "decide", Meter{BudgetUSD: 1, MaxSteps: 4}, now)
	if err != nil {
		t.Fatal(err)
	}
	c.Meter.CostUSD = 2
	before := councilBytes(t, c)
	steps := c.steps
	if err = c.Satisfy("a", "s", "cite", now); !errors.Is(err, ErrBudget) {
		t.Fatalf("budget: %v", err)
	}
	if c.steps != steps || councilBytes(t, c) != before || c.Reqs[0].Satisfied || c.Reqs[0].Citation != "" {
		t.Fatal("budget failure changed requirements, steps or head")
	}
	c.Meter.CostUSD = 0
	c.Meter.MaxSteps = len(c.Receipts)
	before = councilBytes(t, c)
	if err = c.Satisfy("a", "s", "cite", now); !errors.Is(err, ErrDoS) {
		t.Fatalf("steps: %v", err)
	}
	if c.steps != steps || councilBytes(t, c) != before || c.Reqs[0].Satisfied || len(c.OptedIn) != 0 {
		t.Fatal("step failure consumed a requirement or advanced the head")
	}
}

func councilBytes(t *testing.T, c *Council) string {
	t.Helper()
	head := ""
	if n := len(c.Receipts); n > 0 {
		head = c.Receipts[n-1].Hash
	}
	b, err := json.Marshal(struct {
		Status Status
		Reqs   []Requirement
		Opt    map[Party]bool
		Closed *time.Time
		N      int
		Head   string
		Dec    string
	}{c.Status, c.Reqs, c.OptedIn, c.ClosedAt, len(c.Receipts), head, c.Decision})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCouncilZeroRequirements(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	c, err := OpenCouncil("z", []Party{"b", "a", "c"}, nil, "ship", Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatV2 || c.Status != StatusReady {
		t.Fatalf("format=%d status=%s", c.Format, c.Status)
	}
	if err = c.Execute("a", now); !errors.Is(err, ErrNotUnanimous) {
		t.Fatalf("execute without consent: %v", err)
	}
	if c.Status != StatusReady || len(c.Receipts) != 1 {
		t.Fatal("failed execute changed the council")
	}
	if err = c.OptIn("a", now); err != nil {
		t.Fatal(err)
	}
	if err = c.Refuse("b", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if !c.OptedIn["a"] || c.Status != StatusRefused || c.ClosedAt == nil {
		t.Fatalf("opt-in then refuse: status=%s opted=%v closed=%v", c.Status, c.OptedIn, c.ClosedAt)
	}
	if err = c.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	legacy, err := openCouncil(0, "legacy-zero", []Party{"a", "b", "c"}, nil, "ship", Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Status != StatusOpen || legacy.Receipts[0].Note != "council opened" || legacy.Format != 0 {
		t.Fatalf("legacy genesis rewritten: status=%s note=%q", legacy.Status, legacy.Receipts[0].Note)
	}
	if err = legacy.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	legacy.Status = StatusReady
	if err = legacy.VerifyReceipts(); err == nil {
		t.Fatal("legacy zero-requirement council became ready without a transition")
	}
}

func TestCouncilDecisionBinding(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	c, err := OpenCouncil("dec", []Party{"a", "b", "c"}, nil, "ship", Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	c.Decision = "other"
	if err = c.VerifyReceipts(); err == nil {
		t.Fatal("format v2 allowed an uncommitted decision change")
	}
	legacy, err := openCouncil(0, "dec0", []Party{"a", "b", "c"}, nil, "ship", Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []Party{"a", "b", "c"} {
		if err = legacy.OptIn(p, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = legacy.Execute("a", now); err != nil {
		t.Fatal(err)
	}
	if legacy.Receipts[len(legacy.Receipts)-1].Note != "ship" {
		t.Fatalf("legacy execute note %q", legacy.Receipts[len(legacy.Receipts)-1].Note)
	}
	legacy.Decision = "other"
	if err = legacy.VerifyReceipts(); err == nil {
		t.Fatal("executed format 0 decision note was ignored")
	}
	openOnly, err := openCouncil(0, "dec-open", []Party{"a", "b", "c"}, nil, "ship", Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	openOnly.Decision = "other"
	if err = openOnly.VerifyReceipts(); err != nil {
		t.Fatal("format 0 must not bind decision before an execute note")
	}
}

func TestCouncilReplayAndLegacyClassification(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	c := testCouncil(t)
	if c.Format != FormatV2 {
		t.Fatal(c.Format)
	}
	for i, step := range []struct {
		party Party
		req   string
	}{{"agent-a", "safety"}, {"agent-b", "cost"}, {"agent-c", "ciphertext"}} {
		if err := c.Satisfy(step.party, step.req, "a:b:c", now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if err := c.OptIn(step.party, now.Add(time.Duration(i+3)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Execute("agent-a", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	assurance, err := c.ReceiptAssurance()
	if err != nil || assurance != AssuranceStateReplay {
		t.Fatalf("assurance %s %v", assurance, err)
	}
	head := c.Receipts[len(c.Receipts)-1].Hash
	c.Status = StatusOpen
	c.ClosedAt = nil
	c.Reqs[0].Satisfied = false
	if c.Receipts[len(c.Receipts)-1].Hash != head {
		t.Fatal("snapshot edit changed a receipt hash")
	}
	if err = c.VerifyReceipts(); err == nil {
		t.Fatal("tampered terminal snapshot accepted")
	}
	c = testCouncil(t)
	if err = c.Satisfy("agent-a", "safety", "ok", now); err != nil {
		t.Fatal(err)
	}
	c.Reqs[0].Citation = "tampered"
	if err = c.VerifyReceipts(); err == nil {
		t.Fatal("wrong citation accepted")
	}
	c = testCouncil(t)
	_ = c.Satisfy("agent-a", "safety", "ok", now)
	_ = c.Satisfy("agent-b", "cost", "ok", now)
	_ = c.Satisfy("agent-c", "ciphertext", "ok", now)
	for _, p := range []Party{"agent-a", "agent-b", "agent-c"} {
		if err = c.OptIn(p, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = c.Execute("agent-b", now); err != nil {
		t.Fatal(err)
	}
	c.ClosedAt = nil
	if err = c.VerifyReceipts(); err == nil {
		t.Fatal("nil close time accepted")
	}

	legacy, err := openCouncil(0, "leg", []Party{"agent-a", "agent-b", "agent-c"}, []Requirement{{ID: "safety", Holder: "agent-a"}, {ID: "cost", Holder: "agent-b"}, {ID: "ciphertext", Holder: "agent-c"}}, "ship", Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = legacy.Satisfy("agent-a", "safety", "https://a:b:c", now); err != nil {
		t.Fatal(err)
	}
	if legacy.Receipts[1].Note != "safety:https://a:b:c" {
		t.Fatalf("legacy note rewritten: %q", legacy.Receipts[1].Note)
	}
	assurance, err = legacy.ReceiptAssurance()
	if err != nil || assurance != AssuranceStateReplay {
		t.Fatalf("legacy assurance %s %v", assurance, err)
	}
	tamperedStatus := legacy.clone()
	tamperedStatus.Status = StatusExecuted
	if err = tamperedStatus.VerifyReceipts(); err == nil {
		t.Fatal("format 0 satisfy council accepted forged executed status")
	}
	tamperedReq := legacy.clone()
	tamperedReq.Reqs[0].Satisfied = false
	tamperedReq.Reqs[0].Citation = ""
	if err = tamperedReq.VerifyReceipts(); err == nil {
		t.Fatal("format 0 satisfy council accepted cleared requirement")
	}
	bare, err := openCouncil(0, "bare", []Party{"agent-a", "agent-b", "agent-c"}, []Requirement{{ID: "safety", Holder: "agent-a"}}, "ship", Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	bare.Reqs[0].Satisfied = true
	if err = bare.VerifyReceipts(); err == nil {
		t.Fatal("format 0 without satisfy notes still has a requirement snapshot")
	}
}

func TestCouncilFormat0SatisfyStateReplayAndPrefixCollision(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)

	// FormatV2 rejects ':' or untrimmed whitespace in Requirement.ID.
	for _, badID := range []string{"req:1", " req", "req ", "\treq"} {
		if _, err := OpenCouncil("bad-v2", []Party{"a", "b", "c"}, []Requirement{{ID: badID, Holder: "a"}}, "ship", Meter{}, now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("FormatV2 accepted requirement id %q: %v", badID, err)
		}
	}

	// Format 0 with multi-colon citations achieves full AssuranceStateReplay
	// and preserves exact Format 0 termsDigest and receipt hashes.
	c, err := openCouncil(0, "leg-full",
		[]Party{"agent-a", "agent-b", "agent-c"},
		[]Requirement{
			{ID: "safety", Holder: "agent-a"},
			{ID: "cost", Holder: "agent-b"},
			{ID: "ciphertext", Holder: "agent-c"},
		},
		"ship-v1",
		Meter{BudgetUSD: 42, MaxSteps: 32},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantTermsBytes := wireDigest("council-terms", struct {
		ID        string    `json:"id"`
		Kind      string    `json:"kind"`
		Parties   []Party   `json:"parties"`
		Reqs      []reqTerm `json:"requirements"`
		CreatedAt time.Time `json:"created_at"`
	}{c.ID, c.Kind, c.Parties, c.reqTerms(), c.CreatedAt})
	wantSum := sha256.Sum256(wantTermsBytes)
	wantTerms := hex.EncodeToString(wantSum[:])
	if got := c.termsDigest(); got != wantTerms {
		t.Fatalf("format 0 termsDigest changed: got %s want %s", got, wantTerms)
	}
	if c.Receipts[0].Hash != hashSignedReceipt(hashCouncilReceipt, wantTerms, c.Receipts[0]) {
		t.Fatal("format 0 genesis receipt hash changed")
	}

	if err = c.Satisfy("agent-a", "safety", "https://a:b:c", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = c.Satisfy("agent-b", "cost", "https://host:8443/doc:v1", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = c.Satisfy("agent-c", "ciphertext", "urn:nex:sealed:ok", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for i, p := range []Party{"agent-a", "agent-b", "agent-c"} {
		if err = c.OptIn(p, now.Add(time.Duration(4+i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	execAt := now.Add(10 * time.Minute)
	if err = c.Execute("agent-a", execAt); err != nil {
		t.Fatal(err)
	}
	if c.termsDigest() != wantTerms {
		t.Fatal("format 0 termsDigest drifted after execution")
	}
	for _, r := range c.Receipts {
		if r.Hash != hashSignedReceipt(hashCouncilReceipt, wantTerms, r) {
			t.Fatalf("format 0 receipt %d hash drifted", r.Seq)
		}
	}
	assurance, err := c.ReceiptAssurance()
	if err != nil || assurance != AssuranceStateReplay {
		t.Fatalf("assurance=%s err=%v, want %s", assurance, err, AssuranceStateReplay)
	}

	// Tampering Citation, Status, OptedIn, Decision, or ClosedAt all fail VerifyReceipts.
	for name, mutate := range map[string]func(*Council){
		"citation": func(x *Council) { x.Reqs[0].Citation = "https://a:b:tampered" },
		"status":   func(x *Council) { x.Status = StatusReady },
		"opted-in": func(x *Council) { delete(x.OptedIn, "agent-b") },
		"decision": func(x *Council) { x.Decision = "tampered-decision" },
		"closed-nil": func(x *Council) {
			x.ClosedAt = nil
		},
		"closed-shift": func(x *Council) {
			later := execAt.Add(time.Second)
			x.ClosedAt = &later
		},
	} {
		bad := c.clone()
		mutate(bad)
		if err = bad.VerifyReceipts(); err == nil {
			t.Fatalf("format 0 council accepted tampered %s", name)
		}
	}

	// Forged Format 0 satisfy receipts (wrong holder, unknown req, empty citation, duplicate satisfy) fail with ErrBadState.
	for name, build := range map[string]func() *Council{
		"wrong-holder": func() *Council {
			x, _ := openCouncil(0, "wh", []Party{"agent-a", "agent-b", "agent-c"}, []Requirement{{ID: "safety", Holder: "agent-a"}}, "ship", Meter{}, now)
			x.Receipts = append(x.Receipts, linkReceipt(x.Receipts, "satisfy", "agent-b", "safety:ok", now, x.termsDigest(), hashCouncilReceipt))
			return x
		},
		"unknown-req": func() *Council {
			x, _ := openCouncil(0, "uk", []Party{"agent-a", "agent-b", "agent-c"}, []Requirement{{ID: "safety", Holder: "agent-a"}}, "ship", Meter{}, now)
			x.Receipts = append(x.Receipts, linkReceipt(x.Receipts, "satisfy", "agent-a", "other:ok", now, x.termsDigest(), hashCouncilReceipt))
			return x
		},
		"empty-citation": func() *Council {
			x, _ := openCouncil(0, "ec", []Party{"agent-a", "agent-b", "agent-c"}, []Requirement{{ID: "safety", Holder: "agent-a"}}, "ship", Meter{}, now)
			x.Receipts = append(x.Receipts, linkReceipt(x.Receipts, "satisfy", "agent-a", "safety:", now, x.termsDigest(), hashCouncilReceipt))
			return x
		},
		"duplicate-satisfy": func() *Council {
			x, _ := openCouncil(0, "ds", []Party{"agent-a", "agent-b", "agent-c"}, []Requirement{{ID: "safety", Holder: "agent-a"}, {ID: "cost", Holder: "agent-b"}}, "ship", Meter{}, now)
			_ = x.Satisfy("agent-a", "safety", "ok", now)
			x.Receipts = append(x.Receipts, linkReceipt(x.Receipts, "satisfy", "agent-a", "safety:again", now, x.termsDigest(), hashCouncilReceipt))
			return x
		},
	} {
		if err = build().VerifyReceipts(); !errors.Is(err, ErrBadState) {
			t.Fatalf("%s: got %v, want ErrBadState", name, err)
		}
	}

	// Different holders with prefix-related IDs ("r" on agent-a, "r:1" on agent-b) are NOT ambiguous.
	diffHolder, err := openCouncil(0, "diff-holder",
		[]Party{"agent-a", "agent-b", "agent-c"},
		[]Requirement{{ID: "r", Holder: "agent-a"}, {ID: "r:1", Holder: "agent-b"}},
		"ship", Meter{}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = diffHolder.Satisfy("agent-a", "r", "1:foo", now); err != nil {
		t.Fatal(err)
	}
	if got, err := diffHolder.ReceiptAssurance(); err != nil || got != AssuranceStateReplay {
		t.Fatalf("different-holder prefix assurance=%s err=%v, want %s", got, err, AssuranceStateReplay)
	}

	// Genuine multi-prefix collision on the SAME holder ("r" and "r:1"):
	// 1. Partial execution with Note="r:1:foo" reports AssuranceLegacyChain,
	//    allows only the two valid interpretations, and still rejects tampered
	//    Status / OptedIn / ClosedAt / forged Citation.
	coll, err := openCouncil(0, "coll",
		[]Party{"agent-a", "agent-b", "agent-c"},
		[]Requirement{
			{ID: "r", Holder: "agent-a"},
			{ID: "r:1", Holder: "agent-a"},
			{ID: "cost", Holder: "agent-b"},
		},
		"ship-coll", Meter{}, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = coll.Satisfy("agent-a", "r:1", "foo", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got, err := coll.ReceiptAssurance(); err != nil || got != AssuranceLegacyChain {
		t.Fatalf("collision assurance=%s err=%v, want %s", got, err, AssuranceLegacyChain)
	}
	alt := coll.clone()
	alt.Reqs[0] = Requirement{ID: "r", Holder: "agent-a", Satisfied: true, Citation: "1:foo"}
	alt.Reqs[1] = Requirement{ID: "r:1", Holder: "agent-a", Satisfied: false}
	if got, err := alt.ReceiptAssurance(); err != nil || got != AssuranceLegacyChain {
		t.Fatalf("alternate collision assignment assurance=%s err=%v", got, err)
	}
	for name, mutate := range map[string]func(*Council){
		"status":   func(x *Council) { x.Status = StatusExecuted },
		"opted-in": func(x *Council) { x.OptedIn["agent-a"] = true },
		"closed":   func(x *Council) { x.ClosedAt = &now },
		"citation": func(x *Council) { x.Reqs[1].Citation = "bar" },
		"both-sat": func(x *Council) {
			x.Reqs[0].Satisfied = true
			x.Reqs[0].Citation = "1:foo"
		},
	} {
		bad := coll.clone()
		mutate(bad)
		if err = bad.VerifyReceipts(); err == nil {
			t.Fatalf("ambiguous partial council accepted tampered %s", name)
		}
	}

	// 2. Full execution with two colliding notes ("r:1:foo" and "r:1:bar")
	//    still reports AssuranceLegacyChain AND rejects tampered Status,
	//    OptedIn, Decision, and ClosedAt!
	if err = coll.Satisfy("agent-a", "r", "1:bar", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = coll.Satisfy("agent-b", "cost", "ok", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	for i, p := range []Party{"agent-a", "agent-b", "agent-c"} {
		if err = coll.OptIn(p, now.Add(time.Duration(4+i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	collClose := now.Add(10 * time.Minute)
	if err = coll.Execute("agent-c", collClose); err != nil {
		t.Fatal(err)
	}
	if got, err := coll.ReceiptAssurance(); err != nil || got != AssuranceLegacyChain {
		t.Fatalf("executed collision assurance=%s err=%v, want %s", got, err, AssuranceLegacyChain)
	}
	for name, mutate := range map[string]func(*Council){
		"status":   func(x *Council) { x.Status = StatusReady },
		"opted-in": func(x *Council) { delete(x.OptedIn, "agent-c") },
		"decision": func(x *Council) { x.Decision = "forged-decision" },
		"closed":   func(x *Council) { x.ClosedAt = nil },
		"citation": func(x *Council) { x.Reqs[0].Citation = "forged" },
	} {
		bad := coll.clone()
		mutate(bad)
		if err = bad.VerifyReceipts(); err == nil {
			t.Fatalf("executed ambiguous council accepted tampered %s", name)
		}
	}
}

func TestCouncilIllegalActorsActionsAndTerminal(t *testing.T) {
	now := time.Date(2026, 9, 4, 2, 0, 0, 0, time.UTC)
	c := testCouncil(t)
	n := len(c.Receipts)
	if err := c.Satisfy("outsider", "safety", "x", now); !errors.Is(err, ErrUnknownParty) {
		t.Fatalf("outsider: %v", err)
	}
	c.Status = StatusAccepted
	if err := c.Satisfy("agent-a", "safety", "x", now); !errors.Is(err, ErrBadState) {
		t.Fatalf("foreign status: %v", err)
	}
	if len(c.Receipts) != n {
		t.Fatal("illegal transition appended")
	}
	c = testCouncil(t)
	note, err := encodeSiblingEvent(siblingEvent{V: FormatV2, Ledger: ledgerCouncil, Action: "lock", Actor: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	c.Receipts = append(c.Receipts, linkReceipt(c.Receipts, "lock", "agent-a", note, now, c.termsDigest(), hashCouncilReceipt))
	if err = c.VerifyReceipts(); !errors.Is(err, ErrBadState) {
		t.Fatalf("illegal action: %v", err)
	}
	c = testCouncil(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := encodeSiblingEvent(siblingEvent{
		V: FormatV2, Ledger: ledgerCouncil, Action: "satisfy", Actor: "outsider",
		ReqID: "safety", Citation: "x", CitationCommitment: commitString("citation", "x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := linkReceipt(c.Receipts, "satisfy", "outsider", ev, now, c.termsDigest(), hashCouncilReceipt)
	signReceipt(&r, priv, c.termsDigest())
	r.Hash = hashSignedReceipt(hashCouncilReceipt, c.termsDigest(), r)
	if !ed25519.Verify(r.ActorKey, canonicalReceiptBytes(r, c.termsDigest()), r.ActorSignature) {
		t.Fatal("fixture signature is not valid")
	}
	c.Receipts = append(c.Receipts, r)
	if err = c.VerifyReceipts(); !errors.Is(err, ErrUnknownParty) {
		t.Fatalf("embedded key admitted outsider: %v", err)
	}
	if err = (&Council{Status: StatusExecuted, Kind: KindCouncil}).VerifyReceipts(); err == nil {
		t.Fatal("empty history established a terminal council")
	}

	done := testCouncil(t)
	for i, step := range []struct {
		party Party
		req   string
	}{{"agent-a", "safety"}, {"agent-b", "cost"}, {"agent-c", "ciphertext"}} {
		if err = done.Satisfy(step.party, step.req, "ok", now); err != nil {
			t.Fatal(err)
		}
		if err = done.OptIn(step.party, now); err != nil {
			t.Fatal(err)
		}
		_ = i
	}
	if err = done.Execute("agent-c", now); err != nil {
		t.Fatal(err)
	}
	frozen := councilBytes(t, done)
	for _, call := range []func() error{
		func() error { return done.Satisfy("agent-a", "safety", "again", now) },
		func() error { return done.OptIn("agent-a", now) },
		func() error { return done.Refuse("agent-a", now) },
		func() error { return done.Execute("agent-a", now) },
	} {
		if err = call(); !errors.Is(err, ErrTakeback) && !errors.Is(err, ErrBadState) {
			t.Fatalf("terminal mutation: %v", err)
		}
	}
	if councilBytes(t, done) != frozen {
		t.Fatal("terminal council changed")
	}
}

func TestCouncilV2RoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 4, 3, 4, 5, 6, time.UTC)
	c, err := OpenCouncil("round", []Party{"a", "b", "c"}, []Requirement{{ID: "s", Holder: "a"}}, "ship", Meter{MaxSteps: 8}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.SignReceipts(map[Party]ed25519.PrivateKey{"a": key}); err != nil {
		t.Fatal(err)
	}
	if err = c.Satisfy("a", "s", "cite:with:colons", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Council
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.steps != 0 {
		t.Fatal("step counter is not a persisted authority")
	}
	if err = back.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	if len(back.Receipts) < 2 || len(back.Receipts[1].ActorSignature) == 0 {
		t.Fatal("signed satisfy receipt did not round-trip")
	}
	if err = back.OptIn("a", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = back.Refuse("b", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	var again Council
	if err = json.Unmarshal(raw, &again); err != nil {
		t.Fatal(err)
	}
	if err = again.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	if again.Status != StatusRefused || !again.OptedIn["a"] || again.Reqs[0].Citation != "cite:with:colons" || again.Decision != "ship" {
		t.Fatalf("%+v", again)
	}
	got, err := again.ReceiptAssurance()
	if err != nil || got != AssuranceStateReplay {
		t.Fatalf("assurance %s %v", got, err)
	}
}
