package nex

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type protocolFixture struct {
	owner, worker, witness Identity
	spec                   ProtocolSpec
}

func newProtocolFixture(t *testing.T) protocolFixture {
	t.Helper()
	a, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s := ProtocolSpec{Version: 1, Nonce: "one delegation", Purpose: "Help the next agent reproduce the result", IntendedOutcome: "A verified answer and a reusable handoff", Scope: "research/question-1", SpecificationHash: Hash("spec-v1"), AcceptanceHash: Hash("evidence and reproducibility"), FailurePolicyHash: Hash("retain failed attempts; retry requires fresh consent"), Initiator: protocolPublic(a).ID(), Participants: []Public{protocolPublic(a), protocolPublic(b), protocolPublic(c)}, WorkByHeight: 20, ReturnByHeight: 40, RequiredWitnesses: []string{protocolPublic(c).ID()}, DissentPolicy: "record", Return: ReturnRequirements{SuccessArtifacts: []string{"answer"}, FailureArtifacts: []string{"failure"}, AllowedDisposition: []string{"continue", "retry", "refuse"}, AllowSuccessors: true}, MaxEvents: 32}
	grant := func(id, actor, label string, permissions ...ProtocolPermission) RoleGrant {
		return RoleGrant{ID: id, Actor: actor, Label: label, Scope: s.Scope, Permissions: permissions, ExpiresAtHeight: 40, LimitsHash: Hash("only this question"), EvidenceObligation: Hash("sign evidence commitment")}
	}
	s.Roles = []RoleGrant{grant("owner", protocolPublic(a).ID(), "proposer", PermitCommit, PermitDecide, PermitReturn), grant("worker", protocolPublic(b).ID(), "worker", PermitWork, PermitReturn), grant("witness", protocolPublic(c).ID(), "guardian", PermitReview)}
	return protocolFixture{a, b, c, s}
}
func protocolApply(t *testing.T, p *Protocol, actor Identity, grant, action string, fill func(*ProtocolCommand)) ProtocolCommand {
	t.Helper()
	v := p.View()
	c := p.Prepare(protocolPublic(actor).ID(), grant, p.spec.Scope, action, action+":"+v.Head, v.Height+1)
	if action == "admit" {
		c.GrantID = ""
		c.Scope = ""
	}
	if fill != nil {
		fill(&c)
	}
	if _, err := p.Apply(c, Sign(actor, "protocol", c), c.Height); err != nil {
		t.Fatal(err)
	}
	return c
}
func enterProtocol(t *testing.T, f protocolFixture) *Protocol {
	t.Helper()
	p, err := NewProtocol(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []Identity{f.owner, f.worker, f.witness} {
		protocolApply(t, p, a, "", "admit", nil)
	}
	protocolApply(t, p, f.owner, "owner", "commit", nil)
	return p
}
func reportProtocol(t *testing.T, p *Protocol, f protocolFixture, outcome WorkOutcome) {
	protocolApply(t, p, f.worker, "worker", "report", func(c *ProtocolCommand) {
		c.Report = &WorkReport{Outcome: outcome, Stage: "verification", ReasonHash: Hash("why"), Evidence: []string{Hash("result evidence")}}
	})
}
func reviewProtocol(t *testing.T, p *Protocol, f protocolFixture, dissent bool) {
	protocolApply(t, p, f.witness, "witness", "review", func(c *ProtocolCommand) {
		c.Review = &WitnessReview{ReportHash: Hash(p.View().Report), AssessmentHash: Hash("independent assessment"), Dissent: dissent}
	})
}
func resolveProtocol(t *testing.T, p *Protocol, f protocolFixture, outcome string) {
	protocolApply(t, p, f.owner, "owner", "resolve", func(c *ProtocolCommand) {
		c.Resolution = &Resolution{ReportHash: Hash(p.View().Report), Outcome: outcome, ReasonHash: Hash("decision rationale")}
	})
}
func manifestFor(p *Protocol) ReturnManifest {
	v := p.View()
	artifact := "answer"
	disposition := "continue"
	if v.Resolution.Outcome != "accept" {
		artifact = "failure"
		disposition = "retry"
	}
	return ReturnManifest{ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews), Evidence: append([]string(nil), v.Report.Evidence...), Resources: v.Report.Resources, Uncertainty: "Only the declared evidence was checked", SafeAssumptions: []string{"No authority transfers to the next agent"}, Artifacts: []ReturnArtifact{{artifact, Hash("artifact bytes"), "Reuse with source citation"}}, Disposition: disposition, SuccessorSpecs: []string{Hash("proposed follow-on; fresh admission required")}}
}
func rejectProtocolCommand(t *testing.T, p *Protocol, actor Identity, c ProtocolCommand, want error) {
	t.Helper()
	before := p.Bundle()
	_, err := p.Apply(c, Sign(actor, "protocol", c), c.Height)
	if err == nil || (want != nil && !errors.Is(err, want)) {
		t.Fatalf("got %v want %v", err, want)
	}
	if !reflect.DeepEqual(before, p.Bundle()) {
		t.Fatal("failure mutated agreement")
	}
}

func TestProtocolCompletesWithoutMoneyAndPreservesDissent(t *testing.T) {
	f := newProtocolFixture(t)
	p := enterProtocol(t, f)
	reportProtocol(t, p, f, WorkCompleted)
	reviewProtocol(t, p, f, true)
	resolveProtocol(t, p, f, "accept")
	if p.View().Phase != "return_due" {
		t.Fatal("resolution silently completed agreement")
	}
	c := p.Prepare(protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "return", "missing", 8)
	c.Return = &ReturnManifest{}
	rejectProtocolCommand(t, p, f.worker, c, ErrProtocolEvidence)
	last := protocolApply(t, p, f.worker, "worker", "return", func(c *ProtocolCommand) { m := manifestFor(p); c.Return = &m })
	view := p.View()
	if view.Phase != "complete" || len(view.Reviews) != 1 || !view.Reviews[0].Review.Dissent || len(view.Return.SuccessorSpecs) != 1 {
		t.Fatal(view)
	}
	verified, err := VerifyProtocolBundle(p.Bundle(), view.ID, view.Head)
	if err != nil || !reflect.DeepEqual(view, verified) {
		t.Fatal(err)
	}
	head, err := p.Apply(last, Sign(f.worker, "protocol", last), 999)
	if err != nil || head != view.Head {
		t.Fatal("exact retry failed", err)
	}
	c = p.Prepare(protocolPublic(f.owner).ID(), "owner", f.spec.Scope, "commit", "reopen", 9)
	rejectProtocolCommand(t, p, f.owner, c, ErrProtocolPhase)
}
func TestProtocolFailureProducesUsefulReturn(t *testing.T) {
	for _, outcome := range []WorkOutcome{WorkAttempted, WorkRejected, WorkFailedSafely, WorkViolated, WorkSpecDefect} {
		t.Run(string(outcome), func(t *testing.T) {
			f := newProtocolFixture(t)
			p := enterProtocol(t, f)
			reportProtocol(t, p, f, outcome)
			reviewProtocol(t, p, f, false)
			resolveProtocol(t, p, f, "reject")
			protocolApply(t, p, f.owner, "owner", "return", func(c *ProtocolCommand) { m := manifestFor(p); c.Return = &m })
			v := p.View()
			if v.Phase != "complete" || v.Report.Outcome != outcome || v.Return.Artifacts[0].ID != "failure" {
				t.Fatal(v)
			}
		})
	}
}
func TestProtocolAdmissionAndRoleScope(t *testing.T) {
	f := newProtocolFixture(t)
	p, err := NewProtocol(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Prepare(protocolPublic(f.owner).ID(), "owner", f.spec.Scope, "commit", "early", 1)
	rejectProtocolCommand(t, p, f.owner, c, ErrProtocolPhase)
	p = enterProtocol(t, f)
	c = p.Prepare(protocolPublic(f.witness).ID(), "witness", f.spec.Scope, "resolve", "guardian", 5)
	c.Resolution = &Resolution{ReportHash: Hash("report"), Outcome: "accept", ReasonHash: Hash("r")}
	rejectProtocolCommand(t, p, f.witness, c, ErrProtocolAuthority)
	c = p.Prepare(protocolPublic(f.worker).ID(), "worker", "another-task", "report", "scope", 5)
	c.Report = &WorkReport{}
	rejectProtocolCommand(t, p, f.worker, c, ErrProtocolAuthority)
	c = p.Prepare(protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "report", "expired", 40)
	c.Report = &WorkReport{}
	rejectProtocolCommand(t, p, f.worker, c, ErrProtocolAuthority)
	// A symbolic title cannot let the worker independently verify itself.
	f.spec.Roles[1].Permissions = append(f.spec.Roles[1].Permissions, PermitReview)
	if _, err = NewProtocol(f.spec); !errors.Is(err, ErrProtocolSpec) {
		t.Fatal(err)
	}
}
func TestProtocolWitnessRequiredAndDissentCanBlockAcceptance(t *testing.T) {
	f := newProtocolFixture(t)
	f.spec.DissentPolicy = "block"
	p := enterProtocol(t, f)
	reportProtocol(t, p, f, WorkCompleted)
	c := p.Prepare(protocolPublic(f.owner).ID(), "owner", f.spec.Scope, "resolve", "no-review", 6)
	c.Resolution = &Resolution{ReportHash: Hash(p.View().Report), Outcome: "accept", ReasonHash: Hash("r")}
	rejectProtocolCommand(t, p, f.owner, c, ErrProtocolEvidence)
	reviewProtocol(t, p, f, true)
	c = p.Prepare(protocolPublic(f.owner).ID(), "owner", f.spec.Scope, "resolve", "ignore-dissent", 7)
	c.Resolution = &Resolution{ReportHash: Hash(p.View().Report), Outcome: "accept", ReasonHash: Hash("r")}
	rejectProtocolCommand(t, p, f.owner, c, ErrProtocolEvidence)
	resolveProtocol(t, p, f, "reject")
}
func TestProtocolReturnCannotEraseDissentOrGrantSuccession(t *testing.T) {
	f := newProtocolFixture(t)
	p := enterProtocol(t, f)
	reportProtocol(t, p, f, WorkCompleted)
	reviewProtocol(t, p, f, true)
	resolveProtocol(t, p, f, "accept")
	m := manifestFor(p)
	m.ReviewsHash = Hash([]RecordedReview{})
	c := p.Prepare(protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "return", "erase", 8)
	c.Return = &m
	rejectProtocolCommand(t, p, f.worker, c, ErrProtocolEvidence)
	protocolApply(t, p, f.worker, "worker", "return", func(c *ProtocolCommand) { m := manifestFor(p); c.Return = &m })
	nextSpec := cloneProtocol(f.spec)
	nextSpec.Nonce = "successor"
	next, err := NewProtocol(nextSpec)
	if err != nil {
		t.Fatal(err)
	}
	c = next.Prepare(protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "report", "inherit", 1)
	c.Report = &WorkReport{Outcome: WorkCompleted}
	rejectProtocolCommand(t, next, f.worker, c, ErrProtocolPhase)
}
func TestProtocolOwnershipTamperingAndDeadline(t *testing.T) {
	f := newProtocolFixture(t)
	p := enterProtocol(t, f)
	before := p.View().ID
	f.spec.Participants[0].Signing[0] ^= 1
	f.spec.Roles[1].Permissions[0] = PermitDecide
	if p.View().ID != before {
		t.Fatal("spec alias")
	}
	// Use the owned bundle to check tampering without changing any live keys.
	b := p.Bundle()
	b.Spec.Purpose = "rewritten"
	if _, err := VerifyProtocolBundle(b, before, p.View().Head); err == nil {
		t.Fatal("purpose rewrite accepted")
	}
	b = p.Bundle()
	b.Events = b.Events[:len(b.Events)-1]
	if _, err := VerifyProtocolBundle(b, before, p.View().Head); err == nil {
		t.Fatal("truncation accepted")
	}
	f = newProtocolFixture(t)
	p = enterProtocol(t, f)
	c := p.Prepare(protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "report", "late", 20)
	c.Report = &WorkReport{Outcome: WorkCompleted, Stage: "done", ReasonHash: Hash("r"), Evidence: []string{Hash("e")}}
	rejectProtocolCommand(t, p, f.worker, c, ErrProtocolPhase)
	c.Report.Outcome = WorkFailedSafely
	if _, err := p.Apply(c, Sign(f.worker, "protocol", c), 20); err != nil {
		t.Fatal("late failure evidence should be retained", err)
	}
}
func TestProtocolStoreRecoveryAndConfidentialAtRest(t *testing.T) {
	for _, stage := range []string{"before-rename", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			f := newProtocolFixture(t)
			dir := filepath.Join(t.TempDir(), "protocols")
			key := bytes.Repeat([]byte{7}, 32)
			store, err := OpenProtocolStore(dir, key)
			if err != nil {
				t.Fatal(err)
			}
			id, err := store.Create(f.spec)
			if err != nil {
				t.Fatal(err)
			}
			c, err := store.Prepare(id, protocolPublic(f.owner).ID(), "", "", "admit", "owner-admission", 1)
			if err != nil {
				t.Fatal(err)
			}
			sig := Sign(f.owner, "protocol", c)
			store.store.commitHook = func(s string) error {
				if s == stage {
					return errors.New("injected")
				}
				return nil
			}
			if _, err = store.Apply(id, c, sig, 1); err == nil {
				t.Fatal("fault not injected")
			}
			recovered, err := OpenProtocolStore(dir, key)
			if err != nil {
				t.Fatal(err)
			}
			head, err := recovered.Apply(id, c, sig, 1)
			if err != nil {
				t.Fatal(err)
			}
			v, err := recovered.View(id)
			if err != nil || len(v.Admitted) != 1 || v.Head != head {
				t.Fatal(v, err)
			}
			data, err := os.ReadFile(recovered.store.path(id))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(data, []byte(f.spec.Purpose)) {
				t.Fatal("plaintext purpose on disk")
			}
			wrong, err := OpenProtocolStore(dir, bytes.Repeat([]byte{9}, 32))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = wrong.View(id); err == nil {
				t.Fatal("wrong key accepted")
			}
		})
	}
}

func protocolPublic(i Identity) Public {
	p, err := i.Public()
	if err != nil {
		panic(err)
	}
	return p
}

func TestProtocolUnresponsiveWorkerReturnsUncertaintyWithoutTakeback(t *testing.T) {
	f := newProtocolFixture(t)
	f.spec.Resources = []ResourceLimit{{Resource: "gpu_ms", Maximum: 100}}
	p := enterProtocol(t, f)
	c := p.Prepare(protocolPublic(f.owner).ID(), "owner", f.spec.Scope, "failure", "missing-worker", 19)
	c.Report = &WorkReport{Outcome: WorkUnreported, Stage: "work deadline", ReasonHash: Hash("no signed report was received"), Evidence: []string{Hash("admitted transcript at deadline")}, Resources: []ResourceUse{{Resource: "gpu_ms", Unknown: true}}}
	rejectProtocolCommand(t, p, f.owner, c, ErrProtocolPhase)
	c.Height = 20
	if _, err := p.Apply(c, Sign(f.owner, "protocol", c), 20); err != nil {
		t.Fatal(err)
	}
	reviewProtocol(t, p, f, false)
	resolveProtocol(t, p, f, "reject")
	protocolApply(t, p, f.owner, "owner", "return", func(c *ProtocolCommand) {
		m := manifestFor(p)
		m.Uncertainty = "Resource consumption was not reported; do not assume it is zero"
		c.Return = &m
	})
	v := p.View()
	if !v.Return.Resources[0].Unknown || v.Report.Outcome != WorkUnreported || v.Phase != "complete" {
		t.Fatal(v)
	}
}
func TestProtocolBundleRejectsDuplicateSuccessfulEvents(t *testing.T) {
	f := newProtocolFixture(t)
	p := enterProtocol(t, f)
	b := p.Bundle()
	b.Events = append(b.Events, b.Events[len(b.Events)-1])
	if _, err := VerifyProtocolBundle(b, p.View().ID, p.View().Head); err == nil {
		t.Fatal("duplicate committed event accepted")
	}
}

func TestProtocolStoreTransactAtomicityAndCacheCoherence(t *testing.T) {
	admitStep := func(actor Identity, role string) ProtocolStep {
		return func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
			who := protocolPublic(actor).ID()
			for _, a := range v.Admitted {
				if a == who {
					return ProtocolCommand{}, nil, false, nil
				}
			}
			cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: who, Action: "admit", RequestID: "admit-" + role, Height: 1}
			return cmd, Sign(actor, "protocol", cmd), true, nil
		}
	}
	commitStep := func(owner Identity, scope string) ProtocolStep {
		return func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
			if v.Phase == "working" {
				return ProtocolCommand{}, nil, false, nil
			}
			cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(owner).ID(), GrantID: "owner", Scope: scope, Action: "commit", RequestID: "commit-owner", Height: 1}
			return cmd, Sign(owner, "protocol", cmd), true, nil
		}
	}

	// (a) atomic admit+commit
	f := newProtocolFixture(t)
	dir := filepath.Join(t.TempDir(), "protocols-a")
	key := bytes.Repeat([]byte{7}, 32)
	store, err := OpenProtocolStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	v, err := store.Transact(id, 1,
		admitStep(f.owner, "owner"),
		admitStep(f.worker, "worker"),
		admitStep(f.witness, "witness"),
		commitStep(f.owner, f.spec.Scope),
	)
	if err != nil {
		t.Fatal(err)
	}
	if v.Phase != "working" {
		t.Fatalf("phase %q", v.Phase)
	}

	// (b) mid-batch error leaves no partial persistence
	f2 := newProtocolFixture(t)
	f2.spec.DissentPolicy = "block"
	dir2 := filepath.Join(t.TempDir(), "protocols-b")
	store2, err := OpenProtocolStore(dir2, key)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := store2.Create(f2.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store2.Transact(id2, 1,
		admitStep(f2.owner, "owner"),
		admitStep(f2.worker, "worker"),
		admitStep(f2.witness, "witness"),
		commitStep(f2.owner, f2.spec.Scope),
	); err != nil {
		t.Fatal(err)
	}
	_, err = store2.Transact(id2, 5,
		func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
			cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f2.worker).ID(), GrantID: "worker", Scope: f2.spec.Scope, Action: "report", RequestID: "report-worker", Height: 5}
			cmd.Report = &WorkReport{Outcome: WorkCompleted, Stage: "verification", ReasonHash: Hash("why"), Evidence: []string{Hash("result evidence")}}
			return cmd, Sign(f2.worker, "protocol", cmd), true, nil
		},
		func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
			cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f2.owner).ID(), GrantID: "owner", Scope: f2.spec.Scope, Action: "resolve", RequestID: "resolve-early", Height: 5}
			cmd.Resolution = &Resolution{ReportHash: Hash(v.Report), Outcome: "accept", ReasonHash: Hash("r")}
			return cmd, Sign(f2.owner, "protocol", cmd), true, nil
		},
	)
	if err == nil || !errors.Is(err, ErrProtocolEvidence) {
		t.Fatalf("got %v want ErrProtocolEvidence", err)
	}
	v2, err := store2.View(id2)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Phase != "working" || v2.Report != nil {
		t.Fatalf("partial persist: phase=%s report=%v", v2.Phase, v2.Report)
	}

	// (c) cross-handle cache coherence
	f3 := newProtocolFixture(t)
	dir3 := filepath.Join(t.TempDir(), "protocols-c")
	first, err := OpenProtocolStore(dir3, key)
	if err != nil {
		t.Fatal(err)
	}
	id3, err := first.Create(f3.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Transact(id3, 1,
		admitStep(f3.owner, "owner"),
		admitStep(f3.worker, "worker"),
		admitStep(f3.witness, "witness"),
		commitStep(f3.owner, f3.spec.Scope),
	); err != nil {
		t.Fatal(err)
	}
	second, err := OpenProtocolStore(dir3, key)
	if err != nil {
		t.Fatal(err)
	}
	reportCmd, err := second.Prepare(id3, protocolPublic(f3.worker).ID(), "worker", f3.spec.Scope, "report", "report-worker", 5)
	if err != nil {
		t.Fatal(err)
	}
	reportCmd.Report = &WorkReport{Outcome: WorkCompleted, Stage: "verification", ReasonHash: Hash("why"), Evidence: []string{Hash("result evidence")}}
	if _, err := second.Apply(id3, reportCmd, Sign(f3.worker, "protocol", reportCmd), 5); err != nil {
		t.Fatal(err)
	}
	final, err := first.Transact(id3, 8,
		func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
			if v.Phase != "review" {
				return ProtocolCommand{}, nil, false, fmt.Errorf("want review got %s", v.Phase)
			}
			if len(v.Reviews) > 0 {
				return ProtocolCommand{}, nil, false, nil
			}
			cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f3.witness).ID(), GrantID: "witness", Scope: f3.spec.Scope, Action: "review", RequestID: "review-witness", Height: 8}
			cmd.Review = &WitnessReview{ReportHash: Hash(v.Report), AssessmentHash: Hash("independent assessment"), Dissent: false}
			return cmd, Sign(f3.witness, "protocol", cmd), true, nil
		},
		func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
			if v.Resolution != nil {
				return ProtocolCommand{}, nil, false, nil
			}
			cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f3.owner).ID(), GrantID: "owner", Scope: f3.spec.Scope, Action: "resolve", RequestID: "resolve-owner", Height: 8}
			cmd.Resolution = &Resolution{ReportHash: Hash(v.Report), Outcome: "accept", ReasonHash: Hash("decision rationale")}
			return cmd, Sign(f3.owner, "protocol", cmd), true, nil
		},
		func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
			if v.Return != nil {
				return ProtocolCommand{}, nil, false, nil
			}
			m := ReturnManifest{ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews), Evidence: append([]string(nil), v.Report.Evidence...), Resources: v.Report.Resources, Uncertainty: "Only the declared evidence was checked", SafeAssumptions: []string{"No authority transfers to the next agent"}, Artifacts: []ReturnArtifact{{"answer", Hash("artifact bytes"), "Reuse with source citation"}}, Disposition: "continue", SuccessorSpecs: []string{Hash("proposed follow-on; fresh admission required")}}
			cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f3.worker).ID(), GrantID: "worker", Scope: f3.spec.Scope, Action: "return", RequestID: "return-worker", Height: 8}
			cmd.Return = &m
			return cmd, Sign(f3.worker, "protocol", cmd), true, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if final.Phase != "complete" {
		t.Fatalf("phase %q", final.Phase)
	}

	// (d) in-place AEAD tamper despite warm cache
	if _, err := first.View(id3); err != nil {
		t.Fatal(err)
	}
	rawBytes, err := os.ReadFile(first.store.path(id3))
	if err != nil {
		t.Fatal(err)
	}
	rawBytes[len(rawBytes)-1] ^= 0xff
	if err := os.WriteFile(first.store.path(id3), rawBytes, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = first.View(id3)
	if err == nil || !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("got %v want ErrCorruptStore", err)
	}
}

func TestProtocolStoreCacheBoundedAndExportConfirmsDurability(t *testing.T) {
	f := newProtocolFixture(t)
	key := bytes.Repeat([]byte{51}, 32)
	store, err := OpenProtocolStore(filepath.Join(t.TempDir(), "protocols-bounded"), key)
	if err != nil {
		t.Fatal(err)
	}
	var lastID string
	for i := 0; i < maxCachedProtocols+20; i++ {
		spec := f.spec
		spec.Nonce = fmt.Sprintf("bounded-%03d", i)
		id, err := store.Create(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.View(id); err != nil {
			t.Fatal(err)
		}
		lastID = id
	}
	store.mu.Lock()
	cacheLen := len(store.cache)
	orderLen := len(store.cacheOrder)
	store.mu.Unlock()
	if cacheLen > maxCachedProtocols {
		t.Fatalf("ProtocolStore cache exceeded cap: got %d > %d", cacheLen, maxCachedProtocols)
	}
	if orderLen > maxCachedProtocols*2 {
		t.Fatalf("ProtocolStore cacheOrder exceeded bound: got %d", orderLen)
	}

	beforeSync := store.Stats().DirSyncOps
	bundle, err := store.Export(lastID)
	if err != nil {
		t.Fatal(err)
	}
	if store.Stats().DirSyncOps <= beforeSync {
		t.Fatalf("expected ProtocolStore.Export to confirm directory durability via syncDir: before=%d after=%d", beforeSync, store.Stats().DirSyncOps)
	}
	if _, err := VerifyProtocolBundle(bundle, lastID, lastID); err != nil {
		t.Fatalf("exported bundle failed verification: %v", err)
	}
}
