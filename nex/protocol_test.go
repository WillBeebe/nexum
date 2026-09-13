package nex

import (
	"bytes"
	"errors"
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
