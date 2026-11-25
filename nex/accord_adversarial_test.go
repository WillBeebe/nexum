package nex

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// makeAdversarialHandoff creates a verified TaskHandoff + ProtocolBundle with
// configurable generation, extra unreturned manifest outputs, extra undeclared
// incomplete artifacts, witness dissent, and optional skipped finalization.
func makeAdversarialHandoff(
	t *testing.T,
	outcome TaskOutcome,
	witnessDissent bool,
	generation uint64,
	slotName, content string,
	extraUnreturned string,
) (TaskHandoff, ProtocolBundle, accordActor, accordActor, string) {
	t.Helper()
	f := newProtocolFixture(t)
	f.spec.Version = ProtocolVersionV2
	f.spec.Return.SuccessArtifacts = []string{slotName}
	f.spec.Return.FailureArtifacts = []string{slotName}
	f.spec.DissentPolicy = "record"

	owner := protocolPublic(f.owner)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{73}, 32)
	goals, err := OpenGoalStore(filepath.Join(dir, "goals"), key)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := OpenProtocolStore(filepath.Join(dir, "attempts"), key)
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := OpenCoordinationStore(filepath.Join(dir, "tasks"), key, goals, attempts)
	if err != nil {
		t.Fatal(err)
	}
	goalID, err := goals.Create(GoalSpec{
		Nonce: fmt.Sprintf("adv-goal-%s-%d", slotName, generation), Purpose: "Adversarial evidence fixture",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	task := TaskSpec{
		GoalID: goalID, Nonce: "task-" + slotName, Purpose: f.spec.Purpose, Scope: f.spec.Scope,
		SpecificationHash: f.spec.SpecificationHash, AcceptanceHash: f.spec.AcceptanceHash,
		FailurePolicyHash: f.spec.FailurePolicyHash, Authority: owner,
		Outputs: []string{slotName}, FailureOutputs: []string{slotName},
	}
	rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "plan-1", Tasks: []TaskSpec{task}}
	if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}

	// Advance generations if generation > 1 by creating expired prior claims.
	var (
		claim    ClaimRequest
		claimSig []byte
		lease    TaskLease
		p        *Protocol
		curH     uint64 = 1
	)
	for g := uint64(1); g <= generation; g++ {
		spec := cloneProtocolSpec(f.spec)
		spec.TaskID = task.ID()
		spec.Generation = g
		spec.Nonce = fmt.Sprintf("gen-%d-%s", g, slotName)
		spec.WorkByHeight = curH + 10
		spec.ReturnByHeight = curH + 20
		for i := range spec.Roles {
			spec.Roles[i].ExpiresAtHeight = spec.ReturnByHeight
		}
		p, err = NewProtocol(spec)
		if err != nil {
			t.Fatal(err)
		}
		claim = ClaimRequest{
			GoalID: goalID, TaskID: task.ID(), WorkerID: protocolPublic(f.worker).ID(),
			RequestID: fmt.Sprintf("claim-%d", g), ProtocolID: p.View().ID,
			ExpectedGeneration: g - 1, LeaseUntilHeight: spec.ReturnByHeight + 5,
		}
		claimSig = Sign(f.owner, ClaimSignatureDomain, claim)
		lease, err = tasks.Claim(claim, claimSig, spec, curH)
		if err != nil {
			t.Fatal(err)
		}
		if g < generation {
			// Expire this generation's lease before next generation claims.
			curH = claim.LeaseUntilHeight + 1
		}
	}

	artRef := testArtifactRef(content)
	spec := p.Bundle().Spec
	applyProto := func(actor Identity, grant, action string, h uint64, fill func(*ProtocolCommand)) {
		t.Helper()
		scope := spec.Scope
		if action == "admit" {
			scope = ""
		}
		v := p.View()
		c := p.Prepare(protocolPublic(actor).ID(), grant, scope, action, action+":"+v.Head, h)
		if fill != nil {
			fill(&c)
		}
		if _, err := p.Apply(c, Sign(actor, "protocol", c), h); err != nil {
			t.Fatalf("protocol %s: %v", action, err)
		}
	}

	switch outcome {
	case TaskIncomplete:
		applyProto(f.owner, "", "admit", curH, nil)
		arts := []NamedArtifact{{Name: slotName, Ref: artRef}}
		if extraUnreturned != "" {
			arts = append(arts, NamedArtifact{Name: extraUnreturned, Ref: testArtifactRef("undeclared-secret")})
		}
		applyProto(f.owner, "owner", "incomplete", spec.ReturnByHeight, func(c *ProtocolCommand) {
			c.Incomplete = &IncompleteReturn{
				ReasonHash: Hash("deadline-incomplete"),
				Artifacts:  arts,
			}
		})
	case TaskAccepted:
		for _, a := range []Identity{f.owner, f.worker, f.witness} {
			applyProto(a, "", "admit", curH, nil)
		}
		applyProto(f.owner, "owner", "commit", curH+1, nil)
		outputs := []NamedArtifact{{Name: slotName, Ref: artRef}}
		if extraUnreturned != "" {
			outputs = append(outputs, NamedArtifact{Name: extraUnreturned, Ref: testArtifactRef("unreturned-scratch")})
		}
		applyProto(f.worker, "worker", "report", curH+2, func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("done"), Evidence: []string{artRef.Digest},
				Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: outputs},
			}
		})
		applyProto(f.witness, "witness", "review", curH+3, func(c *ProtocolCommand) {
			c.Review = &WitnessReview{ReportHash: Hash(p.View().Report), AssessmentHash: Hash("ok"), Dissent: witnessDissent}
		})
		applyProto(f.owner, "owner", "resolve", curH+4, func(c *ProtocolCommand) {
			c.Resolution = &Resolution{ReportHash: Hash(p.View().Report), Outcome: "accept", ReasonHash: Hash("acc")}
		})
		applyProto(f.worker, "worker", "return", curH+5, func(c *ProtocolCommand) {
			v := p.View()
			c.Return = &ReturnManifest{
				ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews),
				Evidence: []string{artRef.Digest}, Uncertainty: "local",
				SafeAssumptions: []string{"bounded"}, Disposition: "continue",
				Artifacts: []ReturnArtifact{{ID: slotName, Commitment: artRef.Digest, ReuseRestrictions: "cite"}},
			}
		})
	case TaskRejected:
		for _, a := range []Identity{f.owner, f.worker, f.witness} {
			applyProto(a, "", "admit", curH, nil)
		}
		applyProto(f.owner, "owner", "commit", curH+1, nil)
		applyProto(f.worker, "worker", "report", curH+2, func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome: WorkFailedSafely, Stage: "work", ReasonHash: Hash("fail"), Evidence: []string{artRef.Digest},
				Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: slotName, Ref: artRef}}},
			}
		})
		applyProto(f.witness, "witness", "review", curH+3, func(c *ProtocolCommand) {
			c.Review = &WitnessReview{ReportHash: Hash(p.View().Report), AssessmentHash: Hash("rej"), Dissent: witnessDissent}
		})
		applyProto(f.owner, "owner", "resolve", curH+4, func(c *ProtocolCommand) {
			c.Resolution = &Resolution{ReportHash: Hash(p.View().Report), Outcome: "reject", ReasonHash: Hash("rej")}
		})
		applyProto(f.owner, "owner", "return", curH+5, func(c *ProtocolCommand) {
			v := p.View()
			c.Return = &ReturnManifest{
				ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews),
				Evidence: []string{artRef.Digest}, Uncertainty: "failed",
				SafeAssumptions: []string{"bounded"}, Disposition: "retry",
				Artifacts: []ReturnArtifact{{ID: slotName, Commitment: artRef.Digest, ReuseRestrictions: "diag"}},
			}
		})
	}

	for _, ev := range p.Bundle().Events {
		if _, err := attempts.Apply(claim.ProtocolID, ev.Command, ev.Signature, ev.Command.Height); err != nil {
			t.Fatal(err)
		}
	}
	v := p.View()
	if _, err := tasks.Finalize(lease, v.Head, v.Height); err != nil {
		t.Fatal(err)
	}
	h, err := tasks.ExportHandoff(claim, claimSig)
	if err != nil {
		t.Fatal(err)
	}
	return h, p.Bundle(), accordActor{id: f.owner, pub: owner}, accordActor{id: f.witness, pub: protocolPublic(f.witness)}, goalID
}

func TestAccordAdversarialEvidenceTrustBoundaries(t *testing.T) {
	fx := newAccordFixture(t)
	acceptedH, acceptedB, ownerAct, _, _ := makeAdversarialHandoff(t, TaskAccepted, false, 2, "config", `{"max_attempts":3}`, "unreturned-secret")
	incompleteH, _, _, _, _ := makeAdversarialHandoff(t, TaskIncomplete, false, 1, "observation", "partial-obs", "undeclared-junk")
	gen1H, _, _, _, _ := makeAdversarialHandoff(t, TaskAccepted, false, 1, "config", `{"max_attempts":1}`, "")

	fx.spec.Roles = append(fx.spec.Roles,
		AccordRoleGrant{
			ID: "release-attest", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
			Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("att-rel"),
		},
		AccordRoleGrant{
			ID: "sre-attest", Actor: fx.sre.pub.ID(), Scope: fx.spec.Scope,
			Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("att-sre"),
		},
	)
	fx.spec.Evidence = []EvidenceSlot{
		{
			ID: "pinned-handoff", Kind: EvidenceTaskHandoff,
			GoalID: acceptedH.Task.GoalID, TaskID: acceptedH.Task.ID(),
			ExpectedAuthority: acceptedH.Task.Authority.ID(), ExpectedResultHash: Hash(acceptedH.Result),
			MinGeneration: 2, RequiredAttester: fx.release.pub.ID(),
		},
		{
			ID: "incomplete-handoff", Kind: EvidenceTaskHandoff,
			GoalID: incompleteH.Task.GoalID, TaskID: incompleteH.Task.ID(),
			ExpectedAuthority: incompleteH.Task.Authority.ID(), RequiredAttester: fx.release.pub.ID(),
		},
		{
			ID: "pinned-bundle", Kind: EvidenceProtocolBundle,
			ProtocolID: Hash(acceptedB.Spec), ExpectedAuthority: acceptedB.Spec.Initiator,
			ExpectedHead: acceptedB.Events[len(acceptedB.Events)-1].ReceiptHash,
		},
		{
			ID: "mingen-handoff", Kind: EvidenceTaskHandoff,
			GoalID: gen1H.Task.GoalID, TaskID: gen1H.Task.ID(),
			ExpectedAuthority: gen1H.Task.Authority.ID(), MinGeneration: 2, RequiredAttester: fx.release.pub.ID(),
		},
	}

	// Guard on full-rollout tries to accept incomplete-handoff's "observation" ONLY when TaskAccepted + NoWitnessDissent.
	fx.spec.Options[0].Guard = OptionGuard{
		AllOf: []EvidencePredicate{
			{EvidenceID: "incomplete-handoff", Op: GuardArtifactSlot, Outcomes: []TaskOutcome{TaskAccepted}, Slot: "observation", Digest: incompleteH.Result.Artifacts[0].Digest},
			{EvidenceID: "incomplete-handoff", Op: GuardNoWitnessDissent},
		},
	}

	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatalf("NewAccord: %v", err)
	}

	// 1. Unauthorized attester (has AccordPermitAttest, but NOT RequiredAttester) -> ErrAccordAuthority.
	accordReject(t, a, fx.sre, "sre-attest", "attest", "wrong-attester", 1, ErrAccordAuthority, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "pinned-handoff", Handoff: &acceptedH}
	})

	// 2. Unknown evidence slot -> ErrAccordEvidence.
	accordReject(t, a, fx.release, "release-attest", "attest", "unknown-slot", 1, ErrAccordEvidence, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "no-such-slot", Handoff: &acceptedH}
	})

	// 3. Kind mismatch (ProtocolBundle supplied for TaskHandoff slot, and vice versa).
	accordReject(t, a, fx.release, "release-attest", "attest", "kind-mismatch-1", 1, ErrAccordEvidence, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "pinned-handoff", Protocol: &acceptedB}
	})
	accordReject(t, a, fx.release, "release-attest", "attest", "kind-mismatch-2", 1, ErrAccordEvidence, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "pinned-bundle", Handoff: &acceptedH}
	})

	// 4. Generation below MinGeneration -> ErrAccordEvidence.
	accordReject(t, a, fx.release, "release-attest", "attest", "stale-gen", 1, ErrAccordEvidence, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "mingen-handoff", Handoff: &gen1H}
	})

	// 5. Forged/tampered TaskHandoff variations -> ErrAccordEvidence.
	badHandoffs := []struct {
		name   string
		mutate func(*TaskHandoff)
	}{
		{"wrong_task_handoff_substituted", func(h *TaskHandoff) { *h = cloneTaskHandoff(incompleteH) }},
		{"tampered_claim_signature", func(h *TaskHandoff) { h.ClaimSignature[0] ^= 0xff }},
		{"tampered_artifact_digest", func(h *TaskHandoff) { h.Result.Artifacts[0].Digest = Hash("evil") }},
		{"tampered_protocol_event_sig", func(h *TaskHandoff) { h.Protocol.Events[0].Signature[0] ^= 0xff }},
		{"truncated_protocol_events", func(h *TaskHandoff) { h.Protocol.Events = h.Protocol.Events[:len(h.Protocol.Events)-1] }},
		{"tampered_result_head", func(h *TaskHandoff) { h.Result.Head = Hash("fake-head") }},
		{"tampered_result_outcome", func(h *TaskHandoff) { h.Result.Outcome = TaskRejected }},
		{"wrong_authority_key", func(h *TaskHandoff) {
			other := newAccordActor(t)
			h.Task.Authority = other.pub
		}},
		{"terminal_event_at_lease_expiry", func(h *TaskHandoff) {
			// Rebuild incomplete closeout at LeaseUntilHeight (illegal in VerifyTaskHandoff).
			p2, err := NewProtocol(h.Protocol.Spec)
			if err != nil {
				t.Fatal(err)
			}
			admit := h.Protocol.Events[0]
			if _, err := p2.Apply(admit.Command, admit.Signature, admit.Command.Height); err != nil {
				t.Fatal(err)
			}
			closeCmd := p2.Prepare(ownerAct.pub.ID(), "owner", h.Protocol.Spec.Scope, "incomplete", "late-close", h.Result.Lease.LeaseUntilHeight)
			closeCmd.Incomplete = &IncompleteReturn{ReasonHash: Hash("late")}
			if _, err := p2.Apply(closeCmd, Sign(ownerAct.id, "protocol", closeCmd), closeCmd.Height); err != nil {
				t.Fatal(err)
			}
			h.Protocol = p2.Bundle()
			h.Result.Head = p2.View().Head
			h.Result.Outcome = TaskIncomplete
		}},
	}
	for i, tc := range badHandoffs {
		t.Run("handoff_"+tc.name, func(t *testing.T) {
			bad := cloneTaskHandoff(acceptedH)
			tc.mutate(&bad)
			accordReject(t, a, fx.release, "release-attest", "attest", fmt.Sprintf("bad-h-%d", i), 1, ErrAccordEvidence, func(c *AccordCommand) {
				c.Attest = &AttestPayload{EvidenceID: "pinned-handoff", Handoff: &bad}
			})
		})
	}

	// 6. Forged/non-terminal/v1 ProtocolBundle attacks -> ErrAccordEvidence.
	v1Fix := newProtocolFixture(t)
	v1Proto := enterProtocol(t, v1Fix)
	reportProtocol(t, v1Proto, v1Fix, WorkCompleted)
	reviewProtocol(t, v1Proto, v1Fix, false)
	resolveProtocol(t, v1Proto, v1Fix, "accept")
	protocolApply(t, v1Proto, v1Fix.worker, "worker", "return", func(c *ProtocolCommand) {
		m := manifestFor(v1Proto)
		c.Return = &m
	})
	v1Bundle := v1Proto.Bundle()

	nonTerminal := cloneProtocolBundle(acceptedB)
	nonTerminal.Events = nonTerminal.Events[:len(nonTerminal.Events)-1] // stops at return_due!

	emptyEvents := cloneProtocolBundle(acceptedB)
	emptyEvents.Events = nil

	forgedSigBundle := cloneProtocolBundle(acceptedB)
	forgedSigBundle.Events[len(forgedSigBundle.Events)-1].Signature[0] ^= 1

	for i, b := range []ProtocolBundle{v1Bundle, nonTerminal, emptyEvents, forgedSigBundle} {
		bc := b
		accordReject(t, a, fx.release, "release-attest", "attest", fmt.Sprintf("bad-b-%d", i), 1, ErrAccordEvidence, func(c *AccordCommand) {
			c.Attest = &AttestPayload{EvidenceID: "pinned-bundle", Protocol: &bc}
		})
	}

	// Also verify a v1 bundle is rejected even when its own ProtocolID & Head are pinned!
	fxV1 := newAccordFixture(t)
	fxV1.spec.Roles = append(fxV1.spec.Roles, AccordRoleGrant{
		ID: "rel-att", Actor: fxV1.release.pub.ID(), Scope: fxV1.spec.Scope,
		Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
	})
	fxV1.spec.Evidence = []EvidenceSlot{{
		ID: "v1-slot", Kind: EvidenceProtocolBundle, ProtocolID: Hash(v1Bundle.Spec),
		ExpectedAuthority: v1Bundle.Spec.Initiator, ExpectedHead: v1Bundle.Events[len(v1Bundle.Events)-1].ReceiptHash,
	}}
	aV1, err := NewAccord(fxV1.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordReject(t, aV1, fxV1.release, "rel-att", "attest", "att-v1", 1, ErrAccordEvidence, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "v1-slot", Protocol: &v1Bundle}
	})

	// Also verify a non-terminal v2 bundle with omitted ExpectedHead is rejected!
	fxNT := newAccordFixture(t)
	fxNT.spec.Roles = append(fxNT.spec.Roles, AccordRoleGrant{
		ID: "rel-att", Actor: fxNT.release.pub.ID(), Scope: fxNT.spec.Scope,
		Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
	})
	fxNT.spec.Evidence = []EvidenceSlot{{
		ID: "nt-slot", Kind: EvidenceProtocolBundle, ProtocolID: Hash(nonTerminal.Spec),
		ExpectedAuthority: nonTerminal.Spec.Initiator, RequiredAttester: fxNT.release.pub.ID(),
	}}
	aNT, err := NewAccord(fxNT.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordReject(t, aNT, fxNT.release, "rel-att", "attest", "att-nt", 1, ErrAccordEvidence, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "nt-slot", Protocol: &nonTerminal}
	})

	// 7. Valid attestations succeed, incomplete handoff fails BOTH GuardArtifactSlot(TaskAccepted) AND GuardNoWitnessDissent,
	//    AND ArtifactRefs strictly excludes unreturned/undeclared artifacts!
	accordMustApply(t, a, fx.release, "release-attest", "attest", "ok-pinned", 1, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "pinned-handoff", Handoff: &acceptedH}
	})
	accordMustApply(t, a, fx.release, "release-attest", "attest", "ok-incomplete", 2, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "incomplete-handoff", Handoff: &incompleteH}
	})
	accordMustApply(t, a, fx.sre, "sre-attest", "attest", "ok-bundle", 3, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "pinned-bundle", Protocol: &acceptedB}
	})

	// Check GuardArtifactSlot(TaskAccepted) + GuardNoWitnessDissent both fail closed on incomplete handoff!
	for _, gs := range a.EvaluateGuards() {
		if gs.OptionID == "full-rollout" {
			if gs.Passed {
				t.Fatalf("incomplete handoff bypassed guard: %+v", gs)
			}
			if len(gs.FailedPredicates) != 2 ||
				gs.FailedPredicates[0].Reason != "outcome_mismatch" ||
				gs.FailedPredicates[1].Reason != "protocol_not_complete" {
				t.Fatalf("unexpected failure reasons on incomplete bypass check: %+v", gs.FailedPredicates)
			}
		}
	}

	// Check ArtifactRefs strict consistency with fact.Artifacts (no leaked unreturned/undeclared artifacts!).
	for _, ev := range a.View().Evidence {
		for _, ref := range ev.ArtifactRefs {
			if !slices.Contains(ev.Artifacts, TaskArtifact{Slot: ref.Name, Digest: ref.Ref.Digest}) {
				t.Fatalf("evidence %s leaked undeclared/unreturned ArtifactRef %q not present in Artifacts %+v", ev.EvidenceID, ref.Name, ev.Artifacts)
			}
		}
		if ev.EvidenceID == "pinned-handoff" && len(ev.ArtifactRefs) != 1 {
			t.Fatalf("pinned-handoff ArtifactRefs=%+v want only [config]", ev.ArtifactRefs)
		}
		if ev.EvidenceID == "incomplete-handoff" && len(ev.ArtifactRefs) != 1 {
			t.Fatalf("incomplete-handoff ArtifactRefs=%+v want only [observation]", ev.ArtifactRefs)
		}
		if ev.EvidenceID == "pinned-bundle" && len(ev.ArtifactRefs) != 1 {
			t.Fatalf("pinned-bundle ArtifactRefs=%+v want only [config]", ev.ArtifactRefs)
		}
	}
}

func TestAccordAdversarialUTF8CanonicalizationAndSliceNormalization(t *testing.T) {
	badUTF8Strings := []struct {
		name string
		val  string
	}{
		{"raw_0xff", "opt-\xff"},
		{"raw_0xfe", "opt-\xfe"},
		{"overlong_slash", "opt-\xc0\xaf"},
		{"lone_surrogate", "opt-\xed\xa0\x80"},
		{"len128_ufffd_expand", strings.Repeat("a", 127) + "\xff"},
		{"nul_byte", "opt\x00id"},
		{"ascii_ctrl_bel", "opt\x07id"},
		{"ascii_ctrl_del", "opt\x7fid"},
		{"unicode_ctrl_nel", "opt\u0085id"},
		{"leading_space", " opt"},
		{"trailing_space", "opt "},
		{"interior_space", "opt id"},
		{"interior_nbsp", "opt\u00a0id"},
		{"interior_en_quad", "opt\u2000id"},
	}

	for _, tc := range badUTF8Strings {
		t.Run("spec_id_"+tc.name, func(t *testing.T) {
			fx := newAccordFixture(t)
			fx.spec.Nonce = tc.val
			if err := fx.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("Nonce=%q: got %v want ErrAccordSpec", tc.val, err)
			}
			fx2 := newAccordFixture(t)
			fx2.spec.Options[0].ID = tc.val
			if err := fx2.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("Option.ID=%q: got %v want ErrAccordSpec", tc.val, err)
			}
			fx3 := newAccordFixture(t)
			fx3.spec.Roles[0].DomainRoles = []string{tc.val}
			if err := fx3.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("DomainRole=%q: got %v want ErrAccordSpec", tc.val, err)
			}
		})
	}

	// U+FFFD collision attack: two distinct invalid UTF-8 strings ("a\xff" and "a\xfe") would both
	// marshal to "a\ufffd" under encoding/json! Both must be rejected BEFORE uniqueness/hashing.
	fxColl := newAccordFixture(t)
	fxColl.spec.Options[0].ID = "opt-\xff"
	fxColl.spec.Options[1].ID = "opt-\xfe"
	if err := fxColl.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
		t.Fatalf("U+FFFD colliding option IDs accepted: %v", err)
	}

	// Invalid UTF-8 & NUL inside embedded ProtocolSpec and TaskSpec inside OptionBinding!
	fxEmb := newAccordFixture(t)
	fxEmb.spec.Options[0].Binding.ProtocolSpec.Purpose = "bad\x00purpose"
	if err := fxEmb.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
		t.Fatalf("NUL in embedded ProtocolSpec accepted: %v", err)
	}
	fxEmb2 := newAccordFixture(t)
	fxEmb2.spec.Options[0].Binding.ProtocolSpec.Roles[0].Label = "bad\xfflabel"
	if err := fxEmb2.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
		t.Fatalf("invalid UTF-8 in embedded ProtocolSpec accepted: %v", err)
	}
	fxEmb3 := newAccordFixture(t)
	badTask := fxEmb3.taskSpec
	badTask.Purpose = "bad\x00task"
	fxEmb3.spec.Options[0].Binding = OptionBinding{Kind: BindingTaskSpec, TaskSpec: &badTask}
	if err := fxEmb3.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
		t.Fatalf("NUL in embedded TaskSpec accepted: %v", err)
	}

	// Invalid UTF-8 in AccordCommand RequestID / Vote / Veto rejected by BOTH SignAccordCommand AND Apply!
	fx := newAccordFixture(t)
	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"req\xff", "req\x00", "req id", " req", "req\t1", strings.Repeat("r", 127) + "\xff"} {
		cmd := a.Prepare(fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", bad, 2)
		cmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
		if _, err := SignAccordCommand(fx.sre.id, cmd); !errors.Is(err, ErrAccordSpec) {
			t.Fatalf("SignAccordCommand accepted bad RequestID %q: %v", bad, err)
		}
		if _, err := a.Apply(cmd, Sign(fx.sre.id, AccordCommandDomain, cmd), 2); !errors.Is(err, ErrAccordSpec) {
			t.Fatalf("Apply accepted bad RequestID %q: %v", bad, err)
		}
	}

	// nil vs []T{} normalization on optional Accord* slices produces identical AccordSpec.ID() and exact retry!
	fxNil := newAccordFixture(t)
	fxNil.spec.Evidence = nil
	fxNil.spec.Options[0].Guard.AllOf = nil
	fxNil.spec.Options[0].ExtraMandatoryRoles = nil
	fxEmpty := cloneAccordSpec(fxNil.spec)
	fxEmpty.Evidence = []EvidenceSlot{}
	fxEmpty.Options[0].Guard.AllOf = []EvidencePredicate{}
	fxEmpty.Options[0].ExtraMandatoryRoles = []RoleRequirement{}
	if fxNil.spec.ID() != fxEmpty.ID() {
		t.Fatalf("nil vs empty optional Accord slices diverged Spec.ID(): %s != %s", fxNil.spec.ID(), fxEmpty.ID())
	}

	// Non-nil empty slices on embedded ProtocolSpec / TaskSpec MUST be preserved across NewAccord + AccordStore + VerifyAccordBundle!
	fxEmbSlice := newAccordFixture(t)
	fxEmbSlice.spec.Options[0].Binding.ProtocolSpec.Resources = []ResourceLimit{} // non-nil empty!
	taskWithEmptyDeps := fxEmbSlice.taskSpec
	taskWithEmptyDeps.Dependencies = []TaskDependency{} // non-nil empty!
	fxEmbSlice.spec.Options[2].Binding = OptionBinding{Kind: BindingTaskSpec, TaskSpec: &taskWithEmptyDeps}

	dir := filepath.Join(t.TempDir(), "slice-store")
	st, err := OpenAccordStore(dir, bytes.Repeat([]byte{88}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.Create(fxEmbSlice.spec)
	if err != nil {
		t.Fatalf("Create with embedded non-nil empty slices: %v", err)
	}
	reopened, err := OpenAccordStore(dir, bytes.Repeat([]byte{88}, 32))
	if err != nil {
		t.Fatal(err)
	}
	b, err := reopened.Export(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccordBundle(b, id, id); err != nil {
		t.Fatalf("VerifyAccordBundle failed after JSON round-trip with embedded non-nil empty slices: %v", err)
	}
	// Also test Veto with []string{} vs nil exact retry equivalence!
	vetoCmd := AccordCommand{
		RequestID: "veto-empty-slice", AccordID: id, Head: id, Actor: fxEmbSlice.safety.pub.ID(),
		GrantID: "safety-vote", Scope: fxEmbSlice.spec.Scope, Action: "veto", Height: 2,
		Veto: &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("r"), EvidenceIDs: []string{}},
	}
	vetoSig, err := SignAccordCommand(fxEmbSlice.safety.id, vetoCmd)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := reopened.Apply(id, vetoCmd, vetoSig, 2)
	if err != nil {
		t.Fatal(err)
	}
	vetoCmdNil := vetoCmd
	vetoCmdNil.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("r"), EvidenceIDs: nil}
	h2, err := reopened.Apply(id, vetoCmdNil, vetoSig, 2)
	if err != nil || h2 != h1 {
		t.Fatalf("nil vs []string{} veto exact retry failed: h1=%s h2=%s err=%v", h1, h2, err)
	}
}

func TestAccordAdversarialDomainsReplayEquivocationAndRoles(t *testing.T) {
	fxA := newAccordFixture(t)
	fxB := newAccordFixture(t)
	// Give Accord B identical participants/roles/scope as Accord A, differing ONLY in Nonce!
	fxB.spec = cloneAccordSpec(fxA.spec)
	fxB.spec.Nonce = "release-accord-2"

	aA, err := NewAccord(fxA.spec)
	if err != nil {
		t.Fatal(err)
	}
	aB, err := NewAccord(fxB.spec)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Cross-domain signature confusion: signing AccordCommand under other Nexum domains must fail!
	voteCmd := aA.Prepare(fxA.sre.pub.ID(), "sre-vote", fxA.spec.Scope, "vote", "dom-test", 2)
	voteCmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	for _, domain := range []string{"protocol", "operation", "contract", PlanSignatureDomain, ClaimSignatureDomain, AccordSpecHashDomain} {
		wrongSig := Sign(fxA.sre.id, domain, voteCmd)
		if _, err := aA.Apply(voteCmd, wrongSig, 2); err == nil {
			t.Fatalf("accepted signature from wrong domain %q", domain)
		}
	}

	// 2. Cross-deliberation replay: commit req "shared-req" in A and B, then replay A's command on B -> ErrAccordStale (NOT ErrOperationConflict!).
	cmdA := aA.Prepare(fxA.sre.pub.ID(), "sre-vote", fxA.spec.Scope, "vote", "shared-req", 2)
	cmdA.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("A")}
	sigA, err := SignAccordCommand(fxA.sre.id, cmdA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aA.Apply(cmdA, sigA, 2); err != nil {
		t.Fatal(err)
	}
	cmdB := aB.Prepare(fxA.sre.pub.ID(), "sre-vote", fxB.spec.Scope, "vote", "shared-req", 2)
	cmdB.Vote = &VotePayload{OptionID: "hold-release", Position: BallotApprove, RationaleHash: Hash("B")}
	sigB, err := SignAccordCommand(fxA.sre.id, cmdB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aB.Apply(cmdB, sigB, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := aB.Apply(cmdA, sigA, 2); !errors.Is(err, ErrAccordStale) {
		t.Fatalf("cross-accord replay got %v want ErrAccordStale", err)
	}

	// 3. Unauthenticated RequestID probing: forged signature on committed RequestID must fail auth, NOT return cached receipt or ErrOperationConflict!
	badSig := slices.Clone(sigA)
	badSig[0] ^= 0xff
	if _, err := aA.Apply(cmdA, badSig, 2); err == nil || errors.Is(err, ErrOperationConflict) {
		t.Fatalf("forged signature on committed RequestID got %v", err)
	}
	// Wrong signer (release signing sre's command) must also fail auth!
	wrongActorSig := Sign(fxA.release.id, AccordCommandDomain, cmdA)
	if _, err := aA.Apply(cmdA, wrongActorSig, 2); err == nil || errors.Is(err, ErrOperationConflict) {
		t.Fatalf("wrong signer on committed RequestID got %v", err)
	}

	// 4. Role escalation & grant misuse:
	// - Outsider identity -> ErrAccordAuthority.
	outsider := newAccordActor(t)
	outCmd := aA.Prepare(outsider.pub.ID(), "sre-vote", fxA.spec.Scope, "vote", "out-1", 3)
	outCmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	if _, err := aA.Apply(outCmd, Sign(outsider.id, AccordCommandDomain, outCmd), 3); !errors.Is(err, ErrAccordAuthority) {
		t.Fatalf("outsider got %v want ErrAccordAuthority", err)
	}
	// - Using another participant's GrantID -> ErrAccordAuthority.
	accordReject(t, aA, fxA.sre, "safety-vote", "veto", "steal-grant", 3, ErrAccordAuthority, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("r")}
	})
	// - Wrong Scope -> ErrAccordAuthority.
	wrongScope := aA.Prepare(fxA.safety.pub.ID(), "safety-vote", "other/scope", "vote", "bad-scope", 3)
	wrongScope.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	if _, err := aA.Apply(wrongScope, Sign(fxA.safety.id, AccordCommandDomain, wrongScope), 3); !errors.Is(err, ErrAccordAuthority) {
		t.Fatalf("wrong scope got %v want ErrAccordAuthority", err)
	}
	// - Non-veto role trying veto -> ErrAccordAuthority.
	accordReject(t, aA, fxA.release, "release-vote", "veto", "no-veto-perm", 3, ErrAccordAuthority, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("r")}
	})
	// - Non-resolver trying resolve -> ErrAccordAuthority.
	accordReject(t, aA, fxA.sre, "sre-vote", "resolve", "no-resolve-perm", 10, ErrAccordAuthority, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("r")}
	})
	// - Non-monotone height & mismatched height -> ErrAccordStale.
	nonMono := aA.Prepare(fxA.safety.pub.ID(), "safety-vote", fxA.spec.Scope, "vote", "non-mono", 1)
	nonMono.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	if _, err := aA.Apply(nonMono, Sign(fxA.safety.id, AccordCommandDomain, nonMono), 1); !errors.Is(err, ErrAccordStale) {
		t.Fatalf("non-monotone height got %v want ErrAccordStale", err)
	}
	mismatchH := aA.Prepare(fxA.safety.pub.ID(), "safety-vote", fxA.spec.Scope, "vote", "mis-h", 4)
	mismatchH.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	if _, err := aA.Apply(mismatchH, Sign(fxA.safety.id, AccordCommandDomain, mismatchH), 5); !errors.Is(err, ErrAccordStale) {
		t.Fatalf("mismatched height got %v want ErrAccordStale", err)
	}

	// 5. Separate grants per actor: vote on grant 1, veto on grant 2, plus "safety" role ONLY on propose grant!
	fxSep := newAccordFixture(t)
	fxSep.spec.AllowProposals = true
	fxSep.spec.ProposalByHeight = 4
	fxSep.spec.Roles = []AccordRoleGrant{
		{
			ID: "rel-vote", Actor: fxSep.release.pub.ID(), Scope: fxSep.spec.Scope,
			DomainRoles: []string{"release"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 2, ExpiresAtHeight: 10, LimitsHash: Hash("1"),
		},
		{
			// release has "safety" ONLY on its propose grant, NOT on its vote grant!
			ID: "rel-prop-safety", Actor: fxSep.release.pub.ID(), Scope: fxSep.spec.Scope,
			DomainRoles: []string{"safety"}, Permissions: []AccordPermission{AccordPermitPropose},
			ExpiresAtHeight: 4, LimitsHash: Hash("2"),
		},
		{
			ID: "sre-vote", Actor: fxSep.sre.pub.ID(), Scope: fxSep.spec.Scope,
			DomainRoles: []string{"sre"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 2, ExpiresAtHeight: 10, LimitsHash: Hash("3"),
		},
		{
			// safety has vote on grant A and veto on grant B (disjoint perms!).
			ID: "saf-vote", Actor: fxSep.safety.pub.ID(), Scope: fxSep.spec.Scope,
			DomainRoles: []string{"safety"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 2, ExpiresAtHeight: 10, LimitsHash: Hash("4"),
		},
		{
			ID: "saf-veto", Actor: fxSep.safety.pub.ID(), Scope: fxSep.spec.Scope,
			DomainRoles: []string{"safety"}, Permissions: []AccordPermission{AccordPermitVeto},
			ExpiresAtHeight: 10, LimitsHash: Hash("5"),
		},
		{
			// security has a resolve grant that expires at 19 (< ResolveByHeight=20) AND release has one expiring at 20.
			ID: "sec-res-early", Actor: fxSep.security.pub.ID(), Scope: fxSep.spec.Scope,
			Permissions: []AccordPermission{AccordPermitResolve}, ExpiresAtHeight: 19, LimitsHash: Hash("6"),
		},
		{
			ID: "rel-res-close", Actor: fxSep.release.pub.ID(), Scope: fxSep.spec.Scope,
			Permissions: []AccordPermission{AccordPermitResolve}, ExpiresAtHeight: 20, LimitsHash: Hash("7"),
		},
	}
	fxSep.spec.Rules.MinParticipationCount = 2
	fxSep.spec.Rules.MinParticipationWeight = 4
	fxSep.spec.Rules.MinApprovalCount = 2
	fxSep.spec.Rules.MinApprovalWeight = 4
	fxSep.spec.Rules.MinApprovalMarginWeight = 0
	fxSep.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}}

	aSep, err := NewAccord(fxSep.spec)
	if err != nil {
		t.Fatalf("NewAccord(separate grants): %v", err)
	}
	// Cross-grant equivocation: safety votes approve via saf-vote, then tries veto via saf-veto -> ErrAccordEquivocation!
	accordMustApply(t, aSep, fxSep.safety, "saf-vote", "vote", "sv1", 4, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
	})
	accordReject(t, aSep, fxSep.safety, "saf-veto", "veto", "svt1", 4, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "canary-rollout", ReasonHash: Hash("flip")}
	})
	// release (who has "safety" ONLY on propose grant, NOT on vote grant) + sre approve full-rollout -> MUST fail mandatory safety role!
	accordMustApply(t, aSep, fxSep.release, "rel-vote", "vote", "rv1", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
	})
	accordMustApply(t, aSep, fxSep.sre, "sre-vote", "vote", "srv1", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
	})
	// sec-res-early cannot expire at height 20 (ExpiresAtHeight=19 != ResolveByHeight=20) -> ErrAccordAuthority!
	accordReject(t, aSep, fxSep.security, "sec-res-early", "expire", "bad-exp", 20, ErrAccordAuthority, func(c *AccordCommand) {
		c.Expire = &ExpirePayload{ReasonHash: Hash("late")}
	})
	// Resolve at height 10 -> full-rollout must be missing "safety" role even though release had "safety" on propose grant!
	accordMustApply(t, aSep, fxSep.security, "sec-res-early", "resolve", "res-sep", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("done")}
	})
	out := aSep.View().Outcome
	if out.Phase != AccordPhaseDeadlocked || out.DeadlockReason != DeadlockNoThresholdMet {
		t.Fatalf("propose-only domain role leaked into voting mandatory role: %+v", out)
	}
	for _, tl := range out.Tallies {
		if tl.OptionID == "full-rollout" && !slices.Contains(tl.MissingRoles, "safety") {
			t.Fatalf("full-rollout should be missing safety role: %+v", tl)
		}
	}
	// Any new command after terminal state -> ErrAccordPhase!
	accordReject(t, aSep, fxSep.release, "rel-res-close", "expire", "after-term", 20, ErrAccordPhase, func(c *AccordCommand) {
		c.Expire = &ExpirePayload{ReasonHash: Hash("too-late")}
	})
}

func TestAccordAdversarialWeightsDeterminismAndVetoGuardBounds(t *testing.T) {
	// 1. Overflow, zero, and unreachable thresholds.
	badRules := []struct {
		name   string
		mutate func(*AccordSpec)
	}{
		{"uint64_wrap_weights", func(s *AccordSpec) {
			s.Roles[0].Weight = math.MaxUint64
			s.Roles[1].Weight = 1
		}},
		{"above_max_total_weight", func(s *AccordSpec) {
			s.Roles[0].Weight = maxAccordTotalWeight/2 + 1
			s.Roles[1].Weight = maxAccordTotalWeight / 2
		}},
		{"zero_voter_weight", func(s *AccordSpec) { s.Roles[0].Weight = 0 }},
		{"nonzero_nonvoter_weight", func(s *AccordSpec) {
			s.Roles[0].Permissions = []AccordPermission{AccordPermitResolve}
			s.Roles[0].Weight = 5
		}},
		{"zero_min_approval_count", func(s *AccordSpec) { s.Rules.MinApprovalCount = 0 }},
		{"zero_min_approval_weight", func(s *AccordSpec) { s.Rules.MinApprovalWeight = 0 }},
		{"min_part_count_gt_voters", func(s *AccordSpec) { s.Rules.MinParticipationCount = 99 }},
		{"min_part_weight_gt_total", func(s *AccordSpec) { s.Rules.MinParticipationWeight = 999 }},
		{"min_margin_gt_total", func(s *AccordSpec) { s.Rules.MinApprovalMarginWeight = 999 }},
		{"override_le_min_approval", func(s *AccordSpec) {
			s.Rules.Veto.Mode = VetoOverridable
			s.Rules.Veto.OverrideWeight = s.Rules.MinApprovalWeight
		}},
		{"override_gt_total", func(s *AccordSpec) {
			s.Rules.Veto.Mode = VetoOverridable
			s.Rules.Veto.OverrideWeight = 100
		}},
		{"max_vetoes_gt_max_options", func(s *AccordSpec) {
			s.Rules.Veto.MaxVetoesPerActor = maxAccordOptions + 1
		}},
		{"duplicate_mandatory_roles", func(s *AccordSpec) {
			s.Rules.MandatoryRoles = []RoleRequirement{
				{Role: "safety", MinApprovals: 1},
				{Role: "safety", MinApprovals: 1},
			}
		}},
		{"veto_grant_with_disallowed_domain_only", func(s *AccordSpec) {
			s.Rules.Veto.AllowedDomainRoles = []string{"security"} // only safety has AccordPermitVeto!
		}},
		{"dead_resolve_grant_expires_at_vote_by", func(s *AccordSpec) {
			s.Roles[0].ExpiresAtHeight = s.VoteByHeight
		}},
		{"max_events_below_min", func(s *AccordSpec) { s.MaxEvents = minAccordEvents - 1 }},
		{"max_events_above_max", func(s *AccordSpec) { s.MaxEvents = maxAccordEvents + 1 }},
		{"spec_exceeds_256kib", func(s *AccordSpec) {
			s.Options = nil
			for i := 0; i < maxAccordOptions; i++ {
				ps := cloneProtocolSpec(*newAccordFixture(t).spec.Options[0].Binding.ProtocolSpec)
				ps.Nonce = fmt.Sprintf("huge-%d-%s", i, strings.Repeat("x", 3500))
				ps.Purpose = strings.Repeat("p", 3500)
				ps.IntendedOutcome = strings.Repeat("o", 3500)
				s.Options = append(s.Options, AccordOption{
					ID: fmt.Sprintf("opt-%02d", i), Title: strings.Repeat("t", 3500),
					Binding: OptionBinding{Kind: BindingProtocolSpec, ProtocolSpec: &ps},
				})
			}
		}},
	}
	for _, tc := range badRules {
		t.Run("spec_"+tc.name, func(t *testing.T) {
			fx := newAccordFixture(t)
			tc.mutate(&fx.spec)
			if err := fx.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("%s: got %v want ErrAccordSpec", tc.name, err)
			}
		})
	}

	// 2. Margin underflow safety: DissentWeight (4) > ApproveWeight (2) with MinApprovalMarginWeight=1 must NOT wrap uint64!
	fxUnder := newAccordFixture(t)
	fxUnder.spec.Rules.MinParticipationCount = 2
	fxUnder.spec.Rules.MinParticipationWeight = 2
	fxUnder.spec.Rules.MinApprovalCount = 1
	fxUnder.spec.Rules.MinApprovalWeight = 2
	fxUnder.spec.Rules.MinApprovalMarginWeight = 1
	fxUnder.spec.Rules.MandatoryRoles = nil
	fxUnder.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
	fxUnder.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
	aUnder, err := NewAccord(fxUnder.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordMustApply(t, aUnder, fxUnder.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	})
	accordMustApply(t, aUnder, fxUnder.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotDissent, RationaleHash: Hash("r")}
	})
	accordMustApply(t, aUnder, fxUnder.safety, "safety-vote", "vote", "v3", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotDissent, RationaleHash: Hash("r")}
	})
	accordMustApply(t, aUnder, fxUnder.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("underflow-check")}
	})
	if aUnder.View().Phase != AccordPhaseDeadlocked || aUnder.View().Outcome.DeadlockReason != DeadlockNoThresholdMet {
		t.Fatalf("margin underflow bug! outcome=%+v", aUnder.View().Outcome)
	}
	// Verify deadlocked bundle is rejected by ALL downstream Authorize* helpers!
	deadB := aUnder.Bundle()
	deadID, deadHead := aUnder.View().ID, aUnder.View().Head
	if _, _, err := AuthorizeProtocolFromAccord(deadB, deadID, deadHead, fxUnder.canSpec); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("deadlocked bundle authorized protocol: %v", err)
	}
	if _, err := AuthorizeTaskFromAccord(deadB, deadID, deadHead, fxUnder.taskSpec); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("deadlocked bundle authorized task: %v", err)
	}
	if _, err := AuthorizeDispositionFromAccord(deadB, deadID, deadHead, "hold", Hash("hold-action"), Hash("hold-params")); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("deadlocked bundle authorized disposition: %v", err)
	}

	// 3. Overridable veto STILL enforces OptionGuard and MandatoryRoles!
	fxOver := newAccordFixture(t)
	patchH, _, _, _, _ := makeAdversarialHandoff(t, TaskIncomplete, false, 1, "config", "x", "")
	fxOver.spec.Roles = append(fxOver.spec.Roles, AccordRoleGrant{
		ID: "rel-att", Actor: fxOver.release.pub.ID(), Scope: fxOver.spec.Scope,
		Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
	})
	fxOver.spec.Evidence = []EvidenceSlot{{
		ID: "patch", Kind: EvidenceTaskHandoff, GoalID: patchH.Task.GoalID, TaskID: patchH.Task.ID(),
		ExpectedAuthority: patchH.Task.Authority.ID(), ExpectedResultHash: Hash(patchH.Result),
	}}
	fxOver.spec.Options[0].Guard = OptionGuard{AllOf: []EvidencePredicate{{EvidenceID: "patch", Op: GuardOutcomeIn, Outcomes: []TaskOutcome{TaskAccepted}}}}
	fxOver.spec.Rules.MinApprovalCount = 2
	fxOver.spec.Rules.MinApprovalWeight = 3
	fxOver.spec.Rules.MinApprovalMarginWeight = 0
	fxOver.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}}
	fxOver.spec.Rules.Veto = VetoPolicy{Mode: VetoOverridable, MaxVetoesPerActor: 1, OverrideWeight: 5, AllowedDomainRoles: []string{"safety"}}
	aOver, err := NewAccord(fxOver.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordMustApply(t, aOver, fxOver.release, "rel-att", "attest", "att", 1, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "patch", Handoff: &patchH}
	})
	accordMustApply(t, aOver, fxOver.safety, "safety-vote", "veto", "vt", 2, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("veto")}
	})
	// release(2)+sre(2)+security(1) = weight 5 overrides veto on full-rollout, BUT guard failed AND mandatory safety role missing!
	accordMustApply(t, aOver, fxOver.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	})
	accordMustApply(t, aOver, fxOver.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	})
	accordMustApply(t, aOver, fxOver.security, "security-vote", "vote", "v3", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	})
	accordMustApply(t, aOver, fxOver.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("r")}
	})
	overOut := aOver.View().Outcome
	if overOut.Phase != AccordPhaseDeadlocked {
		t.Fatalf("overridden veto bypassed guard/mandatory role: %+v", overOut)
	}
	for _, tl := range overOut.Tallies {
		if tl.OptionID == "full-rollout" {
			if !tl.VetoOverridden || tl.VetoEffective || tl.Eligible ||
				!slices.Equal(tl.DisqualificationReasons, []string{"guard_failed", "missing_mandatory_role"}) {
				t.Fatalf("unexpected tally on overridden veto with failed guard+role: %+v", tl)
			}
		}
	}

	// 4. Shuffled-order determinism: identical ballots/options applied in 6 permutations produce identical Tallies & winner!
	type ballotAction struct {
		actor accordActor
		grant string
		opt   string
		pos   BallotPosition
		req   string
	}
	fxDet := newAccordFixture(t)
	fxDet.spec.Rules.TieBreak = TieBreakFewestDissents
	fxDet.spec.Rules.MinApprovalCount = 1
	fxDet.spec.Rules.MinApprovalWeight = 2
	fxDet.spec.Rules.MinApprovalMarginWeight = 0
	fxDet.spec.Rules.MandatoryRoles = nil
	fxDet.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
	fxDet.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
	ballots := []ballotAction{
		{fxDet.release, "release-vote", "canary-rollout", BallotApprove, "b1"},
		{fxDet.sre, "sre-vote", "full-rollout", BallotApprove, "b2"},
		{fxDet.safety, "safety-vote", "full-rollout", BallotDissent, "b3"},
		{fxDet.security, "security-vote", "hold-release", BallotAbstain, "b4"},
	}
	perms := [][]int{
		{0, 1, 2, 3},
		{3, 2, 1, 0},
		{1, 3, 0, 2},
		{2, 0, 3, 1},
		{0, 2, 3, 1},
		{3, 0, 1, 2},
	}
	var baselineJSON []byte
	for pIdx, perm := range perms {
		specCopy := cloneAccordSpec(fxDet.spec)
		// Also rotate genesis option slice order across permutations!
		if pIdx%2 == 1 {
			slices.Reverse(specCopy.Options)
		}
		a, err := NewAccord(specCopy)
		if err != nil {
			t.Fatal(err)
		}
		for _, bi := range perm {
			b := ballots[bi]
			accordMustApply(t, a, b.actor, b.grant, "vote", b.req, 5, func(c *AccordCommand) {
				c.Vote = &VotePayload{OptionID: b.opt, Position: b.pos, RationaleHash: Hash(b.req)}
			})
		}
		accordMustApply(t, a, fxDet.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("det")}
		})
		o := a.View().Outcome
		if o.Phase != AccordPhaseDecided || o.WinningOptionID != "canary-rollout" {
			t.Fatalf("perm %v unexpected winner: %+v", perm, o)
		}
		// Compare complete tallies + winner + commitment + participation (excluding event-chain-dependent ReceiptHashes).
		canonical := struct {
			Phase   AccordPhase
			Winner  string
			Commit  string
			PCount  uint64
			PWeight uint64
			Tallies []OptionTally
		}{o.Phase, o.WinningOptionID, o.WinningCommitment, o.ParticipatingCount, o.ParticipatingWeight, o.Tallies}
		gotJSON, err := json.Marshal(canonical)
		if err != nil {
			t.Fatal(err)
		}
		if baselineJSON == nil {
			baselineJSON = gotJSON
		} else if !bytes.Equal(baselineJSON, gotJSON) {
			t.Fatalf("order-dependent tally divergence on perm %v:\ngot:  %s\nwant: %s", perm, gotJSON, baselineJSON)
		}
	}
}

func TestAccordAdversarialCallerAliasing(t *testing.T) {
	fx := newAccordFixture(t)
	acceptedH, _, _, _, _ := makeAdversarialHandoff(t, TaskAccepted, false, 1, "config", `{"max_attempts":3}`, "")
	fx.spec.Roles = append(fx.spec.Roles, AccordRoleGrant{
		ID: "rel-att", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
		Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
	})
	fx.spec.Evidence = []EvidenceSlot{{
		ID: "patch", Kind: EvidenceTaskHandoff, GoalID: acceptedH.Task.GoalID, TaskID: acceptedH.Task.ID(),
		ExpectedAuthority: acceptedH.Task.Authority.ID(), ExpectedResultHash: Hash(acceptedH.Result),
	}}
	fx.spec.Options[1].Guard = OptionGuard{
		AllOf: []EvidencePredicate{{EvidenceID: "patch", Op: GuardArtifactSlot, Outcomes: []TaskOutcome{TaskAccepted}, Slot: "config"}},
	}

	dir := filepath.Join(t.TempDir(), "alias")
	st, err := OpenAccordStore(dir, bytes.Repeat([]byte{91}, 32))
	if err != nil {
		t.Fatal(err)
	}
	specIn := cloneAccordSpec(fx.spec)
	id, err := st.Create(specIn)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate every input slice on specIn after Create.
	specIn.Participants[0].Signing[0] ^= 0xff
	specIn.Roles[0].DomainRoles[0] = "MUTATED"
	specIn.Roles[0].Permissions[0] = AccordPermitVeto
	specIn.Evidence[0].ID = "MUTATED"
	specIn.Options[1].Guard.AllOf[0].Slot = "MUTATED"
	specIn.Options[0].Binding.ProtocolSpec.Participants[0].Signing[0] ^= 0xff
	specIn.Rules.MandatoryRoles[0].Role = "MUTATED"
	specIn.Rules.Veto.AllowedDomainRoles[0] = "MUTATED"

	// Apply attest command, then mutate caller's Handoff & signature buffers!
	handoffIn := cloneTaskHandoff(acceptedH)
	attCmd, err := st.Prepare(id, fx.release.pub.ID(), "rel-att", fx.spec.Scope, "attest", "att-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	attCmd.Attest = &AttestPayload{EvidenceID: "patch", Handoff: &handoffIn}
	attSig, err := SignAccordCommand(fx.release.id, attCmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(id, attCmd, attSig, 1); err != nil {
		t.Fatal(err)
	}
	handoffIn.Result.Artifacts[0].Digest = Hash("CALLER-MUTATED")
	handoffIn.ClaimSignature[0] ^= 0xff
	attSig[0] ^= 0xff

	// Complete votes & resolve so Outcome is populated.
	for i, v := range []struct {
		a   accordActor
		g   string
		pos BallotPosition
	}{
		{fx.safety, "safety-vote", BallotApprove},
		{fx.sre, "sre-vote", BallotApprove},
		{fx.security, "security-vote", BallotApprove},
		{fx.release, "release-vote", BallotDissent},
	} {
		cmd, err := st.Prepare(id, v.a.pub.ID(), v.g, fx.spec.Scope, "vote", fmt.Sprintf("v-%d", i), 2)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: v.pos, RationaleHash: Hash(fmt.Sprintf("r-%d", i))}
		sig, err := SignAccordCommand(v.a.id, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Apply(id, cmd, sig, 2); err != nil {
			t.Fatal(err)
		}
	}
	resCmd, err := st.Prepare(id, fx.security.pub.ID(), "security-vote", fx.spec.Scope, "resolve", "res-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	resCmd.Resolve = &ResolvePayload{ReasonHash: Hash("ok")}
	resSig, err := SignAccordCommand(fx.security.id, resCmd)
	if err != nil {
		t.Fatal(err)
	}
	finalHead, err := st.Apply(id, resCmd, resSig, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Warm cache, mutate returned View AND Export bundle aggressively, then re-read and verify untouched!
	v1, err := st.View(id)
	if err != nil {
		t.Fatal(err)
	}
	origOutcomeHash := v1.Outcome.Hash()
	v1.Options[0].Option.Title = "MUTATED"
	v1.Evidence[0].Artifacts[0].Digest = "MUTATED"
	v1.Evidence[0].ArtifactRefs[0].Name = "MUTATED"
	v1.Votes[0].DomainRoles[0] = "MUTATED"
	v1.Outcome.Tallies[0].Approvers = []string{"MUTATED"}
	v1.Outcome.WinningOptionDissents[0].DomainRoles[0] = "MUTATED"
	v1.Outcome.WinningBinding.ProtocolSpec.Participants[0].Signing[0] ^= 0xff

	b1, err := st.Export(id)
	if err != nil {
		t.Fatal(err)
	}
	b1.Spec.Participants[0].Signing[0] ^= 0xff
	b1.Events[0].Signature[0] ^= 0xff

	v2, err := st.View(id)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Outcome.Hash() != origOutcomeHash {
		t.Fatal("returned View/Export aliased cached AccordStore state")
	}
	b2, err := st.Export(id)
	if err != nil {
		t.Fatal(err)
	}
	vOff, err := VerifyAccordBundle(b2, id, finalHead)
	if err != nil || vOff.Outcome.Hash() != origOutcomeHash {
		t.Fatalf("offline verification after caller mutations failed: %v", err)
	}
}

func TestAccordAdversarialOfflineBundleTampering(t *testing.T) {
	fx := newAccordFixture(t)
	acceptedH, _, _, _, _ := makeAdversarialHandoff(t, TaskAccepted, false, 1, "config", `{"max_attempts":3}`, "")
	_, auditB, _, _, _ := makeAdversarialHandoff(t, TaskRejected, true, 1, "audit", "finding", "")

	fx.spec.AllowProposals = true
	fx.spec.ProposalByHeight = 4
	fx.spec.Roles = append(fx.spec.Roles,
		AccordRoleGrant{
			ID: "rel-prop", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
			Permissions: []AccordPermission{AccordPermitPropose}, ExpiresAtHeight: 4, LimitsHash: Hash("p"),
		},
		AccordRoleGrant{
			ID: "rel-att", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
			Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
		},
	)
	fx.spec.Evidence = []EvidenceSlot{
		{
			ID: "patch", Kind: EvidenceTaskHandoff, GoalID: acceptedH.Task.GoalID, TaskID: acceptedH.Task.ID(),
			ExpectedAuthority: acceptedH.Task.Authority.ID(), ExpectedResultHash: Hash(acceptedH.Result),
		},
		{
			ID: "audit", Kind: EvidenceProtocolBundle, ProtocolID: Hash(auditB.Spec),
			ExpectedAuthority: auditB.Spec.Initiator, ExpectedHead: auditB.Events[len(auditB.Events)-1].ReceiptHash,
		},
	}
	fx.spec.Rules.Veto = VetoPolicy{
		Mode: VetoOverridable, MaxVetoesPerActor: 1, OverrideWeight: 5,
		RequireEvidence: true, AllowedDomainRoles: []string{"safety"},
	}
	fx.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}}

	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordMustApply(t, a, fx.release, "rel-prop", "propose", "p1", 1, func(c *AccordCommand) {
		c.Propose = &ProposePayload{Option: AccordOption{
			ID: "extra-opt", Title: "Dynamic option", Priority: 4,
			Binding: OptionBinding{Kind: BindingDisposition, Disposition: "remediate", ActionHash: Hash("rem")},
		}}
	})
	accordMustApply(t, a, fx.release, "rel-att", "attest", "a1", 2, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "patch", Handoff: &acceptedH}
	})
	accordMustApply(t, a, fx.release, "rel-att", "attest", "a2", 3, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "audit", Protocol: &auditB}
	})
	accordMustApply(t, a, fx.safety, "safety-vote", "veto", "vt1", 4, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "canary-rollout", ReasonHash: Hash("concern"), EvidenceIDs: []string{"audit"}}
	})
	accordMustApply(t, a, fx.safety, "safety-vote", "vote", "v0", 4, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotDissent, RationaleHash: Hash("dissent")}
	})
	accordMustApply(t, a, fx.release, "release-vote", "vote", "v1", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok1")}
	})
	accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v2", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok2")}
	})
	accordMustApply(t, a, fx.security, "security-vote", "vote", "v3", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("ok3")}
	})
	finalHead := accordMustApply(t, a, fx.security, "security-vote", "resolve", "res1", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("resolved")}
	})
	accordID := a.View().ID

	// Round-trip via JSON (pure offline verification, zero private keys/store).
	raw, err := json.Marshal(a.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	var clean AccordBundle
	if err := json.Unmarshal(raw, &clean); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccordBundle(clean, accordID, finalHead); err != nil {
		t.Fatalf("clean bundle failed VerifyAccordBundle: %v", err)
	}

	cloneBundle := func() AccordBundle {
		var out AccordBundle
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	tampers := []struct {
		name   string
		mutate func(*AccordBundle)
	}{
		{"spec_nonce", func(b *AccordBundle) { b.Spec.Nonce = "tampered" }},
		{"spec_purpose", func(b *AccordBundle) { b.Spec.Purpose = "tampered" }},
		{"spec_scope", func(b *AccordBundle) { b.Spec.Scope = "tampered" }},
		{"spec_policy_hash", func(b *AccordBundle) { b.Spec.PolicyHash = Hash("tampered") }},
		{"spec_vote_by_height", func(b *AccordBundle) { b.Spec.VoteByHeight++ }},
		{"spec_resolve_by_height", func(b *AccordBundle) { b.Spec.ResolveByHeight++ }},
		{"spec_max_events", func(b *AccordBundle) { b.Spec.MaxEvents++ }},
		{"spec_participant_key", func(b *AccordBundle) { b.Spec.Participants[0].Signing[0] ^= 1 }},
		{"spec_role_weight", func(b *AccordBundle) { b.Spec.Roles[0].Weight++ }},
		{"spec_rule_min_weight", func(b *AccordBundle) { b.Spec.Rules.MinApprovalWeight-- }},
		{"spec_option_priority", func(b *AccordBundle) { b.Spec.Options[0].Priority = 99 }},
		{"event_propose_title", func(b *AccordBundle) { b.Events[0].Command.Propose.Option.Title = "tampered" }},
		{"event_attest_handoff_digest", func(b *AccordBundle) { b.Events[1].Command.Attest.Handoff.Result.Artifacts[0].Digest = Hash("x") }},
		{"event_attest_bundle_sig", func(b *AccordBundle) { b.Events[2].Command.Attest.Protocol.Events[0].Signature[0] ^= 1 }},
		{"event_veto_reason", func(b *AccordBundle) { b.Events[3].Command.Veto.ReasonHash = Hash("tampered") }},
		{"event_vote_position", func(b *AccordBundle) { b.Events[4].Command.Vote.Position = BallotApprove }},
		{"event_vote_rationale", func(b *AccordBundle) { b.Events[5].Command.Vote.RationaleHash = Hash("tampered") }},
		{"event_resolve_reason", func(b *AccordBundle) { b.Events[len(b.Events)-1].Command.Resolve.ReasonHash = Hash("tampered") }},
		{"event_height", func(b *AccordBundle) { b.Events[5].Command.Height++ }},
		{"event_request_id", func(b *AccordBundle) { b.Events[5].Command.RequestID = "tampered" }},
		{"event_signature", func(b *AccordBundle) { b.Events[5].Signature[0] ^= 1 }},
		{"event_receipt_hash", func(b *AccordBundle) { b.Events[5].ReceiptHash = Hash("tampered") }},
		{"truncate_last_event", func(b *AccordBundle) { b.Events = b.Events[:len(b.Events)-1] }},
		{"drop_first_event", func(b *AccordBundle) { b.Events = b.Events[1:] }},
		{"duplicate_event_stuffed", func(b *AccordBundle) { b.Events = append(b.Events, b.Events[len(b.Events)-1]) }},
		{"swap_two_events", func(b *AccordBundle) { b.Events[5], b.Events[6] = b.Events[6], b.Events[5] }},
	}
	for _, tc := range tampers {
		t.Run(tc.name, func(t *testing.T) {
			b := cloneBundle()
			tc.mutate(&b)
			if _, err := VerifyAccordBundle(b, accordID, finalHead); err == nil {
				t.Fatalf("tamper %s was NOT rejected by VerifyAccordBundle", tc.name)
			}
		})
	}

	// Also reject invalid or mismatched pins.
	for _, pins := range [][2]string{
		{"", finalHead},
		{accordID, ""},
		{"not-hex", finalHead},
		{accordID, "not-hex"},
		{Hash("other-accord"), finalHead},
		{accordID, Hash("other-head")},
		{accordID, accordID}, // genesis head != finalHead
	} {
		if _, err := VerifyAccordBundle(clean, pins[0], pins[1]); err == nil {
			t.Fatalf("VerifyAccordBundle ignored pins %v", pins)
		}
	}
}

func TestAccordAdversarialStoreDurabilityCacheAndConcurrency(t *testing.T) {
	fx := newAccordFixture(t)
	dir := filepath.Join(t.TempDir(), "accords-adv")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	st, err := OpenAccordStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.Create(fx.spec)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Failed command MUST NOT consume (Actor, RequestID): fail at wrong height, then succeed with same RequestID!
	badCmd, err := st.Prepare(id, fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", "reusable-on-fail", 10) // >= VoteByHeight!
	if err != nil {
		t.Fatal(err)
	}
	badCmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
	badSig, err := SignAccordCommand(fx.sre.id, badCmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(id, badCmd, badSig, 10); !errors.Is(err, ErrAccordPhase) {
		t.Fatalf("late vote got %v want ErrAccordPhase", err)
	}
	goodCmd := badCmd
	goodCmd.Height = 2
	goodSig, err := SignAccordCommand(fx.sre.id, goodCmd)
	if err != nil {
		t.Fatal(err)
	}
	head1, err := st.Apply(id, goodCmd, goodSig, 2)
	if err != nil {
		t.Fatalf("failed command consumed RequestID: %v", err)
	}

	// 2. Crash hooks across ALL 4 stages: after-write, before-rename (not committed), after-rename, after-sync (ErrCommitUncertain).
	for i, stage := range []string{"after-write", "before-rename", "after-rename", "after-sync"} {
		t.Run("crash_"+stage, func(t *testing.T) {
			cDir := filepath.Join(t.TempDir(), "crash-"+stage)
			cStore, err := OpenAccordStore(cDir, key)
			if err != nil {
				t.Fatal(err)
			}
			cid, err := cStore.Create(fx.spec)
			if err != nil {
				t.Fatal(err)
			}
			// Warm cache.
			if _, err := cStore.View(cid); err != nil {
				t.Fatal(err)
			}
			cmd, err := cStore.Prepare(cid, fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", fmt.Sprintf("crash-%d", i), 2)
			if err != nil {
				t.Fatal(err)
			}
			cmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
			sig, err := SignAccordCommand(fx.sre.id, cmd)
			if err != nil {
				t.Fatal(err)
			}
			cStore.store.commitHook = func(s string) error {
				if s == stage {
					return errors.New("injected-" + stage)
				}
				return nil
			}
			_, err = cStore.Apply(cid, cmd, sig, 2)
			cStore.store.commitHook = nil
			uncertain := stage == "after-rename" || stage == "after-sync"
			if err == nil || errors.Is(err, ErrCommitUncertain) != uncertain {
				t.Fatalf("stage %s: err=%v uncertain=%v", stage, err, uncertain)
			}
			reopened, err := OpenAccordStore(cDir, key)
			if err != nil {
				t.Fatal(err)
			}
			vBeforeRetry, err := reopened.View(cid)
			if err != nil {
				t.Fatal(err)
			}
			if uncertain && len(vBeforeRetry.Votes) != 1 {
				t.Fatalf("stage %s: committed vote lost after reopen", stage)
			}
			if !uncertain && len(vBeforeRetry.Votes) != 0 {
				t.Fatalf("stage %s: uncommitted vote leaked", stage)
			}
			// Exact retry resolves cleanly in BOTH cases with zero duplicate votes!
			h, err := reopened.Apply(cid, cmd, sig, 2)
			if err != nil {
				t.Fatalf("stage %s: exact retry failed: %v", stage, err)
			}
			vAfter, err := reopened.View(cid)
			if err != nil || len(vAfter.Votes) != 1 || vAfter.Head != h {
				t.Fatalf("stage %s: post-retry state corrupted: %+v", stage, vAfter)
			}
		})
	}

	// 3. Corrupt disk states: wrong key, bad header, truncated file, relocated checkpoint (AAD),
	//    in-place same-inode/size/mtime ciphertext tamper, AND authenticated plaintext tamper failing replay-on-load!
	cpPath := st.store.path(id)
	origCipher, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	origInfo, err := os.Lstat(cpPath)
	if err != nil {
		t.Fatal(err)
	}

	// Warm cache first!
	if _, err := st.View(id); err != nil {
		t.Fatal(err)
	}

	// Wrong key -> ErrCorruptStore.
	wrongKey := bytes.Clone(key)
	wrongKey[0] ^= 1
	wrongStore, err := OpenAccordStore(dir, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongStore.View(id); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("wrong key got %v want ErrCorruptStore", err)
	}

	// Checkpoint relocation (copy id.nex -> otherID.nex) -> AAD failure -> ErrCorruptStore.
	otherID := Hash("relocated-accord")
	if err := os.WriteFile(st.store.path(otherID), origCipher, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.View(otherID); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("relocated checkpoint got %v want ErrCorruptStore", err)
	}

	// In-place ciphertext tamper preserving exact inode, size, and mtime while cache is warm!
	tampered := bytes.Clone(origCipher)
	tampered[len(tampered)-1] ^= 0xff
	fh, err := os.OpenFile(cpPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteAt(tampered, 0); err != nil {
		fh.Close()
		t.Fatal(err)
	}
	_ = fh.Sync()
	_ = fh.Close()
	_ = os.Chtimes(cpPath, origInfo.ModTime(), origInfo.ModTime())
	if _, err := st.View(id); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("in-place same-inode/mtime ciphertext tamper got %v want ErrCorruptStore", err)
	}

	// Truncated file -> ErrCorruptStore.
	if err := os.WriteFile(cpPath, origCipher[:12], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.View(id); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("truncated file got %v want ErrCorruptStore", err)
	}

	// Bad storeHeader -> ErrStoreVersion.
	badHdr := bytes.Clone(origCipher)
	badHdr[0] ^= 1
	if err := os.WriteFile(cpPath, badHdr, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.View(id); !errors.Is(err, ErrStoreVersion) {
		t.Fatalf("bad header got %v want ErrStoreVersion", err)
	}

	// Restore valid checkpoint, then test AUTHENTICATED plaintext tampering failing replay-on-load!
	if err := os.WriteFile(cpPath, origCipher, 0600); err != nil {
		t.Fatal(err)
	}
	validPlain, err := st.store.readEncrypted(id)
	if err != nil {
		t.Fatal(err)
	}
	var validRec storedAccord
	if err := json.Unmarshal(validPlain, &validRec); err != nil {
		t.Fatal(err)
	}
	diskTampers := []struct {
		name   string
		mutate func(*storedAccord)
	}{
		{"wrong_wrapper_version", func(r *storedAccord) { r.Version = 99 }},
		{"wrong_head", func(r *storedAccord) { r.Head = Hash("fake-head") }},
		{"tampered_event_sig", func(r *storedAccord) { r.Bundle.Events[0].Signature[0] ^= 1 }},
		{"tampered_event_receipt", func(r *storedAccord) { r.Bundle.Events[0].ReceiptHash = Hash("fake") }},
		{"dropped_event_mismatched_head", func(r *storedAccord) { r.Bundle.Events = nil }},
		{"tampered_spec_purpose", func(r *storedAccord) { r.Bundle.Spec.Purpose = "rewritten" }},
	}
	for _, tc := range diskTampers {
		t.Run("disk_"+tc.name, func(t *testing.T) {
			var rec storedAccord
			if err := json.Unmarshal(validPlain, &rec); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&rec)
			if err := st.store.write(id, rec); err != nil {
				t.Fatal(err)
			}
			if _, err := st.View(id); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("authenticated disk tamper %s got %v want ErrCorruptStore", tc.name, err)
			}
		})
	}

	// Authenticated invalid-UTF-8 raw plaintext bytes -> ErrCorruptStore!
	nonce := make([]byte, st.store.aead.NonceSize())
	_, _ = rand.Read(nonce)
	rawBadUTF8 := append([]byte(storeHeader), nonce...)
	rawBadUTF8 = st.store.aead.Seal(rawBadUTF8, nonce, []byte(`{"version":1,"bad":"\xff"}`[:16]+"\xff}"), []byte(storeHeader+"/"+id))
	if err := os.WriteFile(cpPath, rawBadUTF8, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.View(id); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("authenticated non-UTF-8 plaintext got %v want ErrCorruptStore", err)
	}

	// Restore original checkpoint and confirm exact retry still recovers head1 cleanly!
	if err := os.WriteFile(cpPath, origCipher, 0600); err != nil {
		t.Fatal(err)
	}
	gotRetry, err := st.Apply(id, goodCmd, goodSig, 2)
	if err != nil || gotRetry != head1 {
		t.Fatalf("recovery after restoring valid checkpoint: head=%s err=%v", gotRetry, err)
	}

	// 4. >256-entry cache eviction boundary + compaction + reload of evicted accord!
	evictDir := filepath.Join(t.TempDir(), "evict")
	evictStore, err := OpenAccordStore(evictDir, key)
	if err != nil {
		t.Fatal(err)
	}
	const totalAccords = maxCachedAccords + 64
	evictIDs := make([]string, 0, totalAccords)
	for i := 0; i < totalAccords; i++ {
		s := cloneAccordSpec(fx.spec)
		s.Nonce = fmt.Sprintf("evict-%04d", i)
		aid, err := evictStore.Create(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := evictStore.View(aid); err != nil {
			t.Fatal(err)
		}
		evictIDs = append(evictIDs, aid)
	}
	// Mutate several accords repeatedly to drive cache invalidation + cacheOrder compaction (> 2*256).
	for round := 0; round < 3; round++ {
		for j := 0; j < 100; j++ {
			aid := evictIDs[j]
			if _, err := evictStore.View(aid); err != nil {
				t.Fatal(err)
			}
		}
	}
	evictStore.mu.Lock()
	cLen, oLen := len(evictStore.cache), len(evictStore.cacheOrder)
	evictStore.mu.Unlock()
	if cLen > maxCachedAccords || oLen > maxCachedAccords*2 {
		t.Fatalf("cache bounds exceeded after churn: cache=%d order=%d", cLen, oLen)
	}
	// Reload earliest evicted accord cleanly.
	vOld, err := evictStore.View(evictIDs[0])
	if err != nil || vOld.ID != evictIDs[0] {
		t.Fatalf("evicted accord reload failed: %+v %v", vOld, err)
	}

	// 5. Concurrent multi-handle mutations, exact retries, and conflicting commands against the same head under -race!
	raceDir := filepath.Join(t.TempDir(), "race")
	raceStore, err := OpenAccordStore(raceDir, key)
	if err != nil {
		t.Fatal(err)
	}
	rid, err := raceStore.Create(fx.spec)
	if err != nil {
		t.Fatal(err)
	}
	sharedVote, err := raceStore.Prepare(rid, fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", "race-retry", 2)
	if err != nil {
		t.Fatal(err)
	}
	sharedVote.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("race")}
	sharedSig, err := SignAccordCommand(fx.sre.id, sharedVote)
	if err != nil {
		t.Fatal(err)
	}
	// Competing command against the SAME initial head by another actor!
	competingVote, err := raceStore.Prepare(rid, fx.safety.pub.ID(), "safety-vote", fx.spec.Scope, "vote", "race-compete", 2)
	if err != nil {
		t.Fatal(err)
	}
	competingVote.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("compete")}
	competingSig, err := SignAccordCommand(fx.safety.id, competingVote)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	sharedHeads := make(chan string, 10)
	sharedErrs := make(chan error, 10)
	competeErrs := make(chan error, 4)

	for i := 0; i < 10; i++ {
		h, err := OpenAccordStore(raceDir, key)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(store *AccordStore) {
			defer wg.Done()
			head, err := store.Apply(rid, sharedVote, sharedSig, 2)
			sharedHeads <- head
			sharedErrs <- err
		}(h)
	}
	for i := 0; i < 4; i++ {
		h, err := OpenAccordStore(raceDir, key)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(store *AccordStore) {
			defer wg.Done()
			_, err := store.Apply(rid, competingVote, competingSig, 2)
			competeErrs <- err
		}(h)
	}
	for i := 0; i < 6; i++ {
		h, err := OpenAccordStore(raceDir, key)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(store *AccordStore) {
			defer wg.Done()
			_, _ = store.View(rid)
			_, _ = store.Export(rid)
		}(h)
	}
	wg.Wait()
	close(sharedHeads)
	close(sharedErrs)
	close(competeErrs)

	// Either sharedVote won the genesis head (all 10 exact retries succeed with identical head, all 4 competing get ErrAccordStale)
	// OR competingVote won the genesis head (all 4 competing retries succeed, all 10 shared get ErrAccordStale)!
	sharedOK, competeOK := 0, 0
	var seenSharedHead string
	for err := range sharedErrs {
		h := <-sharedHeads
		if err == nil {
			sharedOK++
			if seenSharedHead == "" {
				seenSharedHead = h
			} else if seenSharedHead != h {
				t.Fatalf("concurrent exact retries diverged: %s vs %s", seenSharedHead, h)
			}
		} else if !errors.Is(err, ErrAccordStale) {
			t.Fatalf("unexpected shared error: %v", err)
		}
	}
	for err := range competeErrs {
		if err == nil {
			competeOK++
		} else if !errors.Is(err, ErrAccordStale) {
			t.Fatalf("unexpected competing error: %v", err)
		}
	}
	if !((sharedOK == 10 && competeOK == 0) || (sharedOK == 0 && competeOK == 4)) {
		t.Fatalf("CAS/retry invariant broken under concurrency: sharedOK=%d competeOK=%d", sharedOK, competeOK)
	}
	finalV, err := raceStore.View(rid)
	if err != nil || len(finalV.Votes) != 1 {
		t.Fatalf("expected exactly 1 committed vote after race, got %+v err=%v", finalV, err)
	}
}
