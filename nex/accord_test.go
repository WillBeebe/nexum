package nex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

type accordActor struct {
	id  Identity
	pub Public
}

func newAccordActor(t *testing.T) accordActor {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := id.Public()
	if err != nil {
		t.Fatal(err)
	}
	return accordActor{id: id, pub: pub}
}

type accordFixture struct {
	release  accordActor
	sre      accordActor
	safety   accordActor
	security accordActor
	spec     AccordSpec
	fullSpec ProtocolSpec
	canSpec  ProtocolSpec
	taskSpec TaskSpec
	goalID   string
}

func makeDownstreamProtocolSpec(t *testing.T, owner, worker, witness accordActor, nonce, scope string) ProtocolSpec {
	t.Helper()
	grant := func(id string, actor accordActor, perms ...ProtocolPermission) RoleGrant {
		return RoleGrant{
			ID: id, Actor: actor.pub.ID(), Label: id, Scope: scope, Permissions: perms,
			ExpiresAtHeight: 40, LimitsHash: Hash(scope + ":" + id), EvidenceObligation: Hash("evidence"),
		}
	}
	return ProtocolSpec{
		Version: ProtocolVersionV2, Nonce: nonce, Purpose: "Execute " + nonce, IntendedOutcome: "Completed " + nonce,
		Scope: scope, SpecificationHash: Hash("spec:" + nonce), AcceptanceHash: Hash("acc:" + nonce),
		FailurePolicyHash: Hash("fail:" + nonce), Initiator: owner.pub.ID(),
		Participants: []Public{owner.pub, worker.pub, witness.pub},
		Roles: []RoleGrant{
			grant("owner", owner, PermitCommit, PermitDecide, PermitReturn),
			grant("worker", worker, PermitWork, PermitReturn),
			grant("witness", witness, PermitReview),
		},
		WorkByHeight: 20, ReturnByHeight: 40,
		RequiredWitnesses: []string{witness.pub.ID()}, DissentPolicy: "record", MaxEvents: 16,
		Return: ReturnRequirements{
			SuccessArtifacts: []string{"report"}, FailureArtifacts: []string{"failure"},
			AllowedDisposition: []string{"continue", "retry", "refuse"}, AllowSuccessors: true,
		},
	}
}

func newAccordFixture(t *testing.T) accordFixture {
	t.Helper()
	release := newAccordActor(t)
	sre := newAccordActor(t)
	safety := newAccordActor(t)
	security := newAccordActor(t)

	fullSpec := makeDownstreamProtocolSpec(t, release, sre, safety, "full-rollout-v2", "release/full")
	canSpec := makeDownstreamProtocolSpec(t, release, sre, safety, "canary-rollout-v2", "release/canary")
	goal := GoalSpec{
		Nonce: "release-goal", Purpose: "Release governance", ConstraintsHash: Hash("c"),
		CompletionPolicyHash: Hash("p"), Planners: []Public{release.pub},
	}
	taskSpec := TaskSpec{
		GoalID: goal.ID(), Nonce: "remediate-rollback", Purpose: "Verify staging rollback", Scope: "release/remediate",
		SpecificationHash: Hash("spec"), AcceptanceHash: Hash("acc"), FailurePolicyHash: Hash("fail"),
		Authority: safety.pub, Outputs: []string{"rollback-proof"},
	}

	spec := AccordSpec{
		Version:    AccordVersion,
		Nonce:      "release-accord-1",
		Purpose:    "Choose release strategy based on verified upstream handoffs",
		Scope:      "release/v2",
		PolicyHash: Hash("release-policy-v1"),
		Participants: []Public{
			release.pub, sre.pub, safety.pub, security.pub,
		},
		Roles: []AccordRoleGrant{
			{
				ID: "release-vote", Actor: release.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"release"}, Permissions: []AccordPermission{AccordPermitVote, AccordPermitResolve},
				Weight: 2, ExpiresAtHeight: 20, LimitsHash: Hash("release-limits"),
			},
			{
				ID: "sre-vote", Actor: sre.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"sre"}, Permissions: []AccordPermission{AccordPermitVote},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: Hash("sre-limits"),
			},
			{
				ID: "safety-vote", Actor: safety.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"safety"}, Permissions: []AccordPermission{AccordPermitVote, AccordPermitVeto},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: Hash("safety-limits"),
			},
			{
				ID: "security-vote", Actor: security.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"security"}, Permissions: []AccordPermission{AccordPermitVote, AccordPermitResolve},
				Weight: 1, ExpiresAtHeight: 20, LimitsHash: Hash("security-limits"),
			},
		},
		Options: []AccordOption{
			{
				ID: "full-rollout", Title: "Full production rollout", Priority: 1,
				Binding: OptionBinding{Kind: BindingProtocolSpec, ProtocolSpec: &fullSpec},
			},
			{
				ID: "canary-rollout", Title: "Canary rollout with safety gates", Priority: 2,
				Binding: OptionBinding{Kind: BindingProtocolSpec, ProtocolSpec: &canSpec},
			},
			{
				ID: "hold-release", Title: "Hold release and remediate", Priority: 3,
				Binding: OptionBinding{
					Kind: BindingDisposition, Disposition: "hold",
					ActionHash: Hash("hold-action"), ParametersHash: Hash("hold-params"),
				},
			},
		},
		VoteByHeight:    10,
		ResolveByHeight: 20,
		Rules: DecisionRules{
			BallotMode:              BallotApproval,
			MinParticipationCount:   3,
			MinParticipationWeight:  5,
			MinApprovalCount:        2,
			MinApprovalWeight:       4,
			MinApprovalMarginWeight: 1,
			MandatoryRoles:          []RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}},
			Veto: VetoPolicy{
				Mode:               VetoBlocking,
				MaxVetoesPerActor:  1,
				AllowedDomainRoles: []string{"safety"},
			},
			TieBreak: TieBreakLowestPriority,
		},
		MaxEvents: 64,
	}

	return accordFixture{
		release: release, sre: sre, safety: safety, security: security,
		spec: spec, fullSpec: fullSpec, canSpec: canSpec, taskSpec: taskSpec, goalID: goal.ID(),
	}
}

func accordMustApply(t *testing.T, a *Accord, actor accordActor, grant, action, reqID string, height uint64, fill func(*AccordCommand)) string {
	t.Helper()
	cmd := a.Prepare(actor.pub.ID(), grant, a.spec.Scope, action, reqID, height)
	if fill != nil {
		fill(&cmd)
	}
	sig, err := SignAccordCommand(actor.id, cmd)
	if err != nil {
		t.Fatalf("SignAccordCommand(%s/%s): %v", action, reqID, err)
	}
	head, err := a.Apply(cmd, sig, height)
	if err != nil {
		t.Fatalf("Apply(%s/%s): %v", action, reqID, err)
	}
	return head
}

func accordReject(t *testing.T, a *Accord, actor accordActor, grant, action, reqID string, height uint64, want error, fill func(*AccordCommand)) {
	t.Helper()
	before := a.Bundle()
	cmd := a.Prepare(actor.pub.ID(), grant, a.spec.Scope, action, reqID, height)
	if fill != nil {
		fill(&cmd)
	}
	sig := Sign(actor.id, AccordCommandDomain, cmd)
	_, err := a.Apply(cmd, sig, height)
	if err == nil || (want != nil && !errors.Is(err, want)) {
		t.Fatalf("Apply(%s/%s) got %v, want %v", action, reqID, err, want)
	}
	if Hash(before) != Hash(a.Bundle()) {
		t.Fatalf("rejected command %s/%s mutated accord state", action, reqID)
	}
}

func makeHandoffWithOptions(t *testing.T, outcome TaskOutcome, witnessDissent bool, slotName, content string) (TaskHandoff, ProtocolBundle, accordActor) {
	t.Helper()
	f := newProtocolFixture(t)
	f.spec.Version = ProtocolVersionV2
	f.spec.Return.SuccessArtifacts = []string{slotName}
	f.spec.Return.FailureArtifacts = []string{slotName}
	f.spec.DissentPolicy = "record"

	owner := protocolPublic(f.owner)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{61}, 32)
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
		Nonce: "ev-goal-" + slotName, Purpose: "Produce verified evidence",
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
	f.spec.TaskID = task.ID()
	f.spec.Generation = 1
	p, err := NewProtocol(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	claim := ClaimRequest{
		GoalID: goalID, TaskID: task.ID(), WorkerID: protocolPublic(f.worker).ID(),
		RequestID: "claim-1", ProtocolID: p.View().ID, LeaseUntilHeight: 41,
	}
	claimSig := Sign(f.owner, ClaimSignatureDomain, claim)
	lease, err := tasks.Claim(claim, claimSig, f.spec, 1)
	if err != nil {
		t.Fatal(err)
	}

	artRef := testArtifactRef(content)
	switch outcome {
	case TaskIncomplete:
		protocolApply(t, p, f.owner, "", "admit", nil)
		cmd := p.Prepare(owner.ID(), "owner", f.spec.Scope, "incomplete", "inc-1", f.spec.ReturnByHeight)
		cmd.Incomplete = &IncompleteReturn{
			ReasonHash: Hash("witness unavailable"),
			Artifacts:  []NamedArtifact{{Name: slotName, Ref: artRef}},
		}
		if _, err := p.Apply(cmd, Sign(f.owner, "protocol", cmd), cmd.Height); err != nil {
			t.Fatal(err)
		}
	case TaskAccepted:
		p = enterProtocol(t, f)
		protocolApply(t, p, f.worker, "worker", "report", func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("done"), Evidence: []string{artRef.Digest},
				Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: slotName, Ref: artRef}}},
			}
		})
		reviewProtocol(t, p, f, witnessDissent)
		resolveProtocol(t, p, f, "accept")
		protocolApply(t, p, f.worker, "worker", "return", func(c *ProtocolCommand) {
			v := p.View()
			c.Return = &ReturnManifest{
				ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews),
				Evidence: []string{artRef.Digest}, Uncertainty: "checked fixture",
				SafeAssumptions: []string{"bounded"}, Disposition: "continue",
				Artifacts: []ReturnArtifact{{ID: slotName, Commitment: artRef.Digest, ReuseRestrictions: "cite"}},
			}
		})
	case TaskRejected:
		p = enterProtocol(t, f)
		protocolApply(t, p, f.worker, "worker", "report", func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome: WorkFailedSafely, Stage: "work", ReasonHash: Hash("failed safely"), Evidence: []string{artRef.Digest},
				Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: slotName, Ref: artRef}}},
			}
		})
		reviewProtocol(t, p, f, witnessDissent)
		resolveProtocol(t, p, f, "reject")
		protocolApply(t, p, f.owner, "owner", "return", func(c *ProtocolCommand) {
			v := p.View()
			c.Return = &ReturnManifest{
				ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews),
				Evidence: []string{artRef.Digest}, Uncertainty: "failure evidence preserved",
				SafeAssumptions: []string{"retry requires fresh consent"}, Disposition: "retry",
				Artifacts: []ReturnArtifact{{ID: slotName, Commitment: artRef.Digest, ReuseRestrictions: "diagnostic"}},
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
	return h, p.Bundle(), accordActor{id: f.witness, pub: protocolPublic(f.witness)}
}

func TestAccordEvidenceGatedLifecycleAndBindings(t *testing.T) {
	fx := newAccordFixture(t)
	patchH, _, patchWit := makeHandoffWithOptions(t, TaskAccepted, false, "config", `{"max_attempts":3}`)
	safetyH, _, _ := makeHandoffWithOptions(t, TaskIncomplete, false, "observation", "no staging rollback")
	_, auditBundle, auditWit := makeHandoffWithOptions(t, TaskRejected, true, "audit", "finding-1")

	fx.spec.Roles = append(fx.spec.Roles, AccordRoleGrant{
		ID: "release-attest", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
		Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("attest"),
	})
	fx.spec.Evidence = []EvidenceSlot{
		{
			ID: "patch", Kind: EvidenceTaskHandoff,
			GoalID: patchH.Task.GoalID, TaskID: patchH.Task.ID(),
			ExpectedAuthority: patchH.Task.Authority.ID(), ExpectedResultHash: Hash(patchH.Result), MinGeneration: 1,
		},
		{
			ID: "safety", Kind: EvidenceTaskHandoff,
			GoalID: safetyH.Task.GoalID, TaskID: safetyH.Task.ID(),
			ExpectedAuthority: safetyH.Task.Authority.ID(), RequiredAttester: fx.release.pub.ID(),
		},
		{
			ID: "audit", Kind: EvidenceProtocolBundle,
			ProtocolID: Hash(auditBundle.Spec), ExpectedAuthority: auditBundle.Spec.Initiator,
			ExpectedHead: auditBundle.Events[len(auditBundle.Events)-1].ReceiptHash,
		},
	}
	fx.spec.Rules.Veto.RequireEvidence = true

	// full-rollout requires safety=accepted + no witness dissent -> fails on incomplete safety!
	fx.spec.Options[0].Guard = OptionGuard{
		AllOf: []EvidencePredicate{
			{EvidenceID: "patch", Op: GuardArtifactSlot, Outcomes: []TaskOutcome{TaskAccepted}, Slot: "config", Digest: patchH.Result.Artifacts[0].Digest},
			{EvidenceID: "patch", Op: GuardNoWitnessDissent},
			{EvidenceID: "patch", Op: GuardWitnessApproved, ActorID: patchWit.pub.ID()},
			{EvidenceID: "patch", Op: GuardMinGeneration, MinGeneration: 1},
			{EvidenceID: "safety", Op: GuardOutcomeIn, Outcomes: []TaskOutcome{TaskAccepted}},
			{EvidenceID: "safety", Op: GuardNoWitnessDissent},
		},
	}
	// canary-rollout requires patch accepted + witness/authority/disposition + (safety incomplete OR audit dissent)
	fx.spec.Options[1].Guard = OptionGuard{
		AllOf: []EvidencePredicate{
			{EvidenceID: "patch", Op: GuardAttested},
			{EvidenceID: "patch", Op: GuardAuthorityMatch, ActorID: patchH.Task.Authority.ID()},
			{EvidenceID: "patch", Op: GuardParticipantPresent, ActorID: patchWit.pub.ID()},
			{EvidenceID: "patch", Op: GuardDispositionIn, Dispositions: []string{"continue"}},
		},
		AnyOf: []EvidencePredicate{
			{EvidenceID: "safety", Op: GuardOutcomeIn, Outcomes: []TaskOutcome{TaskIncomplete}},
			{EvidenceID: "audit", Op: GuardHasWitnessDissent},
		},
	}
	fx.spec.Options[1].ExtraMandatoryRoles = []RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}}

	// hold-release requires audit witness reviewed + dissent + rejected artifact slot
	fx.spec.Options[2].Guard = OptionGuard{
		AllOf: []EvidencePredicate{
			{EvidenceID: "audit", Op: GuardWitnessReviewed, ActorID: auditWit.pub.ID()},
			{EvidenceID: "audit", Op: GuardHasWitnessDissent},
			{EvidenceID: "audit", Op: GuardArtifactSlot, Outcomes: []TaskOutcome{TaskRejected}, Slot: "audit"},
		},
	}

	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatalf("NewAccord: %v", err)
	}
	if got := a.View().StageAt(1); got != "voting" {
		t.Fatalf("StageAt(1)=%q want voting", got)
	}
	if got := a.View().StageAt(0); got != "invalid" {
		t.Fatalf("StageAt(0)=%q want invalid", got)
	}

	// Attest all three evidence slots.
	accordMustApply(t, a, fx.release, "release-attest", "attest", "att-patch", 1, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "patch", Handoff: &patchH}
	})
	accordMustApply(t, a, fx.release, "release-attest", "attest", "att-safety", 2, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "safety", Handoff: &safetyH}
	})
	accordMustApply(t, a, fx.release, "release-attest", "attest", "att-audit", 3, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "audit", Protocol: &auditBundle}
	})

	// Duplicate attestation rejected with ErrAccordPhase.
	accordReject(t, a, fx.release, "release-attest", "attest", "att-patch-dup", 3, ErrAccordPhase, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "patch", Handoff: &patchH}
	})

	guards := a.EvaluateGuards()
	guardByID := map[string]OptionGuardStatus{}
	for _, g := range guards {
		guardByID[g.OptionID] = g
	}
	if guardByID["full-rollout"].Passed {
		t.Fatalf("full-rollout should fail guard on incomplete safety: %+v", guardByID["full-rollout"])
	}
	if len(guardByID["full-rollout"].FailedPredicates) != 2 ||
		guardByID["full-rollout"].FailedPredicates[0].Reason != "outcome_mismatch" ||
		guardByID["full-rollout"].FailedPredicates[1].Reason != "protocol_not_complete" {
		t.Fatalf("unexpected full-rollout failures: %+v", guardByID["full-rollout"].FailedPredicates)
	}
	if !guardByID["canary-rollout"].Passed || !guardByID["hold-release"].Passed {
		t.Fatalf("canary and hold guards should pass: %+v", guardByID)
	}

	// Verify ArtifactRefs populated offline on VerifiedEvidenceFact and verify bytes!
	vAfterAttest := a.View()
	if len(vAfterAttest.Evidence) != 3 {
		t.Fatalf("evidence len=%d want 3", len(vAfterAttest.Evidence))
	}
	for _, ev := range vAfterAttest.Evidence {
		if ev.Assurance != EvidenceFactsVerified {
			t.Fatalf("evidence %s assurance=%q", ev.EvidenceID, ev.Assurance)
		}
		if ev.EvidenceID == "patch" {
			if len(ev.ArtifactRefs) != 1 || ev.ArtifactRefs[0].Ref.Verify(strings.NewReader(`{"max_attempts":3}`)) != nil {
				t.Fatalf("patch ArtifactRef failed verification: %+v", ev.ArtifactRefs)
			}
		}
	}

	// Safety dissents AND casts bounded evidence-cited veto on full-rollout (dissent+veto is allowed!).
	accordMustApply(t, a, fx.safety, "safety-vote", "vote", "safety-dissent-full", 4, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotDissent, RationaleHash: Hash("safety-incomplete")}
	})
	accordMustApply(t, a, fx.safety, "safety-vote", "veto", "safety-veto-full", 4, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("no-rollback-proof"), EvidenceIDs: []string{"safety"}}
	})
	// Second veto on another option exceeds MaxVetoesPerActor=1 -> ErrAccordAuthority.
	accordReject(t, a, fx.safety, "safety-vote", "veto", "safety-veto-hold", 4, ErrAccordAuthority, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "hold-release", ReasonHash: Hash("too-many"), EvidenceIDs: []string{"safety"}}
	})

	// Votes on canary-rollout: safety(2) + sre(2) + security(1) = weight 5 approve; release(2) dissents (margin = 5-2 = 3 >= 1).
	accordMustApply(t, a, fx.safety, "safety-vote", "vote", "safety-ok-canary", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("canary-safe")}
	})
	accordMustApply(t, a, fx.sre, "sre-vote", "vote", "sre-ok-canary", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("sre-ready")}
	})
	accordMustApply(t, a, fx.security, "security-vote", "vote", "sec-ok-canary", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("sec-ok")}
	})
	accordMustApply(t, a, fx.release, "release-vote", "vote", "rel-dissent-canary", 6, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotDissent, RationaleHash: Hash("prefer-full")}
	})

	// Early resolve before VoteByHeight=10 rejected!
	accordReject(t, a, fx.release, "release-vote", "resolve", "res-early", 9, ErrAccordPhase, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("too-early")}
	})
	if got := a.View().StageAt(10); got != "resolving" {
		t.Fatalf("StageAt(10)=%q want resolving", got)
	}

	// Resolve at height=10.
	finalHead := accordMustApply(t, a, fx.security, "security-vote", "resolve", "res-final", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("tally-complete")}
	})
	v := a.View()
	if v.Phase != AccordPhaseDecided || v.Outcome == nil || v.Outcome.WinningOptionID != "canary-rollout" {
		t.Fatalf("unexpected outcome: %+v", v)
	}
	if v.Outcome.WinningCommitment != Hash(fx.canSpec) {
		t.Fatalf("commitment mismatch: got %s want %s", v.Outcome.WinningCommitment, Hash(fx.canSpec))
	}
	if len(v.Outcome.WinningOptionDissents) != 1 || v.Outcome.WinningOptionDissents[0].Actor != fx.release.pub.ID() ||
		v.Outcome.WinningOptionDissents[0].RationaleHash != Hash("prefer-full") {
		t.Fatalf("minority dissent not preserved: %+v", v.Outcome.WinningOptionDissents)
	}
	if v.Outcome.Hash() == "" || len(v.Outcome.Hash()) != 64 {
		t.Fatalf("invalid outcome hash: %q", v.Outcome.Hash())
	}
	if got := v.StageAt(15); got != "decided" {
		t.Fatalf("terminal StageAt=%q want decided", got)
	}

	// Offline portable verification over serialized JSON with zero private keys!
	rawBundle, err := json.Marshal(a.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	var received AccordBundle
	if err := json.Unmarshal(rawBundle, &received); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAccordBundle(received, v.ID, finalHead)
	if err != nil {
		t.Fatalf("VerifyAccordBundle: %v", err)
	}
	if verified.Outcome.Hash() != v.Outcome.Hash() {
		t.Fatalf("verified outcome hash mismatch")
	}

	// Downstream binding helpers: canary succeeds, full-rollout rejected with ErrAccordBinding!
	p, _, err := AuthorizeProtocolFromAccord(received, v.ID, finalHead, fx.canSpec)
	if err != nil || p.View().ID != Hash(fx.canSpec) {
		t.Fatalf("AuthorizeProtocolFromAccord(canary): %v", err)
	}
	if _, _, err := AuthorizeProtocolFromAccord(received, v.ID, finalHead, fx.fullSpec); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("expected ErrAccordBinding for full-rollout, got %v", err)
	}
	if _, err := AuthorizeTaskFromAccord(received, v.ID, finalHead, fx.taskSpec); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("expected ErrAccordBinding for wrong kind task, got %v", err)
	}
	if _, err := AuthorizeDispositionFromAccord(received, v.ID, finalHead, "hold", Hash("hold-action"), Hash("hold-params")); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("expected ErrAccordBinding for wrong kind disposition, got %v", err)
	}

	// CreateProtocolFromAccord creates in ProtocolStore and propagates ErrExists on duplicate, ErrAccordBinding on nil store.
	if _, _, err := CreateProtocolFromAccord(nil, received, v.ID, finalHead); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("expected ErrAccordBinding for nil store, got %v", err)
	}
	pStore, err := OpenProtocolStore(filepath.Join(t.TempDir(), "protos"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	pid, _, err := CreateProtocolFromAccord(pStore, received, v.ID, finalHead)
	if err != nil || pid != Hash(fx.canSpec) {
		t.Fatalf("CreateProtocolFromAccord: id=%s err=%v", pid, err)
	}
	if _, _, err := CreateProtocolFromAccord(pStore, received, v.ID, finalHead); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists on duplicate CreateProtocolFromAccord, got %v", err)
	}
}

func TestAccordDynamicProposalsTaskAndDispositionBindings(t *testing.T) {
	fx := newAccordFixture(t)
	fx.spec.AllowProposals = true
	fx.spec.ProposalByHeight = 5
	fx.spec.VoteByHeight = 10
	fx.spec.ResolveByHeight = 20
	fx.spec.Options = nil // dynamic only
	fx.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
	fx.spec.Rules.MandatoryRoles = nil
	fx.spec.Rules.MinParticipationCount = 2
	fx.spec.Rules.MinParticipationWeight = 2
	fx.spec.Rules.MinApprovalCount = 2
	fx.spec.Rules.MinApprovalWeight = 2
	fx.spec.Rules.MinApprovalMarginWeight = 0
	// Remove veto permission from safety, add propose to release
	fx.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
	fx.spec.Roles = append(fx.spec.Roles, AccordRoleGrant{
		ID: "release-propose", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
		Permissions: []AccordPermission{AccordPermitPropose}, ExpiresAtHeight: 5, LimitsHash: Hash("prop"),
	})

	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatalf("NewAccord: %v", err)
	}
	if got := a.View().StageAt(1); got != "proposing" {
		t.Fatalf("StageAt(1)=%q want proposing", got)
	}
	// Voting before ProposalByHeight=5 is refused.
	accordMustApply(t, a, fx.release, "release-propose", "propose", "prop-task", 2, func(c *AccordCommand) {
		c.Propose = &ProposePayload{Option: AccordOption{
			ID: "remediate", Title: "Run remediation task", Priority: 1,
			Binding: OptionBinding{Kind: BindingTaskSpec, TaskSpec: &fx.taskSpec},
		}}
	})
	accordReject(t, a, fx.sre, "sre-vote", "vote", "early-vote", 3, ErrAccordPhase, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "remediate", Position: BallotApprove, RationaleHash: Hash("early")}
	})
	// Duplicate option ID refused with ErrAccordSpec.
	accordReject(t, a, fx.release, "release-propose", "propose", "prop-dup", 3, ErrAccordSpec, func(c *AccordCommand) {
		c.Propose = &ProposePayload{Option: AccordOption{
			ID: "remediate", Title: "Duplicate", Priority: 2,
			Binding: OptionBinding{Kind: BindingDisposition, Disposition: "hold", ActionHash: Hash("h")},
		}}
	})
	// Propose at ProposalByHeight=5 refused!
	accordReject(t, a, fx.release, "release-propose", "propose", "prop-late", 5, ErrAccordAuthority, func(c *AccordCommand) {
		c.Propose = &ProposePayload{Option: AccordOption{
			ID: "late-opt", Title: "Late", Priority: 2,
			Binding: OptionBinding{Kind: BindingDisposition, Disposition: "hold", ActionHash: Hash("h")},
		}}
	})

	// Vote in [5, 10) and resolve at 10.
	accordMustApply(t, a, fx.release, "release-vote", "vote", "v1", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "remediate", Position: BallotApprove, RationaleHash: Hash("r1")}
	})
	accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v2", 6, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "remediate", Position: BallotApprove, RationaleHash: Hash("r2")}
	})
	head := accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("done")}
	})

	b := a.Bundle()
	if _, err := AuthorizeTaskFromAccord(b, a.View().ID, head, fx.taskSpec); err != nil {
		t.Fatalf("AuthorizeTaskFromAccord: %v", err)
	}
	wrongTask := fx.taskSpec
	wrongTask.Nonce = "other"
	if _, err := AuthorizeTaskFromAccord(b, a.View().ID, head, wrongTask); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("expected ErrAccordBinding for wrong task, got %v", err)
	}

	// Also verify BindingDisposition exact parametersHash enforcement.
	fx2 := newAccordFixture(t)
	fx2.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
	fx2.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
	fx2.spec.Rules.MandatoryRoles = nil
	fx2.spec.Rules.MinParticipationCount = 2
	fx2.spec.Rules.MinParticipationWeight = 2
	fx2.spec.Rules.MinApprovalCount = 2
	fx2.spec.Rules.MinApprovalWeight = 2
	a2, err := NewAccord(fx2.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordMustApply(t, a2, fx2.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "hold-release", Position: BallotApprove, RationaleHash: Hash("r1")}
	})
	accordMustApply(t, a2, fx2.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "hold-release", Position: BallotApprove, RationaleHash: Hash("r2")}
	})
	head2 := accordMustApply(t, a2, fx2.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("hold")}
	})
	if _, err := AuthorizeDispositionFromAccord(a2.Bundle(), a2.View().ID, head2, "hold", Hash("hold-action"), Hash("hold-params")); err != nil {
		t.Fatalf("AuthorizeDispositionFromAccord: %v", err)
	}
	if _, err := AuthorizeDispositionFromAccord(a2.Bundle(), a2.View().ID, head2, "hold", Hash("hold-action"), Hash("wrong-params")); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("expected ErrAccordBinding for drifted parametersHash, got %v", err)
	}
}

func TestAccordOverridableVetoAndEquivocationRules(t *testing.T) {
	fx := newAccordFixture(t)
	fx.spec.Rules.BallotMode = BallotSingleChoice
	fx.spec.Rules.MinParticipationCount = 2
	fx.spec.Rules.MinParticipationWeight = 2
	fx.spec.Rules.MinApprovalCount = 2
	fx.spec.Rules.MinApprovalWeight = 3
	fx.spec.Rules.MinApprovalMarginWeight = 0
	fx.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}}
	fx.spec.Rules.Veto = VetoPolicy{
		Mode:               VetoOverridable,
		MaxVetoesPerActor:  2,
		OverrideWeight:     5, // release(2) + sre(2) + security(1) = 5 overrides safety veto!
		AllowedDomainRoles: []string{"safety"},
	}

	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatalf("NewAccord: %v", err)
	}

	// Equivocation checks: approve + approve on second option in single_choice -> ErrAccordEquivocation.
	accordMustApply(t, a, fx.release, "release-vote", "vote", "r-ok-full", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("ok")}
	})
	accordReject(t, a, fx.release, "release-vote", "vote", "r-ok-can", 2, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("second-approve")}
	})
	// Duplicate vote on same option -> ErrAccordEquivocation.
	accordReject(t, a, fx.release, "release-vote", "vote", "r-dup-full", 2, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotDissent, RationaleHash: Hash("flip")}
	})
	// Dissent on another option IS permitted in single_choice.
	accordMustApply(t, a, fx.release, "release-vote", "vote", "r-dis-hold", 2, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "hold-release", Position: BallotDissent, RationaleHash: Hash("no-hold")}
	})

	// Safety vetoes full-rollout, then cannot approve or abstain on full-rollout, CAN dissent, cannot double-veto!
	accordMustApply(t, a, fx.safety, "safety-vote", "veto", "s-veto-full", 3, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("risk")}
	})
	accordReject(t, a, fx.safety, "safety-vote", "veto", "s-veto-full-2", 3, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("risk2")}
	})
	accordReject(t, a, fx.safety, "safety-vote", "vote", "s-app-full", 3, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("contradict")}
	})
	accordReject(t, a, fx.safety, "safety-vote", "vote", "s-abs-full", 3, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotAbstain, RationaleHash: Hash("contradict")}
	})
	accordMustApply(t, a, fx.safety, "safety-vote", "vote", "s-dis-full", 3, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotDissent, RationaleHash: Hash("consistent")}
	})

	// Safety abstains on canary-rollout, then cannot veto canary-rollout!
	accordMustApply(t, a, fx.safety, "safety-vote", "vote", "s-abs-can", 4, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotAbstain, RationaleHash: Hash("abstain")}
	})
	accordReject(t, a, fx.safety, "safety-vote", "veto", "s-veto-can", 4, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "canary-rollout", ReasonHash: Hash("contradict")}
	})

	// Override full-rollout veto with weight 5 (release=2 + sre=2 + security=1) + mandatory sre!
	accordMustApply(t, a, fx.sre, "sre-vote", "vote", "sre-ok-full", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("sre-ok")}
	})
	accordMustApply(t, a, fx.security, "security-vote", "vote", "sec-ok-full", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "full-rollout", Position: BallotApprove, RationaleHash: Hash("sec-ok")}
	})
	accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("override")}
	})
	v := a.View()
	if v.Phase != AccordPhaseDecided || v.Outcome.WinningOptionID != "full-rollout" {
		t.Fatalf("expected overridden veto win for full-rollout, got %+v", v.Outcome)
	}
	if len(v.Outcome.WinningOptionVetoes) != 1 || v.Outcome.WinningOptionVetoes[0].Actor != fx.safety.pub.ID() {
		t.Fatalf("overridden veto not preserved: %+v", v.Outcome.WinningOptionVetoes)
	}
	if len(v.Outcome.WinningOptionDissents) != 1 || v.Outcome.WinningOptionDissents[0].Actor != fx.safety.pub.ID() {
		t.Fatalf("dissent not preserved: %+v", v.Outcome.WinningOptionDissents)
	}
}

func TestAccordTieBreakPoliciesAndDeadlockPrecedence(t *testing.T) {
	makeTieSpec := func(t *testing.T, policy TieBreakPolicy, prioA, prioB, prioC uint32) (accordFixture, *Accord) {
		t.Helper()
		fx := newAccordFixture(t)
		fx.spec.Rules.BallotMode = BallotApproval
		fx.spec.Rules.MinParticipationCount = 1
		fx.spec.Rules.MinParticipationWeight = 1
		fx.spec.Rules.MinApprovalCount = 1
		fx.spec.Rules.MinApprovalWeight = 2
		fx.spec.Rules.MinApprovalMarginWeight = 0
		fx.spec.Rules.MandatoryRoles = nil
		fx.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
		fx.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
		fx.spec.Rules.TieBreak = policy
		fx.spec.Options[0].ID, fx.spec.Options[0].Priority = "opt-b", prioB
		fx.spec.Options[1].ID, fx.spec.Options[1].Priority = "opt-a", prioA
		fx.spec.Options[2].ID, fx.spec.Options[2].Priority = "opt-c", prioC
		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		return fx, a
	}

	t.Run("tiebreak_deadlock", func(t *testing.T) {
		fx, a := makeTieSpec(t, TieBreakDeadlock, 1, 2, 3)
		accordMustApply(t, a, fx.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-a", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-b", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r")}
		})
		out := a.View().Outcome
		if out.Phase != AccordPhaseDeadlocked || out.DeadlockReason != DeadlockTie || !slices.Equal(out.TiedOptionIDs, []string{"opt-a", "opt-b"}) {
			t.Fatalf("got %+v", out)
		}
	})

	t.Run("tiebreak_lowest_priority_partial_narrowing", func(t *testing.T) {
		// opt-a(prio 1), opt-b(prio 1), opt-c(prio 5) all tied at weight 2 -> narrows to [opt-a, opt-b] only!
		fx, a := makeTieSpec(t, TieBreakLowestPriority, 1, 1, 5)
		accordMustApply(t, a, fx.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-a", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-b", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.safety, "safety-vote", "vote", "v3", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-c", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r")}
		})
		out := a.View().Outcome
		if out.Phase != AccordPhaseDeadlocked || out.DeadlockReason != DeadlockTie || !slices.Equal(out.TiedOptionIDs, []string{"opt-a", "opt-b"}) {
			t.Fatalf("expected surviving subset [opt-a, opt-b], got %+v", out)
		}
	})

	t.Run("tiebreak_fewest_dissents_weight_then_count", func(t *testing.T) {
		// opt-a, opt-b, opt-c all have approveWeight=2; opt-c has dissentWeight=2, opt-a has dissentWeight=1(count 1), opt-b has dissentWeight=0 -> opt-b wins!
		fx, a := makeTieSpec(t, TieBreakFewestDissents, 1, 1, 1)
		accordMustApply(t, a, fx.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-a", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-b", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.safety, "safety-vote", "vote", "v3", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-c", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.security, "security-vote", "vote", "d1", 3, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-a", Position: BallotDissent, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.release, "release-vote", "vote", "d2", 3, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-c", Position: BallotDissent, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r")}
		})
		out := a.View().Outcome
		if out.Phase != AccordPhaseDecided || out.WinningOptionID != "opt-b" {
			t.Fatalf("expected opt-b to win fewest_dissents, got %+v", out)
		}
	})

	t.Run("tiebreak_lexicographic_id", func(t *testing.T) {
		fx, a := makeTieSpec(t, TieBreakLexicographicID, 9, 1, 1)
		accordMustApply(t, a, fx.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-b", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "opt-a", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r")}
		})
		out := a.View().Outcome
		if out.Phase != AccordPhaseDecided || out.WinningOptionID != "opt-a" {
			t.Fatalf("expected opt-a to win lexicographic_id, got %+v", out)
		}
	})

	t.Run("deadlock_no_options", func(t *testing.T) {
		fx := newAccordFixture(t)
		fx.spec.AllowProposals = true
		fx.spec.ProposalByHeight = 5
		fx.spec.Options = nil
		fx.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
		fx.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
		fx.spec.Roles = append(fx.spec.Roles, AccordRoleGrant{
			ID: "rel-prop", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
			Permissions: []AccordPermission{AccordPermitPropose}, ExpiresAtHeight: 5, LimitsHash: Hash("p"),
		})
		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("none")}
		})
		if a.View().Outcome.DeadlockReason != DeadlockNoOptions {
			t.Fatalf("got %+v", a.View().Outcome)
		}
	})

	t.Run("deadlock_quorum_not_met_populates_tallies", func(t *testing.T) {
		fx := newAccordFixture(t)
		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, a, fx.safety, "safety-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("no-quorum")}
		})
		out := a.View().Outcome
		if out.DeadlockReason != DeadlockNoQuorum || len(out.Tallies) != 3 || out.ParticipatingCount != 1 {
			t.Fatalf("expected quorum_not_met with 3 tallies, got %+v", out)
		}
	})

	t.Run("deadlock_all_disqualified_by_evidence", func(t *testing.T) {
		fx := newAccordFixture(t)
		patchH, _, _ := makeHandoffWithOptions(t, TaskAccepted, false, "config", "x")
		fx.spec.Roles = append(fx.spec.Roles, AccordRoleGrant{
			ID: "rel-att", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
			Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
		})
		fx.spec.Evidence = []EvidenceSlot{{
			ID: "patch", Kind: EvidenceTaskHandoff, GoalID: patchH.Task.GoalID, TaskID: patchH.Task.ID(),
			ExpectedAuthority: patchH.Task.Authority.ID(), ExpectedResultHash: Hash(patchH.Result),
		}}
		for i := range fx.spec.Options {
			fx.spec.Options[i].Guard = OptionGuard{AllOf: []EvidencePredicate{{EvidenceID: "patch", Op: GuardAttested}}}
		}
		fx.spec.Rules.MinParticipationCount = 0
		fx.spec.Rules.MinParticipationWeight = 0
		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		// Never attest "patch" -> all 3 options fail guard!
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("no-ev")}
		})
		if a.View().Outcome.DeadlockReason != DeadlockAllDisqualifiedByEvidence {
			t.Fatalf("got %+v", a.View().Outcome)
		}
	})

	t.Run("deadlock_all_eligible_options_vetoed_and_no_threshold_met", func(t *testing.T) {
		fx := newAccordFixture(t)
		fx.spec.Rules.MandatoryRoles = nil
		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		// canary-rollout gets 2 approvers (weight 4, margin 4) + blocking veto by safety; others get 0 votes!
		accordMustApply(t, a, fx.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.safety, "safety-vote", "vote", "v3", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "hold-release", Position: BallotAbstain, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a, fx.safety, "safety-vote", "veto", "vt1", 3, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "canary-rollout", ReasonHash: Hash("block")}
		})
		accordMustApply(t, a, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("all-vetoed")}
		})
		if a.View().Outcome.DeadlockReason != DeadlockAllVetoed {
			t.Fatalf("expected all_eligible_options_vetoed, got %+v", a.View().Outcome)
		}

		// Without veto and without meeting approval threshold -> no_option_met_threshold
		a2, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, a2, fx.release, "release-vote", "vote", "v1", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotAbstain, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a2, fx.sre, "sre-vote", "vote", "v2", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotAbstain, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a2, fx.safety, "safety-vote", "vote", "v3", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotAbstain, RationaleHash: Hash("r")}
		})
		accordMustApply(t, a2, fx.security, "security-vote", "resolve", "res", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("no-thresh")}
		})
		if a2.View().Outcome.DeadlockReason != DeadlockNoThresholdMet {
			t.Fatalf("expected no_option_met_threshold, got %+v", a2.View().Outcome)
		}
	})

	t.Run("expire_preserves_partial_state", func(t *testing.T) {
		fx := newAccordFixture(t)
		a, err := NewAccord(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, a, fx.sre, "sre-vote", "vote", "v1", 3, func(c *AccordCommand) {
			c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
		})
		// Early expire rejected with ErrAccordAuthority.
		accordReject(t, a, fx.security, "security-vote", "expire", "exp-early", 19, ErrAccordAuthority, func(c *AccordCommand) {
			c.Expire = &ExpirePayload{ReasonHash: Hash("early")}
		})
		if got := a.View().StageAt(20); got != "expirable" {
			t.Fatalf("StageAt(20)=%q want expirable", got)
		}
		head := accordMustApply(t, a, fx.security, "security-vote", "expire", "exp-final", 20, func(c *AccordCommand) {
			c.Expire = &ExpirePayload{ReasonHash: Hash("deadline-missed")}
		})
		v := a.View()
		if v.Phase != AccordPhaseExpired || v.Outcome == nil || v.Outcome.ExpiredReasonHash != Hash("deadline-missed") || len(v.Votes) != 1 {
			t.Fatalf("unexpected expired view: %+v", v)
		}
		if _, err := VerifyAccordBundle(a.Bundle(), v.ID, head); err != nil {
			t.Fatalf("VerifyAccordBundle(expired): %v", err)
		}
	})
}

func TestAccordSpecHardeningAndNoAliasing(t *testing.T) {
	fx := newAccordFixture(t)

	cases := []struct {
		name   string
		mutate func(*AccordSpec)
	}{
		{"invalid_utf8_nonce", func(s *AccordSpec) { s.Nonce = "bad\xffid" }},
		{"nul_in_purpose", func(s *AccordSpec) { s.Purpose = "bad\x00purpose" }},
		{"whitespace_in_id", func(s *AccordSpec) { s.Scope = "release v2" }},
		{"control_in_title", func(s *AccordSpec) { s.Options[0].Title = "line1\nline2" }},
		{"duplicate_signing_key", func(s *AccordSpec) {
			dup := fx.security.pub
			dup.Signing = slices.Clone(fx.sre.pub.Signing)
			s.Participants[3] = dup
			s.Roles[3].Actor = dup.ID()
		}},
		{"weight_overflow", func(s *AccordSpec) { s.Roles[0].Weight = maxAccordTotalWeight; s.Roles[1].Weight = 1 }},
		{"independent_resolver_conflict", func(s *AccordSpec) { s.Rules.RequireIndependentResolver = true }},
		{"veto_disabled_with_veto_grant", func(s *AccordSpec) { s.Rules.Veto = VetoPolicy{Mode: VetoDisabled} }},
		{"require_evidence_with_zero_slots", func(s *AccordSpec) { s.Rules.Veto.RequireEvidence = true }},
		{"dangling_predicate_evidence_id", func(s *AccordSpec) {
			s.Options[0].Guard = OptionGuard{AllOf: []EvidencePredicate{{EvidenceID: "ghost", Op: GuardNotAttested}}}
		}},
		{"unfeasible_mandatory_role", func(s *AccordSpec) {
			s.Rules.MandatoryRoles = []RoleRequirement{{Role: "nonexistent", MinApprovals: 1}}
		}},
		{"missing_closeout_resolve_grant", func(s *AccordSpec) {
			s.Roles[0].ExpiresAtHeight = 19
			s.Roles[3].ExpiresAtHeight = 19
		}},
		{"guard_artifact_slot_without_outcomes", func(s *AccordSpec) {
			s.Roles = append(s.Roles, AccordRoleGrant{
				ID: "att", Actor: fx.release.pub.ID(), Scope: s.Scope,
				Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
			})
			s.Evidence = []EvidenceSlot{{
				ID: "ev1", Kind: EvidenceProtocolBundle, ProtocolID: Hash("p"),
				ExpectedAuthority: fx.release.pub.ID(), ExpectedHead: Hash("h"),
			}}
			s.Options[0].Guard = OptionGuard{AllOf: []EvidencePredicate{{EvidenceID: "ev1", Op: GuardArtifactSlot, Slot: "config"}}}
		}},
		{"guard_min_gen_on_protocol_bundle", func(s *AccordSpec) {
			s.Roles = append(s.Roles, AccordRoleGrant{
				ID: "att", Actor: fx.release.pub.ID(), Scope: s.Scope,
				Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
			})
			s.Evidence = []EvidenceSlot{{
				ID: "ev1", Kind: EvidenceProtocolBundle, ProtocolID: Hash("p"),
				ExpectedAuthority: fx.release.pub.ID(), ExpectedHead: Hash("h"),
			}}
			s.Options[0].Guard = OptionGuard{AllOf: []EvidencePredicate{{EvidenceID: "ev1", Op: GuardMinGeneration, MinGeneration: 1}}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := cloneAccordSpec(fx.spec)
			tc.mutate(&s)
			if err := s.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("%s: got %v want ErrAccordSpec", tc.name, err)
			}
		})
	}

	// Verify caller mutation after NewAccord / View / Bundle cannot alias internal state!
	specCopy := cloneAccordSpec(fx.spec)
	a, err := NewAccord(specCopy)
	if err != nil {
		t.Fatal(err)
	}
	origID := a.View().ID
	specCopy.Participants[0].Signing[0] ^= 0xff
	specCopy.Roles[0].DomainRoles[0] = "tampered"
	specCopy.Options[0].Binding.ProtocolSpec.Purpose = "tampered"
	if a.View().ID != origID || a.Bundle().Spec.Roles[0].DomainRoles[0] != "release" || a.Bundle().Spec.Options[0].Binding.ProtocolSpec.Purpose == "tampered" {
		t.Fatal("spec input aliased internal Accord state")
	}
	v := a.View()
	v.Options[0].Option.Title = "mutated"
	if a.View().Options[0].Option.Title == "mutated" {
		t.Fatal("View() aliased internal Accord state")
	}
}

func TestAccordStoreDurabilityRetryCacheAndConcurrency(t *testing.T) {
	fx := newAccordFixture(t)
	dir := filepath.Join(t.TempDir(), "accords")
	key := bytes.Repeat([]byte{33}, 32)
	store, err := OpenAccordStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(fx.spec)
	if err != nil || id != fx.spec.ID() {
		t.Fatalf("Create: id=%s err=%v", id, err)
	}
	if _, err := store.Create(fx.spec); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate Create got %v want ErrExists", err)
	}

	// Confidential at rest.
	diskBytes, err := os.ReadFile(store.store.path(id))
	if err != nil || bytes.Contains(diskBytes, []byte(fx.spec.Purpose)) {
		t.Fatalf("accord checkpoint leaked plaintext: err=%v", err)
	}

	// Transact atomically applies multiple votes; mid-batch error rolls back cleanly.
	_, err = store.Transact(id, 2,
		func(v AccordView) (AccordCommand, []byte, bool, error) {
			cmd := AccordCommand{
				RequestID: "tx-v1", AccordID: v.ID, Head: v.Head, Actor: fx.sre.pub.ID(),
				GrantID: "sre-vote", Scope: fx.spec.Scope, Action: "vote", Height: 2,
				Vote: &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r1")},
			}
			sig, err := SignAccordCommand(fx.sre.id, cmd)
			return cmd, sig, true, err
		},
		func(v AccordView) (AccordCommand, []byte, bool, error) {
			// Invalid height (resolve before VoteByHeight=10) triggers rollback.
			cmd := AccordCommand{
				RequestID: "tx-bad", AccordID: v.ID, Head: v.Head, Actor: fx.security.pub.ID(),
				GrantID: "security-vote", Scope: fx.spec.Scope, Action: "resolve", Height: 2,
				Resolve: &ResolvePayload{ReasonHash: Hash("early")},
			}
			sig, err := SignAccordCommand(fx.security.id, cmd)
			return cmd, sig, true, err
		},
	)
	if !errors.Is(err, ErrAccordPhase) {
		t.Fatalf("mid-batch error got %v want ErrAccordPhase", err)
	}
	vAfterRollback, err := store.View(id)
	if err != nil || len(vAfterRollback.Votes) != 0 {
		t.Fatalf("failed Transact leaked partial state: %+v %v", vAfterRollback, err)
	}

	// Crash boundary: after-rename returns ErrCommitUncertain, cache invalidated, reopen + exact retry succeeds!
	cmd1, err := store.Prepare(id, fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", "retry-1", 3)
	if err != nil {
		t.Fatal(err)
	}
	cmd1.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r1")}
	sig1, err := SignAccordCommand(fx.sre.id, cmd1)
	if err != nil {
		t.Fatal(err)
	}
	store.store.commitHook = func(stage string) error {
		if stage == "after-rename" {
			return errors.New("injected sync failure")
		}
		return nil
	}
	if _, err := store.Apply(id, cmd1, sig1, 3); !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("got %v want ErrCommitUncertain", err)
	}
	store.store.commitHook = nil
	store.mu.Lock()
	_, stillCached := store.cache[id]
	store.mu.Unlock()
	if stillCached {
		t.Fatal("cache was not invalidated before uncertain write")
	}

	reopened, err := OpenAccordStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	head1, err := reopened.Apply(id, cmd1, sig1, 3)
	if err != nil {
		t.Fatalf("exact retry after reopen: %v", err)
	}
	// Conflicting payload with same RequestID rejected with ErrOperationConflict.
	conflictCmd := cmd1
	conflictCmd.Vote = &VotePayload{OptionID: "hold-release", Position: BallotApprove, RationaleHash: Hash("other")}
	conflictSig, _ := SignAccordCommand(fx.sre.id, conflictCmd)
	if _, err := reopened.Apply(id, conflictCmd, conflictSig, 3); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("conflicting RequestID got %v want ErrOperationConflict", err)
	}

	// Advance state to terminal, then verify historical exact retry still returns original head1!
	_, err = reopened.Transact(id, 4,
		func(v AccordView) (AccordCommand, []byte, bool, error) {
			cmd := AccordCommand{
				RequestID: "v2", AccordID: v.ID, Head: v.Head, Actor: fx.safety.pub.ID(),
				GrantID: "safety-vote", Scope: fx.spec.Scope, Action: "vote", Height: 4,
				Vote: &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r2")},
			}
			sig, err := SignAccordCommand(fx.safety.id, cmd)
			return cmd, sig, true, err
		},
		func(v AccordView) (AccordCommand, []byte, bool, error) {
			cmd := AccordCommand{
				RequestID: "v3", AccordID: v.ID, Head: v.Head, Actor: fx.security.pub.ID(),
				GrantID: "security-vote", Scope: fx.spec.Scope, Action: "vote", Height: 4,
				Vote: &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r3")},
			}
			sig, err := SignAccordCommand(fx.security.id, cmd)
			return cmd, sig, true, err
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	resCmd, err := reopened.Prepare(id, fx.security.pub.ID(), "security-vote", fx.spec.Scope, "resolve", "res-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	resCmd.Resolve = &ResolvePayload{ReasonHash: Hash("done")}
	resSig, err := SignAccordCommand(fx.security.id, resCmd)
	if err != nil {
		t.Fatal(err)
	}
	finalHead, err := reopened.Apply(id, resCmd, resSig, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Historical exact retry AFTER terminal closeout returns head1 and does not overwrite finalHead!
	retriedHead, err := reopened.Apply(id, cmd1, sig1, 999)
	if err != nil || retriedHead != head1 {
		t.Fatalf("historical exact retry got %s %v want %s", retriedHead, err, head1)
	}
	finalView, err := reopened.View(id)
	if err != nil || finalView.Head != finalHead || finalView.Phase != AccordPhaseDecided {
		t.Fatalf("historical retry corrupted final state: %+v %v", finalView, err)
	}

	// Export confirms syncDir and verifies offline.
	beforeSync := reopened.Stats().DirSyncOps
	bundle, err := reopened.Export(id)
	if err != nil || reopened.Stats().DirSyncOps <= beforeSync {
		t.Fatalf("Export sync check failed: err=%v stats=%+v", err, reopened.Stats())
	}
	if _, err := VerifyAccordBundle(bundle, id, finalHead); err != nil {
		t.Fatalf("VerifyAccordBundle(exported): %v", err)
	}

	// In-place ciphertext tamper detected even when cache is warm!
	cpPath := reopened.store.path(id)
	rawBytes, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(rawBytes)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(cpPath, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.View(id); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("tampered ciphertext got %v want ErrCorruptStore", err)
	}

	// Bounded 256-entry FIFO cache + concurrent reads under -race.
	boundedStore, err := OpenAccordStore(filepath.Join(t.TempDir(), "bounded"), key)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < maxCachedAccords+16; i++ {
		s := cloneAccordSpec(fx.spec)
		s.Nonce = fmt.Sprintf("bounded-%03d", i)
		aid, err := boundedStore.Create(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := boundedStore.View(aid); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, aid)
	}
	boundedStore.mu.Lock()
	cLen, oLen := len(boundedStore.cache), len(boundedStore.cacheOrder)
	boundedStore.mu.Unlock()
	if cLen > maxCachedAccords || oLen > maxCachedAccords*2 {
		t.Fatalf("cache bounds exceeded: cache=%d order=%d", cLen, oLen)
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if _, err := boundedStore.View(ids[len(ids)-1-(idx%4)]); err != nil {
				t.Errorf("concurrent View failed: %v", err)
			}
		}(g)
	}
	wg.Wait()
}

func TestAccordGuardNotAttestedIndependentResolverAndBundleAttester(t *testing.T) {
	fx := newAccordFixture(t)
	_, acceptedBundle, wit := makeHandoffWithOptions(t, TaskAccepted, false, "report", "ok")
	_, dissentBundle, dissentWit := makeHandoffWithOptions(t, TaskAccepted, true, "review", "dissent")

	// Independent resolver actor (only AccordPermitResolve + AccordPermitAttest, no vote/veto/propose).
	resolver := newAccordActor(t)
	fx.spec.Participants = append(fx.spec.Participants, resolver.pub)
	fx.spec.Roles = []AccordRoleGrant{
		{
			ID: "release-vote", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
			DomainRoles: []string{"release"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 2, ExpiresAtHeight: 15, LimitsHash: Hash("r"),
		},
		{
			ID: "sre-vote", Actor: fx.sre.pub.ID(), Scope: fx.spec.Scope,
			DomainRoles: []string{"sre"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 2, ExpiresAtHeight: 15, LimitsHash: Hash("s"),
		},
		{
			ID: "resolver-role", Actor: resolver.pub.ID(), Scope: fx.spec.Scope,
			Permissions:     []AccordPermission{AccordPermitAttest, AccordPermitResolve},
			ExpiresAtHeight: 20, LimitsHash: Hash("res"),
		},
	}
	fx.spec.Rules.RequireIndependentResolver = true
	fx.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
	fx.spec.Rules.MandatoryRoles = nil
	fx.spec.Rules.MinParticipationCount = 2
	fx.spec.Rules.MinParticipationWeight = 4
	fx.spec.Rules.MinApprovalCount = 2
	fx.spec.Rules.MinApprovalWeight = 4
	fx.spec.Rules.MinApprovalMarginWeight = 0

	fx.spec.Evidence = []EvidenceSlot{
		{
			ID: "clean-proto", Kind: EvidenceProtocolBundle,
			ProtocolID: Hash(acceptedBundle.Spec), ExpectedAuthority: acceptedBundle.Spec.Initiator,
			RequiredAttester: resolver.pub.ID(), // ExpectedHead omitted -> delegates to RequiredAttester
		},
		{
			ID: "dissent-proto", Kind: EvidenceProtocolBundle,
			ProtocolID: Hash(dissentBundle.Spec), ExpectedAuthority: dissentBundle.Spec.Initiator,
			ExpectedHead: dissentBundle.Events[len(dissentBundle.Events)-1].ReceiptHash,
		},
	}
	fx.spec.Options[0].Guard = OptionGuard{
		AllOf: []EvidencePredicate{
			{EvidenceID: "clean-proto", Op: GuardNotAttested},
		},
	}
	fx.spec.Options[1].Guard = OptionGuard{
		AllOf: []EvidencePredicate{
			{EvidenceID: "clean-proto", Op: GuardWitnessApproved, ActorID: wit.pub.ID()},
			{EvidenceID: "dissent-proto", Op: GuardWitnessApproved, ActorID: dissentWit.pub.ID()},
		},
	}
	fx.spec.Options[2].Guard = OptionGuard{
		AllOf: []EvidencePredicate{
			{EvidenceID: "clean-proto", Op: GuardWitnessApproved, ActorID: wit.pub.ID()},
			{EvidenceID: "dissent-proto", Op: GuardNotAttested},
		},
	}

	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatalf("NewAccord(independent resolver): %v", err)
	}

	// Before attestation: opt0 (GuardNotAttested) passes with empty SatisfiedEvidenceIDs; opt2 fails clean-proto.
	g0 := map[string]OptionGuardStatus{}
	for _, gs := range a.EvaluateGuards() {
		g0[gs.OptionID] = gs
	}
	if !g0["full-rollout"].Passed || len(g0["full-rollout"].SatisfiedEvidenceIDs) != 0 {
		t.Fatalf("expected GuardNotAttested pass with no attested SatisfiedEvidenceIDs: %+v", g0["full-rollout"])
	}

	// Attest clean-proto (omitted ExpectedHead derived from last event).
	accordMustApply(t, a, resolver, "resolver-role", "attest", "att-clean", 1, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "clean-proto", Protocol: &acceptedBundle}
	})
	g1 := map[string]OptionGuardStatus{}
	for _, gs := range a.EvaluateGuards() {
		g1[gs.OptionID] = gs
	}
	if g1["full-rollout"].Passed || g1["full-rollout"].FailedPredicates[0].Reason != "evidence_already_attested" {
		t.Fatalf("expected evidence_already_attested: %+v", g1["full-rollout"])
	}
	if !g1["hold-release"].Passed || !slices.Equal(g1["hold-release"].SatisfiedEvidenceIDs, []string{"clean-proto"}) {
		t.Fatalf("expected hold-release passed with clean-proto: %+v", g1["hold-release"])
	}

	// Attest dissent-proto -> canary-rollout fails GuardWitnessApproved with witness_dissented!
	accordMustApply(t, a, resolver, "resolver-role", "attest", "att-dissent", 2, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "dissent-proto", Protocol: &dissentBundle}
	})
	g2 := map[string]OptionGuardStatus{}
	for _, gs := range a.EvaluateGuards() {
		g2[gs.OptionID] = gs
	}
	if g2["canary-rollout"].Passed || len(g2["canary-rollout"].FailedPredicates) != 1 ||
		g2["canary-rollout"].FailedPredicates[0].Reason != "witness_dissented" {
		t.Fatalf("expected witness_dissented: %+v", g2["canary-rollout"])
	}
}

func TestAccordArtifactRefsStrictlyMatchReturnedArtifacts(t *testing.T) {
	buildHandoff := func(t *testing.T, incomplete bool) TaskHandoff {
		t.Helper()
		f := newProtocolFixture(t)
		f.spec.Version = ProtocolVersionV2
		f.spec.Return.SuccessArtifacts = []string{"declared"}
		f.spec.Return.FailureArtifacts = []string{"declared"}
		owner := protocolPublic(f.owner)
		dir := t.TempDir()
		key := bytes.Repeat([]byte{77}, 32)
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
			Nonce: "filter-goal", Purpose: "Test ArtifactRefs filtering",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		task := TaskSpec{
			GoalID: goalID, Nonce: "filter-task", Purpose: f.spec.Purpose, Scope: f.spec.Scope,
			SpecificationHash: f.spec.SpecificationHash, AcceptanceHash: f.spec.AcceptanceHash,
			FailurePolicyHash: f.spec.FailurePolicyHash, Authority: owner,
			Outputs: []string{"declared"}, FailureOutputs: []string{"declared"},
		}
		rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "p1", Tasks: []TaskSpec{task}}
		if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}
		f.spec.TaskID = task.ID()
		f.spec.Generation = 1
		p, err := NewProtocol(f.spec)
		if err != nil {
			t.Fatal(err)
		}
		claim := ClaimRequest{
			GoalID: goalID, TaskID: task.ID(), WorkerID: protocolPublic(f.worker).ID(),
			RequestID: "c1", ProtocolID: p.View().ID, LeaseUntilHeight: 41,
		}
		claimSig := Sign(f.owner, ClaimSignatureDomain, claim)
		lease, err := tasks.Claim(claim, claimSig, f.spec, 1)
		if err != nil {
			t.Fatal(err)
		}
		declaredRef := testArtifactRef("declared-bytes")
		extraRef := testArtifactRef("undeclared-bytes")
		if incomplete {
			protocolApply(t, p, f.owner, "", "admit", nil)
			cmd := p.Prepare(owner.ID(), "owner", f.spec.Scope, "incomplete", "inc", f.spec.ReturnByHeight)
			cmd.Incomplete = &IncompleteReturn{
				ReasonHash: Hash("timeout"),
				Artifacts: []NamedArtifact{
					{Name: "declared", Ref: declaredRef},
					{Name: "undeclared-extra", Ref: extraRef},
				},
			}
			if _, err := p.Apply(cmd, Sign(f.owner, "protocol", cmd), cmd.Height); err != nil {
				t.Fatal(err)
			}
		} else {
			p = enterProtocol(t, f)
			protocolApply(t, p, f.worker, "worker", "report", func(c *ProtocolCommand) {
				c.Report = &WorkReport{
					Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("ok"),
					Evidence: []string{declaredRef.Digest},
					Manifest: &EvidenceManifest{
						MethodHash: Hash("m"),
						Outputs: []NamedArtifact{
							{Name: "declared", Ref: declaredRef},
							{Name: "unreturned-extra", Ref: extraRef},
						},
					},
				}
			})
			reviewProtocol(t, p, f, false)
			resolveProtocol(t, p, f, "accept")
			protocolApply(t, p, f.worker, "worker", "return", func(c *ProtocolCommand) {
				v := p.View()
				c.Return = &ReturnManifest{
					ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews),
					Evidence: []string{declaredRef.Digest}, Uncertainty: "bounded",
					SafeAssumptions: []string{"ok"}, Disposition: "continue",
					Artifacts: []ReturnArtifact{{ID: "declared", Commitment: declaredRef.Digest, ReuseRestrictions: "cite"}},
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
		return h
	}

	accH := buildHandoff(t, false)
	incH := buildHandoff(t, true)
	fx := newAccordFixture(t)
	fx.spec.Roles = append(fx.spec.Roles, AccordRoleGrant{
		ID: "rel-att", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
		Permissions: []AccordPermission{AccordPermitAttest}, ExpiresAtHeight: 10, LimitsHash: Hash("a"),
	})
	fx.spec.Evidence = []EvidenceSlot{
		{
			ID: "acc", Kind: EvidenceTaskHandoff, GoalID: accH.Task.GoalID, TaskID: accH.Task.ID(),
			ExpectedAuthority: accH.Task.Authority.ID(), ExpectedResultHash: Hash(accH.Result),
		},
		{
			ID: "inc", Kind: EvidenceTaskHandoff, GoalID: incH.Task.GoalID, TaskID: incH.Task.ID(),
			ExpectedAuthority: incH.Task.Authority.ID(), ExpectedResultHash: Hash(incH.Result),
		},
	}
	a, err := NewAccord(fx.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordMustApply(t, a, fx.release, "rel-att", "attest", "a1", 1, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "acc", Handoff: &accH}
	})
	accordMustApply(t, a, fx.release, "rel-att", "attest", "a2", 2, func(c *AccordCommand) {
		c.Attest = &AttestPayload{EvidenceID: "inc", Handoff: &incH}
	})
	for _, ev := range a.View().Evidence {
		if len(ev.Artifacts) != 1 || len(ev.ArtifactRefs) != 1 ||
			ev.ArtifactRefs[0].Name != "declared" || ev.ArtifactRefs[0].Ref.Digest != ev.Artifacts[0].Digest {
			t.Fatalf("evidence %s leaked extra ArtifactRefs: artifacts=%+v refs=%+v", ev.EvidenceID, ev.Artifacts, ev.ArtifactRefs)
		}
	}
}
