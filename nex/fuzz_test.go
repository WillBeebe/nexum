package nex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
)

type fuzzActor struct {
	id  Identity
	pub Public
}

func fuzzNewActor(tb testing.TB) fuzzActor {
	tb.Helper()
	id, err := NewIdentity()
	if err != nil {
		tb.Fatal(err)
	}
	pub, err := id.Public()
	if err != nil {
		tb.Fatal(err)
	}
	return fuzzActor{id: id, pub: pub}
}

func fuzzArtifactRef(contents string) ArtifactRef {
	sum := sha256.Sum256([]byte(contents))
	return ArtifactRef{
		Digest:    hex.EncodeToString(sum[:]),
		Size:      uint64(len(contents)),
		MediaType: "text/plain",
	}
}

func fuzzFlipHex(s string) string {
	if len(s) == 0 {
		return "0"
	}
	b := []byte(s)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

func fuzzMakeProtocolSpec(owner, worker, witness fuzzActor, version int, nonce, scope string, withResources bool) ProtocolSpec {
	grant := func(id string, actor fuzzActor, label string, perms ...ProtocolPermission) RoleGrant {
		return RoleGrant{
			ID:                 id,
			Actor:              actor.pub.ID(),
			Label:              label,
			Scope:              scope,
			Permissions:        perms,
			ExpiresAtHeight:    40,
			LimitsHash:         Hash(scope + ":" + id),
			EvidenceObligation: Hash("evidence:" + id),
		}
	}
	spec := ProtocolSpec{
		Version:           version,
		Nonce:             nonce,
		Purpose:           "Fuzz protocol " + nonce,
		IntendedOutcome:   "Verified outcome for " + nonce,
		Scope:             scope,
		SpecificationHash: Hash("spec:" + nonce),
		AcceptanceHash:    Hash("acc:" + nonce),
		FailurePolicyHash: Hash("fail:" + nonce),
		Initiator:         owner.pub.ID(),
		Participants:      []Public{owner.pub, worker.pub, witness.pub},
		Roles: []RoleGrant{
			grant("owner", owner, "proposer", PermitCommit, PermitDecide, PermitReturn),
			grant("worker", worker, "worker", PermitWork, PermitReturn),
			grant("witness", witness, "witness", PermitReview),
		},
		WorkByHeight:      20,
		ReturnByHeight:    40,
		RequiredWitnesses: []string{witness.pub.ID()},
		DissentPolicy:     "record",
		Return: ReturnRequirements{
			SuccessArtifacts:   []string{"answer"},
			FailureArtifacts:   []string{"failure"},
			AllowedDisposition: []string{"continue", "retry", "refuse"},
			AllowSuccessors:    true,
		},
		MaxEvents: 32,
	}
	if withResources {
		spec.Resources = []ResourceLimit{{Resource: "compute", Maximum: 100}}
	}
	return spec
}

func fuzzApplyProtocolStep(tb testing.TB, p *Protocol, actor fuzzActor, grant, action, reqID string, height uint64, fill func(*ProtocolCommand)) ProtocolCommand {
	tb.Helper()
	cmd := p.Prepare(actor.pub.ID(), grant, p.spec.Scope, action, reqID, height)
	if action == "admit" {
		cmd.GrantID = ""
		cmd.Scope = ""
	}
	if fill != nil {
		fill(&cmd)
	}
	sig := Sign(actor.id, "protocol", cmd)
	if _, err := p.Apply(cmd, sig, height); err != nil {
		tb.Fatalf("fuzzApplyProtocolStep(%s/%s): %v", action, reqID, err)
	}
	return cmd
}

func fuzzBuildHandoff(tb testing.TB, owner, worker, witness fuzzActor, outcome TaskOutcome, slotName, content string) (TaskHandoff, ProtocolBundle) {
	tb.Helper()
	spec := fuzzMakeProtocolSpec(owner, worker, witness, ProtocolVersionV2, "handoff-"+string(outcome)+"-"+slotName, "fuzz/handoff", false)
	spec.Return.SuccessArtifacts = []string{slotName}
	spec.Return.FailureArtifacts = []string{slotName}

	dir := tb.TempDir()
	key := bytes.Repeat([]byte{0x42}, 32)
	goals, err := OpenGoalStore(filepath.Join(dir, "goals"), key)
	if err != nil {
		tb.Fatal(err)
	}
	attempts, err := OpenProtocolStore(filepath.Join(dir, "attempts"), key)
	if err != nil {
		tb.Fatal(err)
	}
	tasks, err := OpenCoordinationStore(filepath.Join(dir, "tasks"), key, goals, attempts)
	if err != nil {
		tb.Fatal(err)
	}

	goalID, err := goals.Create(GoalSpec{
		Nonce:                "fuzz-goal-" + string(outcome) + "-" + slotName,
		Purpose:              "Produce verified fuzz handoff",
		ConstraintsHash:      Hash("fuzz-constraints"),
		CompletionPolicyHash: Hash("fuzz-completion"),
		Planners:             []Public{owner.pub},
	})
	if err != nil {
		tb.Fatal(err)
	}
	task := TaskSpec{
		GoalID:            goalID,
		Nonce:             "fuzz-task-" + string(outcome) + "-" + slotName,
		Purpose:           spec.Purpose,
		Scope:             spec.Scope,
		SpecificationHash: spec.SpecificationHash,
		AcceptanceHash:    spec.AcceptanceHash,
		FailurePolicyHash: spec.FailurePolicyHash,
		Authority:         owner.pub,
		Outputs:           []string{slotName},
		FailureOutputs:    []string{slotName},
	}
	rev := PlanRevision{
		GoalID:    goalID,
		Head:      goalID,
		Planner:   owner.pub.ID(),
		RequestID: "plan-1",
		Tasks:     []TaskSpec{task},
	}
	if _, err := goals.Apply(rev, Sign(owner.id, PlanSignatureDomain, rev)); err != nil {
		tb.Fatal(err)
	}

	spec.TaskID = task.ID()
	spec.Generation = 1
	p, err := NewProtocol(spec)
	if err != nil {
		tb.Fatal(err)
	}

	claim := ClaimRequest{
		GoalID:           goalID,
		TaskID:           task.ID(),
		WorkerID:         worker.pub.ID(),
		RequestID:        "claim-1",
		ProtocolID:       p.View().ID,
		LeaseUntilHeight: 41,
	}
	claimSig := Sign(owner.id, ClaimSignatureDomain, claim)
	lease, err := tasks.Claim(claim, claimSig, spec, 1)
	if err != nil {
		tb.Fatal(err)
	}

	art := fuzzArtifactRef(content)
	switch outcome {
	case TaskIncomplete:
		fuzzApplyProtocolStep(tb, p, owner, "", "admit", "admit-owner", 1, nil)
		fuzzApplyProtocolStep(tb, p, owner, "owner", "incomplete", "inc-1", spec.ReturnByHeight, func(c *ProtocolCommand) {
			c.Incomplete = &IncompleteReturn{
				ReasonHash: Hash("witness unavailable"),
				Artifacts:  []NamedArtifact{{Name: slotName, Ref: art}},
			}
		})
	case TaskAccepted:
		fuzzApplyProtocolStep(tb, p, owner, "", "admit", "admit-owner", 1, nil)
		fuzzApplyProtocolStep(tb, p, worker, "", "admit", "admit-worker", 2, nil)
		fuzzApplyProtocolStep(tb, p, witness, "", "admit", "admit-witness", 3, nil)
		fuzzApplyProtocolStep(tb, p, owner, "owner", "commit", "commit-1", 4, nil)
		fuzzApplyProtocolStep(tb, p, worker, "worker", "report", "report-1", 5, func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome:    WorkCompleted,
				Stage:      "work",
				ReasonHash: Hash("done"),
				Evidence:   []string{art.Digest},
				Manifest: &EvidenceManifest{
					MethodHash: Hash("method"),
					Outputs:    []NamedArtifact{{Name: slotName, Ref: art}},
				},
			}
		})
		fuzzApplyProtocolStep(tb, p, witness, "witness", "review", "review-1", 6, func(c *ProtocolCommand) {
			c.Review = &WitnessReview{
				ReportHash:     Hash(p.View().Report),
				AssessmentHash: Hash("verified"),
				Dissent:        false,
			}
		})
		fuzzApplyProtocolStep(tb, p, owner, "owner", "resolve", "resolve-1", 7, func(c *ProtocolCommand) {
			c.Resolution = &Resolution{
				ReportHash: Hash(p.View().Report),
				Outcome:    "accept",
				ReasonHash: Hash("accepted"),
			}
		})
		fuzzApplyProtocolStep(tb, p, worker, "worker", "return", "return-1", 8, func(c *ProtocolCommand) {
			v := p.View()
			c.Return = &ReturnManifest{
				ResolutionHash:  Hash(v.Resolution),
				ReviewsHash:     Hash(v.Reviews),
				Evidence:        []string{art.Digest},
				Uncertainty:     "checked fixture",
				SafeAssumptions: []string{"bounded"},
				Disposition:     "continue",
				Artifacts:       []ReturnArtifact{{ID: slotName, Commitment: art.Digest, ReuseRestrictions: "cite"}},
			}
		})
	case TaskRejected:
		fuzzApplyProtocolStep(tb, p, owner, "", "admit", "admit-owner", 1, nil)
		fuzzApplyProtocolStep(tb, p, worker, "", "admit", "admit-worker", 2, nil)
		fuzzApplyProtocolStep(tb, p, witness, "", "admit", "admit-witness", 3, nil)
		fuzzApplyProtocolStep(tb, p, owner, "owner", "commit", "commit-1", 4, nil)
		fuzzApplyProtocolStep(tb, p, worker, "worker", "report", "report-1", 5, func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome:    WorkFailedSafely,
				Stage:      "work",
				ReasonHash: Hash("failed safely"),
				Evidence:   []string{art.Digest},
				Manifest: &EvidenceManifest{
					MethodHash: Hash("method"),
					Outputs:    []NamedArtifact{{Name: slotName, Ref: art}},
				},
			}
		})
		fuzzApplyProtocolStep(tb, p, witness, "witness", "review", "review-1", 6, func(c *ProtocolCommand) {
			c.Review = &WitnessReview{
				ReportHash:     Hash(p.View().Report),
				AssessmentHash: Hash("dissent"),
				Dissent:        true,
			}
		})
		fuzzApplyProtocolStep(tb, p, owner, "owner", "resolve", "resolve-1", 7, func(c *ProtocolCommand) {
			c.Resolution = &Resolution{
				ReportHash: Hash(p.View().Report),
				Outcome:    "reject",
				ReasonHash: Hash("rejected"),
			}
		})
		fuzzApplyProtocolStep(tb, p, owner, "owner", "return", "return-1", 8, func(c *ProtocolCommand) {
			v := p.View()
			c.Return = &ReturnManifest{
				ResolutionHash:  Hash(v.Resolution),
				ReviewsHash:     Hash(v.Reviews),
				Evidence:        []string{art.Digest},
				Uncertainty:     "failure preserved",
				SafeAssumptions: []string{"retry needs fresh consent"},
				Disposition:     "retry",
				Artifacts:       []ReturnArtifact{{ID: slotName, Commitment: art.Digest, ReuseRestrictions: "diagnostic"}},
			}
		})
	default:
		tb.Fatalf("unsupported outcome: %s", outcome)
	}

	bundle := p.Bundle()
	for _, ev := range bundle.Events {
		if _, err := attempts.Apply(claim.ProtocolID, ev.Command, ev.Signature, ev.Command.Height); err != nil {
			tb.Fatal(err)
		}
	}
	v := p.View()
	if _, err := tasks.Finalize(lease, v.Head, v.Height); err != nil {
		tb.Fatal(err)
	}
	h, err := tasks.ExportHandoff(claim, claimSig)
	if err != nil {
		tb.Fatal(err)
	}
	return h, bundle
}

func fuzzAccordApply(tb testing.TB, a *Accord, actor fuzzActor, grant, action, reqID string, height uint64, fill func(*AccordCommand)) {
	tb.Helper()
	cmd := a.Prepare(actor.pub.ID(), grant, a.spec.Scope, action, reqID, height)
	if fill != nil {
		fill(&cmd)
	}
	sig, err := SignAccordCommand(actor.id, cmd)
	if err != nil {
		tb.Fatalf("SignAccordCommand(%s/%s): %v", action, reqID, err)
	}
	if _, err := a.Apply(cmd, sig, height); err != nil {
		tb.Fatalf("Accord.Apply(%s/%s): %v", action, reqID, err)
	}
}

func fuzzBuildAccordSeeds(tb testing.TB) ([]AccordBundle, map[[2]string]string) {
	tb.Helper()
	release := fuzzNewActor(tb)
	sre := fuzzNewActor(tb)
	safety := fuzzNewActor(tb)
	security := fuzzNewActor(tb)
	upOwner := fuzzNewActor(tb)
	upWorker := fuzzNewActor(tb)
	upWitness := fuzzNewActor(tb)

	patchHandoff, _ := fuzzBuildHandoff(tb, upOwner, upWorker, upWitness, TaskAccepted, "patch", `{"ok":true}`)
	_, auditBundle := fuzzBuildHandoff(tb, upOwner, upWorker, upWitness, TaskRejected, "audit", "finding-1")

	downstreamFull := fuzzMakeProtocolSpec(release, sre, safety, ProtocolVersionV2, "fuzz-full", "release/full", false)
	downstreamCanary := fuzzMakeProtocolSpec(release, sre, safety, ProtocolVersionV2, "fuzz-canary", "release/canary", false)

	goal := GoalSpec{
		Nonce:                "fuzz-accord-goal",
		Purpose:              "Downstream task binding",
		ConstraintsHash:      Hash("c"),
		CompletionPolicyHash: Hash("p"),
		Planners:             []Public{release.pub},
	}
	downstreamTask := TaskSpec{
		GoalID:            goal.ID(),
		Nonce:             "fuzz-remediate",
		Purpose:           "Run remediation check",
		Scope:             "release/remediate",
		SpecificationHash: Hash("spec"),
		AcceptanceHash:    Hash("acc"),
		FailurePolicyHash: Hash("fail"),
		Authority:         safety.pub,
		Outputs:           []string{"proof"},
	}

	// 1. Rich decided Accord with dynamic proposal, handoff+protocol attestation, votes, bounded veto, and resolution.
	decidedSpec := AccordSpec{
		Version:    AccordVersion,
		Nonce:      "fuzz-accord-decided",
		Purpose:    "Choose release strategy",
		Scope:      "release/v2",
		PolicyHash: Hash("policy-v1"),
		Participants: []Public{
			release.pub, sre.pub, safety.pub, security.pub,
		},
		Roles: []AccordRoleGrant{
			{
				ID: "release-role", Actor: release.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"release"},
				Permissions: []AccordPermission{AccordPermitPropose, AccordPermitAttest, AccordPermitVote, AccordPermitResolve},
				Weight:      2, ExpiresAtHeight: 20, LimitsHash: Hash("release-limits"),
			},
			{
				ID: "sre-role", Actor: sre.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"sre"},
				Permissions: []AccordPermission{AccordPermitVote},
				Weight:      2, ExpiresAtHeight: 15, LimitsHash: Hash("sre-limits"),
			},
			{
				ID: "safety-role", Actor: safety.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"safety"},
				Permissions: []AccordPermission{AccordPermitVote, AccordPermitVeto},
				Weight:      2, ExpiresAtHeight: 15, LimitsHash: Hash("safety-limits"),
			},
			{
				ID: "security-role", Actor: security.pub.ID(), Scope: "release/v2",
				DomainRoles: []string{"security"},
				Permissions: []AccordPermission{AccordPermitVote, AccordPermitResolve},
				Weight:      1, ExpiresAtHeight: 20, LimitsHash: Hash("security-limits"),
			},
		},
		Evidence: []EvidenceSlot{
			{
				ID:                 "patch",
				Kind:               EvidenceTaskHandoff,
				GoalID:             patchHandoff.Task.GoalID,
				TaskID:             patchHandoff.Task.ID(),
				ExpectedAuthority:  patchHandoff.Task.Authority.ID(),
				ExpectedResultHash: Hash(patchHandoff.Result),
				MinGeneration:      1,
			},
			{
				ID:                "audit",
				Kind:              EvidenceProtocolBundle,
				ProtocolID:        Hash(auditBundle.Spec),
				ExpectedAuthority: auditBundle.Spec.Initiator,
				ExpectedHead:      auditBundle.Events[len(auditBundle.Events)-1].ReceiptHash,
			},
		},
		Options: []AccordOption{
			{
				ID: "full-rollout", Title: "Full rollout", Priority: 1,
				Guard: OptionGuard{
					AllOf: []EvidencePredicate{
						{EvidenceID: "patch", Op: GuardOutcomeIn, Outcomes: []TaskOutcome{TaskAccepted}},
					},
				},
				Binding: OptionBinding{Kind: BindingProtocolSpec, ProtocolSpec: &downstreamFull},
			},
			{
				ID: "canary-rollout", Title: "Canary rollout", Priority: 2,
				Guard: OptionGuard{
					AllOf: []EvidencePredicate{
						{EvidenceID: "patch", Op: GuardAttested},
						{EvidenceID: "audit", Op: GuardHasWitnessDissent},
					},
				},
				Binding: OptionBinding{Kind: BindingProtocolSpec, ProtocolSpec: &downstreamCanary},
			},
		},
		AllowProposals:   true,
		ProposalByHeight: 3,
		VoteByHeight:     10,
		ResolveByHeight:  20,
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
				RequireEvidence:    true,
				AllowedDomainRoles: []string{"safety"},
			},
			TieBreak: TieBreakLowestPriority,
		},
		MaxEvents: 64,
	}

	aDecided, err := NewAccord(decidedSpec)
	if err != nil {
		tb.Fatal(err)
	}
	fuzzAccordApply(tb, aDecided, release, "release-role", "propose", "prop-1", 1, func(c *AccordCommand) {
		c.Propose = &ProposePayload{
			Option: AccordOption{
				ID: "remediate-task", Title: "Remediate first", Priority: 3,
				Binding: OptionBinding{Kind: BindingTaskSpec, TaskSpec: &downstreamTask},
			},
		}
	})
	fuzzAccordApply(tb, aDecided, release, "release-role", "attest", "att-patch", 2, func(c *AccordCommand) {
		hCopy := cloneTaskHandoff(patchHandoff)
		c.Attest = &AttestPayload{EvidenceID: "patch", Handoff: &hCopy}
	})
	fuzzAccordApply(tb, aDecided, release, "release-role", "attest", "att-audit", 3, func(c *AccordCommand) {
		bCopy := cloneProtocolBundle(auditBundle)
		c.Attest = &AttestPayload{EvidenceID: "audit", Protocol: &bCopy}
	})
	fuzzAccordApply(tb, aDecided, safety, "safety-role", "veto", "veto-full", 4, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("audit-dissent"), EvidenceIDs: []string{"audit"}}
	})
	fuzzAccordApply(tb, aDecided, release, "release-role", "vote", "v-rel", 5, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("rel-ok")}
	})
	fuzzAccordApply(tb, aDecided, safety, "safety-role", "vote", "v-saf", 6, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("saf-ok")}
	})
	fuzzAccordApply(tb, aDecided, sre, "sre-role", "vote", "v-sre", 7, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotDissent, RationaleHash: Hash("sre-concern")}
	})
	fuzzAccordApply(tb, aDecided, security, "security-role", "vote", "v-sec", 8, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotAbstain, RationaleHash: Hash("sec-abstain")}
	})
	fuzzAccordApply(tb, aDecided, release, "release-role", "resolve", "res-1", 10, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("resolve-canary")}
	})

	// 2. Deadlocked Accord (no votes -> quorum not met).
	simpleSpec := AccordSpec{
		Version:      AccordVersion,
		Nonce:        "fuzz-accord-deadlock",
		Purpose:      "Deadlock seed",
		Scope:        "release/deadlock",
		PolicyHash:   Hash("policy-deadlock"),
		Participants: []Public{release.pub, safety.pub},
		Roles: []AccordRoleGrant{
			{
				ID: "rel", Actor: release.pub.ID(), Scope: "release/deadlock",
				Permissions: []AccordPermission{AccordPermitVote, AccordPermitResolve},
				Weight:      1, ExpiresAtHeight: 10, LimitsHash: Hash("l1"),
			},
			{
				ID: "saf", Actor: safety.pub.ID(), Scope: "release/deadlock",
				Permissions: []AccordPermission{AccordPermitVote},
				Weight:      1, ExpiresAtHeight: 8, LimitsHash: Hash("l2"),
			},
		},
		Options: []AccordOption{
			{
				ID: "hold", Title: "Hold", Priority: 1,
				Binding: OptionBinding{
					Kind:           BindingDisposition,
					Disposition:    "hold",
					ActionHash:     Hash("hold-act"),
					ParametersHash: Hash("hold-param"),
				},
			},
		},
		VoteByHeight:    5,
		ResolveByHeight: 10,
		Rules: DecisionRules{
			BallotMode:            BallotSingleChoice,
			MinParticipationCount: 2,
			MinApprovalCount:      2,
			MinApprovalWeight:     2,
			Veto:                  VetoPolicy{Mode: VetoDisabled},
			TieBreak:              TieBreakDeadlock,
		},
		MaxEvents: 16,
	}
	aDeadlock, err := NewAccord(simpleSpec)
	if err != nil {
		tb.Fatal(err)
	}
	fuzzAccordApply(tb, aDeadlock, release, "rel", "resolve", "res-dl", 5, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("deadlock")}
	})

	// 3. Expired Accord.
	expSpec := simpleSpec
	expSpec.Nonce = "fuzz-accord-expired"
	aExpired, err := NewAccord(expSpec)
	if err != nil {
		tb.Fatal(err)
	}
	fuzzAccordApply(tb, aExpired, release, "rel", "expire", "exp-1", 10, func(c *AccordCommand) {
		c.Expire = &ExpirePayload{ReasonHash: Hash("expired")}
	})

	// 4. Open Accord (0 events).
	openSpec := simpleSpec
	openSpec.Nonce = "fuzz-accord-open"
	aOpen, err := NewAccord(openSpec)
	if err != nil {
		tb.Fatal(err)
	}

	bundles := []AccordBundle{aDecided.Bundle(), aDeadlock.Bundle(), aExpired.Bundle(), aOpen.Bundle()}
	seedViews := make(map[[2]string]string, len(bundles))
	for _, b := range bundles {
		id := b.Spec.ID()
		head := id
		if len(b.Events) > 0 {
			head = b.Events[len(b.Events)-1].ReceiptHash
		}
		v, err := VerifyAccordBundle(b, id, head)
		if err != nil {
			tb.Fatalf("seed AccordBundle %s failed verification: %v", b.Spec.Nonce, err)
		}
		seedViews[[2]string{id, head}] = Hash(v)
	}
	return bundles, seedViews
}

func FuzzVerifyAccordBundle(f *testing.F) {
	bundles, seedViewHashes := fuzzBuildAccordSeeds(f)

	for _, b := range bundles {
		raw, err := json.Marshal(b)
		if err != nil {
			f.Fatal(err)
		}
		id := b.Spec.ID()
		head := id
		if len(b.Events) > 0 {
			head = b.Events[len(b.Events)-1].ReceiptHash
		}
		f.Add(raw, id, head)
	}

	// Mutated & edge-case seeds.
	decided := bundles[0]
	decidedID := decided.Spec.ID()
	decidedHead := decided.Events[len(decided.Events)-1].ReceiptHash

	forgedSig := AccordBundle{Spec: cloneAccordSpec(decided.Spec), Events: cloneAccordEvents(decided.Events)}
	forgedSig.Events[0].Signature[0] ^= 0xff
	if raw, err := json.Marshal(forgedSig); err == nil {
		f.Add(raw, decidedID, decidedHead)
	}

	truncated := AccordBundle{Spec: cloneAccordSpec(decided.Spec), Events: cloneAccordEvents(decided.Events[:len(decided.Events)-1])}
	if raw, err := json.Marshal(truncated); err == nil {
		f.Add(raw, decidedID, decidedHead)
	}

	tamperedSpec := AccordBundle{Spec: cloneAccordSpec(decided.Spec), Events: cloneAccordEvents(decided.Events)}
	tamperedSpec.Spec.Purpose = "tampered purpose"
	if raw, err := json.Marshal(tamperedSpec); err == nil {
		f.Add(raw, decidedID, decidedHead)
	}

	f.Add([]byte(`{`), decidedID, decidedHead)
	f.Add([]byte(`{}`), decidedID, decidedHead)
	f.Add([]byte(`null`), "", "")
	f.Add([]byte(`{"spec":{"version":1,"nonce":"bad\u0000nonce"}}`), decidedID, decidedHead)
	f.Add([]byte(`[]`), "not-hex", "not-hex")

	checkAccepted := func(t *testing.T, bundle AccordBundle, id, head string, view AccordView) {
		t.Helper()
		if view.ID != id || view.Head != head {
			t.Fatalf("verified view pins mismatch: got (%s,%s), want (%s,%s)", view.ID, view.Head, id, head)
		}
		if err := bundle.Spec.Validate(); err != nil {
			t.Fatalf("verified bundle has invalid spec: %v", err)
		}
		view2, err := VerifyAccordBundle(bundle, id, head)
		if err != nil || Hash(view) != Hash(view2) {
			t.Fatalf("non-deterministic verification: %v", err)
		}
		if wantHash, ok := seedViewHashes[[2]string{id, head}]; ok && Hash(view) != wantHash {
			t.Fatalf("mutated bundle verified with original seed pins (%s,%s)", id, head)
		}

		// Fail-closed checks on mutated pins and bundle fields.
		if _, err := VerifyAccordBundle(bundle, fuzzFlipHex(id), head); err == nil {
			t.Fatal("VerifyAccordBundle accepted mutated expectedAccordID")
		}
		if _, err := VerifyAccordBundle(bundle, id, fuzzFlipHex(head)); err == nil {
			t.Fatal("VerifyAccordBundle accepted mutated expectedHead")
		}
		mutSpec := AccordBundle{Spec: cloneAccordSpec(bundle.Spec), Events: cloneAccordEvents(bundle.Events)}
		mutSpec.Spec.Purpose += "-mut"
		if _, err := VerifyAccordBundle(mutSpec, id, head); err == nil {
			t.Fatal("VerifyAccordBundle accepted mutated Spec.Purpose")
		}
		if len(bundle.Events) > 0 {
			mutSig := AccordBundle{Spec: cloneAccordSpec(bundle.Spec), Events: cloneAccordEvents(bundle.Events)}
			mutSig.Events[0].Signature[0] ^= 0x01
			if _, err := VerifyAccordBundle(mutSig, id, head); err == nil {
				t.Fatal("VerifyAccordBundle accepted flipped event signature bit")
			}
			mutTrunc := AccordBundle{Spec: cloneAccordSpec(bundle.Spec), Events: cloneAccordEvents(bundle.Events[:len(bundle.Events)-1])}
			if _, err := VerifyAccordBundle(mutTrunc, id, head); err == nil {
				t.Fatal("VerifyAccordBundle accepted truncated event list")
			}
			mutRcpt := AccordBundle{Spec: cloneAccordSpec(bundle.Spec), Events: cloneAccordEvents(bundle.Events)}
			mutRcpt.Events[0].ReceiptHash = fuzzFlipHex(mutRcpt.Events[0].ReceiptHash)
			if _, err := VerifyAccordBundle(mutRcpt, id, head); err == nil {
				t.Fatal("VerifyAccordBundle accepted mutated event receipt hash")
			}
		}

		// Mismatched downstream binding authorizations must fail closed without panicking.
		if _, _, err := AuthorizeProtocolFromAccord(bundle, id, head, ProtocolSpec{}); err == nil {
			t.Fatal("AuthorizeProtocolFromAccord accepted zero ProtocolSpec")
		}
		if _, err := AuthorizeTaskFromAccord(bundle, id, head, TaskSpec{}); err == nil {
			t.Fatal("AuthorizeTaskFromAccord accepted zero TaskSpec")
		}
		if _, err := AuthorizeDispositionFromAccord(bundle, id, head, "refuse", Hash("mismatch-action"), Hash("mismatch-params")); err == nil {
			t.Fatal("AuthorizeDispositionFromAccord accepted mismatched disposition")
		}
	}

	f.Fuzz(func(t *testing.T, raw []byte, expectedID, expectedHead string) {
		var bundle AccordBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			if _, vErr := VerifyAccordBundle(AccordBundle{}, expectedID, expectedHead); vErr == nil {
				t.Fatal("VerifyAccordBundle accepted zero bundle")
			}
			return
		}
		if view, err := VerifyAccordBundle(bundle, expectedID, expectedHead); err == nil {
			checkAccepted(t, bundle, expectedID, expectedHead, view)
		}
		// Penetrate past ID/head mismatch checks when Spec is structurally valid.
		if bundle.Spec.Validate() == nil {
			derivedID := bundle.Spec.ID()
			derivedHead := derivedID
			if len(bundle.Events) > 0 {
				derivedHead = bundle.Events[len(bundle.Events)-1].ReceiptHash
			}
			if derivedID != expectedID || derivedHead != expectedHead {
				if view, err := VerifyAccordBundle(bundle, derivedID, derivedHead); err == nil {
					checkAccepted(t, bundle, derivedID, derivedHead, view)
				}
			}
		}
	})
}

func FuzzVerifyTaskHandoff(f *testing.F) {
	owner := fuzzNewActor(f)
	worker := fuzzNewActor(f)
	witness := fuzzNewActor(f)

	acceptedH, _ := fuzzBuildHandoff(f, owner, worker, witness, TaskAccepted, "answer", "accepted output")
	rejectedH, _ := fuzzBuildHandoff(f, owner, worker, witness, TaskRejected, "failure", "rejected diagnostic")
	incompleteH, _ := fuzzBuildHandoff(f, owner, worker, witness, TaskIncomplete, "partial", "incomplete notes")

	validHandoffs := []TaskHandoff{acceptedH, rejectedH, incompleteH}
	seedResultHashes := make(map[[2]string]string, len(validHandoffs))
	for _, h := range validHandoffs {
		taskID := h.Task.ID()
		resHash := Hash(h.Result)
		got, err := VerifyTaskHandoff(h, taskID, resHash)
		if err != nil {
			f.Fatalf("seed TaskHandoff (%s) failed verification: %v", h.Result.Outcome, err)
		}
		seedResultHashes[[2]string{taskID, resHash}] = Hash(got)

		raw, err := json.Marshal(h)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, taskID, resHash)
	}

	// Mutated & edge-case seeds.
	accTaskID := acceptedH.Task.ID()
	accResHash := Hash(acceptedH.Result)

	badClaimSig := cloneTaskHandoff(acceptedH)
	badClaimSig.ClaimSignature[0] ^= 0xff
	if raw, err := json.Marshal(badClaimSig); err == nil {
		f.Add(raw, accTaskID, accResHash)
	}

	badProtoSig := cloneTaskHandoff(acceptedH)
	badProtoSig.Protocol.Events[0].Signature[0] ^= 0xff
	if raw, err := json.Marshal(badProtoSig); err == nil {
		f.Add(raw, accTaskID, accResHash)
	}

	badOutcome := cloneTaskHandoff(incompleteH)
	badOutcome.Result.Outcome = TaskAccepted
	if raw, err := json.Marshal(badOutcome); err == nil {
		f.Add(raw, badOutcome.Task.ID(), Hash(badOutcome.Result))
	}

	badArtifact := cloneTaskHandoff(acceptedH)
	badArtifact.Result.Artifacts[0].Digest = Hash("unreviewed")
	if raw, err := json.Marshal(badArtifact); err == nil {
		f.Add(raw, accTaskID, Hash(badArtifact.Result))
	}

	truncProto := cloneTaskHandoff(acceptedH)
	truncProto.Protocol.Events = truncProto.Protocol.Events[:len(truncProto.Protocol.Events)-1]
	if raw, err := json.Marshal(truncProto); err == nil {
		f.Add(raw, accTaskID, accResHash)
	}

	f.Add([]byte(`{`), accTaskID, accResHash)
	f.Add([]byte(`{}`), accTaskID, accResHash)
	f.Add([]byte(`null`), "", "")
	f.Add([]byte(`{"Result":{"Outcome":"*"}}`), accTaskID, accResHash)

	checkAccepted := func(t *testing.T, h TaskHandoff, taskID, resHash string, got TaskResult) {
		t.Helper()
		if Hash(got) != resHash || got.Lease.TaskID != taskID {
			t.Fatalf("verified result mismatch: got=%+v taskID=%s resHash=%s", got, taskID, resHash)
		}
		if wantHash, ok := seedResultHashes[[2]string{taskID, resHash}]; ok && Hash(got) != wantHash {
			t.Fatalf("mutated handoff verified under original seed pins (%s,%s)", taskID, resHash)
		}

		// Fail-closed checks on mutated pins and handoff fields.
		if _, err := VerifyTaskHandoff(h, fuzzFlipHex(taskID), resHash); err == nil {
			t.Fatal("VerifyTaskHandoff accepted mutated expectedTaskID")
		}
		if _, err := VerifyTaskHandoff(h, taskID, fuzzFlipHex(resHash)); err == nil {
			t.Fatal("VerifyTaskHandoff accepted mutated expectedResultHash")
		}

		mutClaim := cloneTaskHandoff(h)
		mutClaim.ClaimSignature[0] ^= 0x01
		if _, err := VerifyTaskHandoff(mutClaim, taskID, resHash); err == nil {
			t.Fatal("VerifyTaskHandoff accepted flipped ClaimSignature bit")
		}

		mutTask := cloneTaskHandoff(h)
		mutTask.Task.Purpose += "-mut"
		if _, err := VerifyTaskHandoff(mutTask, taskID, resHash); err == nil {
			t.Fatal("VerifyTaskHandoff accepted mutated Task.Purpose")
		}

		if len(h.Protocol.Events) > 0 {
			mutEv := cloneTaskHandoff(h)
			mutEv.Protocol.Events[0].Signature[0] ^= 0x01
			if _, err := VerifyTaskHandoff(mutEv, taskID, resHash); err == nil {
				t.Fatal("VerifyTaskHandoff accepted flipped protocol event signature")
			}
			mutTrunc := cloneTaskHandoff(h)
			mutTrunc.Protocol.Events = mutTrunc.Protocol.Events[:len(mutTrunc.Protocol.Events)-1]
			if _, err := VerifyTaskHandoff(mutTrunc, taskID, resHash); err == nil {
				t.Fatal("VerifyTaskHandoff accepted truncated protocol transcript")
			}
		}

		mutOutcome := cloneTaskHandoff(h)
		if mutOutcome.Result.Outcome == TaskAccepted {
			mutOutcome.Result.Outcome = TaskRejected
		} else {
			mutOutcome.Result.Outcome = TaskAccepted
		}
		if _, err := VerifyTaskHandoff(mutOutcome, taskID, Hash(mutOutcome.Result)); err == nil {
			t.Fatal("VerifyTaskHandoff accepted forged outcome even with repinned result hash")
		}
	}

	f.Fuzz(func(t *testing.T, raw []byte, expectedTaskID, expectedResultHash string) {
		var h TaskHandoff
		if err := json.Unmarshal(raw, &h); err != nil {
			if _, vErr := VerifyTaskHandoff(TaskHandoff{}, expectedTaskID, expectedResultHash); vErr == nil {
				t.Fatal("VerifyTaskHandoff accepted zero TaskHandoff")
			}
			return
		}
		if res, err := VerifyTaskHandoff(h, expectedTaskID, expectedResultHash); err == nil {
			checkAccepted(t, h, expectedTaskID, expectedResultHash, res)
		}
		// Penetrate past pin mismatch checks when Task is structurally valid.
		if h.Task.validate(h.Task.GoalID) == nil {
			derivedTaskID := h.Task.ID()
			derivedResHash := Hash(h.Result)
			if derivedTaskID != expectedTaskID || derivedResHash != expectedResultHash {
				if res, err := VerifyTaskHandoff(h, derivedTaskID, derivedResHash); err == nil {
					checkAccepted(t, h, derivedTaskID, derivedResHash, res)
				}
			}
		}
	})
}

type fuzzProtocolStage struct {
	spec   ProtocolSpec
	events []ProtocolEvent
	view   ProtocolView
}

type fuzzProtocolSeed struct {
	stage    uint8
	cmd      ProtocolCommand
	sig      []byte
	signMode uint8
	height   uint64
}

func fuzzBuildProtocolStages(tb testing.TB, owner, worker, witness fuzzActor, version int) ([]fuzzProtocolStage, []fuzzProtocolSeed) {
	tb.Helper()
	spec := fuzzMakeProtocolSpec(owner, worker, witness, version, "fuzz-proto-v"+string(rune('0'+version)), "fuzz/protocol", true)
	p, err := NewProtocol(spec)
	if err != nil {
		tb.Fatal(err)
	}
	snapshot := func(pr *Protocol) fuzzProtocolStage {
		b := pr.Bundle()
		return fuzzProtocolStage{
			spec:   b.Spec,
			events: b.Events,
			view:   pr.View(),
		}
	}

	var seeds []fuzzProtocolSeed
	var stages []fuzzProtocolStage

	// Stage 0: genesis (admission)
	stages = append(stages, snapshot(p))
	admitOwner := p.Prepare(owner.pub.ID(), "", "", "admit", "req-admit-owner", 1)
	admitOwnerSig := Sign(owner.id, "protocol", admitOwner)
	seeds = append(seeds, fuzzProtocolSeed{stage: 0, cmd: admitOwner, sig: admitOwnerSig, signMode: 0, height: 1})
	if _, err := p.Apply(admitOwner, admitOwnerSig, 1); err != nil {
		tb.Fatal(err)
	}

	// Stage 1: partially admitted
	stages = append(stages, snapshot(p))
	admitWorker := p.Prepare(worker.pub.ID(), "", "", "admit", "req-admit-worker", 2)
	admitWorkerSig := Sign(worker.id, "protocol", admitWorker)
	if _, err := p.Apply(admitWorker, admitWorkerSig, 2); err != nil {
		tb.Fatal(err)
	}
	admitWitness := p.Prepare(witness.pub.ID(), "", "", "admit", "req-admit-witness", 3)
	admitWitnessSig := Sign(witness.id, "protocol", admitWitness)
	if _, err := p.Apply(admitWitness, admitWitnessSig, 3); err != nil {
		tb.Fatal(err)
	}

	// Stage 2: all admitted (ready for commit)
	stages = append(stages, snapshot(p))
	commitCmd := p.Prepare(owner.pub.ID(), "owner", spec.Scope, "commit", "req-commit", 4)
	commitSig := Sign(owner.id, "protocol", commitCmd)
	seeds = append(seeds, fuzzProtocolSeed{stage: 2, cmd: commitCmd, sig: commitSig, signMode: 0, height: 4})
	// Exact retry of an earlier event (admitOwner) at stage 2.
	seeds = append(seeds, fuzzProtocolSeed{stage: 2, cmd: admitOwner, sig: admitOwnerSig, signMode: 0, height: 9})
	if _, err := p.Apply(commitCmd, commitSig, 4); err != nil {
		tb.Fatal(err)
	}

	// Stage 3: working (ready for report or failure)
	stages = append(stages, snapshot(p))
	art := fuzzArtifactRef("fuzz protocol output")
	reportCmd := p.Prepare(worker.pub.ID(), "worker", spec.Scope, "report", "req-report", 5)
	reportCmd.Report = &WorkReport{
		Outcome:    WorkCompleted,
		Stage:      "execute",
		ReasonHash: Hash("completed"),
		Evidence:   []string{art.Digest},
		Resources:  []ResourceUse{{Resource: "compute", Used: 42}},
	}
	if version == ProtocolVersionV2 {
		reportCmd.Report.Manifest = &EvidenceManifest{
			MethodHash: Hash("method"),
			Outputs:    []NamedArtifact{{Name: "answer", Ref: art}},
		}
	}
	reportSig := Sign(worker.id, "protocol", reportCmd)
	seeds = append(seeds, fuzzProtocolSeed{stage: 3, cmd: reportCmd, sig: reportSig, signMode: 0, height: 5})

	// Also seed a valid failure report at stage 3 (height >= WorkByHeight).
	failCmd := p.Prepare(owner.pub.ID(), "owner", spec.Scope, "failure", "req-failure", spec.WorkByHeight)
	failCmd.Report = &WorkReport{
		Outcome:    WorkUnreported,
		Stage:      "deadline",
		ReasonHash: Hash("missed"),
		Evidence:   []string{Hash("deadline-ev")},
		Resources:  []ResourceUse{{Resource: "compute", Used: 0, Unknown: true}},
	}
	seeds = append(seeds, fuzzProtocolSeed{stage: 3, cmd: failCmd, sig: Sign(owner.id, "protocol", failCmd), signMode: 0, height: spec.WorkByHeight})

	if _, err := p.Apply(reportCmd, reportSig, 5); err != nil {
		tb.Fatal(err)
	}

	// Stage 4: review (ready for witness review)
	stages = append(stages, snapshot(p))
	reviewCmd := p.Prepare(witness.pub.ID(), "witness", spec.Scope, "review", "req-review", 6)
	reviewCmd.Review = &WitnessReview{
		ReportHash:     Hash(p.View().Report),
		AssessmentHash: Hash("assessment"),
		Dissent:        false,
	}
	reviewSig := Sign(witness.id, "protocol", reviewCmd)
	seeds = append(seeds, fuzzProtocolSeed{stage: 4, cmd: reviewCmd, sig: reviewSig, signMode: 0, height: 6})
	if _, err := p.Apply(reviewCmd, reviewSig, 6); err != nil {
		tb.Fatal(err)
	}

	// Stage 5: reviewed (ready for resolve)
	stages = append(stages, snapshot(p))
	resolveCmd := p.Prepare(owner.pub.ID(), "owner", spec.Scope, "resolve", "req-resolve", 7)
	resolveCmd.Resolution = &Resolution{
		ReportHash: Hash(p.View().Report),
		Outcome:    "accept",
		ReasonHash: Hash("accepted"),
	}
	resolveSig := Sign(owner.id, "protocol", resolveCmd)
	seeds = append(seeds, fuzzProtocolSeed{stage: 5, cmd: resolveCmd, sig: resolveSig, signMode: 0, height: 7})
	if _, err := p.Apply(resolveCmd, resolveSig, 7); err != nil {
		tb.Fatal(err)
	}

	// Stage 6: return_due (ready for return)
	stages = append(stages, snapshot(p))
	v6 := p.View()
	returnCmd := p.Prepare(worker.pub.ID(), "worker", spec.Scope, "return", "req-return", 8)
	returnCmd.Return = &ReturnManifest{
		ResolutionHash:  Hash(v6.Resolution),
		ReviewsHash:     Hash(v6.Reviews),
		Evidence:        append([]string(nil), v6.Report.Evidence...),
		Resources:       slices.Clone(v6.Report.Resources),
		Uncertainty:     "bounded fixture",
		SafeAssumptions: []string{"verified"},
		Artifacts:       []ReturnArtifact{{ID: "answer", Commitment: art.Digest, ReuseRestrictions: "cite"}},
		Disposition:     "continue",
	}
	returnSig := Sign(worker.id, "protocol", returnCmd)
	seeds = append(seeds, fuzzProtocolSeed{stage: 6, cmd: returnCmd, sig: returnSig, signMode: 0, height: 8})
	if _, err := p.Apply(returnCmd, returnSig, 8); err != nil {
		tb.Fatal(err)
	}

	// Stage 7: complete (terminal)
	stages = append(stages, snapshot(p))
	// Exact retry after completion.
	seeds = append(seeds, fuzzProtocolSeed{stage: 7, cmd: returnCmd, sig: returnSig, signMode: 0, height: 99})

	// For v2, also seed a valid incomplete closeout from stage 1 (height >= ReturnByHeight).
	if version == ProtocolVersionV2 {
		pInc := &Protocol{
			spec:   cloneProtocolSpec(stages[1].spec),
			events: cloneProtocol(stages[1].events),
			view:   cloneProtocol(stages[1].view),
		}
		incCmd := pInc.Prepare(owner.pub.ID(), "owner", spec.Scope, "incomplete", "req-incomplete", spec.ReturnByHeight)
		incCmd.Incomplete = &IncompleteReturn{
			ReasonHash: Hash("timeout"),
			Artifacts:  []NamedArtifact{{Name: "partial", Ref: fuzzArtifactRef("partial notes")}},
		}
		seeds = append(seeds, fuzzProtocolSeed{stage: 1, cmd: incCmd, sig: Sign(owner.id, "protocol", incCmd), signMode: 0, height: spec.ReturnByHeight})
	}

	return stages, seeds
}

func FuzzProtocolApply(f *testing.F) {
	owner := fuzzNewActor(f)
	worker := fuzzNewActor(f)
	witness := fuzzNewActor(f)
	outsider := fuzzNewActor(f)
	storeKey := bytes.Repeat([]byte{0x5a}, 32)

	v1Stages, v1Seeds := fuzzBuildProtocolStages(f, owner, worker, witness, ProtocolVersion)
	v2Stages, v2Seeds := fuzzBuildProtocolStages(f, owner, worker, witness, ProtocolVersionV2)

	for _, s := range v1Seeds {
		raw, err := json.Marshal(s.cmd)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, s.sig, s.signMode, s.height, s.stage, false)
	}
	for _, s := range v2Seeds {
		raw, err := json.Marshal(s.cmd)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, s.sig, s.signMode, s.height, s.stage, true)
	}

	// Mutated & invalid seeds.
	f.Add([]byte(`{`), []byte("bad"), uint8(0), uint64(1), uint8(0), true)
	f.Add([]byte(`{}`), []byte{}, uint8(0), uint64(0), uint8(0), true)
	f.Add([]byte(`{"RequestID":"bad-multi","Action":"report","Height":5,"Report":{},"Review":{}}`), []byte("sig"), uint8(13), uint64(5), uint8(3), true)
	// Unauthorized worker trying to resolve with real signature (signMode selects worker + binds head/height).
	badResolve, _ := json.Marshal(ProtocolCommand{
		RequestID: "bad-resolve",
		GrantID:   "worker",
		Scope:     "fuzz/protocol",
		Action:    "resolve",
		Height:    7,
		Resolution: &Resolution{
			ReportHash: Hash("r"),
			Outcome:    "accept",
			ReasonHash: Hash("x"),
		},
	})
	f.Add(badResolve, []byte{}, uint8(1|4|(2<<3)|32), uint64(7), uint8(5), true)
	// Conflicting RequestID with same actor (reuses req-admit-owner with different action).
	conflictCmd, _ := json.Marshal(ProtocolCommand{
		RequestID: "req-admit-owner",
		GrantID:   "owner",
		Scope:     "fuzz/protocol",
		Action:    "commit",
		Height:    4,
	})
	f.Add(conflictCmd, []byte{}, uint8(1|4|(1<<3)|32), uint64(4), uint8(2), true)

	f.Fuzz(func(t *testing.T, cmdJSON []byte, sig []byte, signMode uint8, height uint64, stageIdx uint8, useV2 bool) {
		stages := v1Stages
		if useV2 {
			stages = v2Stages
		}
		st := stages[int(stageIdx)%len(stages)]

		p := &Protocol{
			spec:   cloneProtocolSpec(st.spec),
			events: cloneProtocol(st.events),
			view:   cloneProtocol(st.view),
		}

		var cmd ProtocolCommand
		if err := json.Unmarshal(cmdJSON, &cmd); err != nil {
			before := Hash(p.Bundle())
			if _, applyErr := p.Apply(ProtocolCommand{}, sig, height); applyErr == nil {
				t.Fatal("Protocol.Apply accepted zero command")
			}
			if Hash(p.Bundle()) != before {
				t.Fatal("rejected zero command mutated protocol")
			}
			return
		}

		v := p.View()
		if signMode&1 != 0 {
			cmd.ProtocolID = v.ID
			if signMode&2 == 0 {
				cmd.Head = v.Head
			}
		}
		if signMode&4 != 0 {
			cmd.Height = height
		}

		effectiveSig := sig
		switch (signMode >> 3) & 3 {
		case 1:
			if signMode&32 != 0 {
				cmd.Actor = owner.pub.ID()
			}
			effectiveSig = Sign(owner.id, "protocol", cmd)
		case 2:
			if signMode&32 != 0 {
				cmd.Actor = worker.pub.ID()
			}
			effectiveSig = Sign(worker.id, "protocol", cmd)
		case 3:
			signer := witness
			if signMode&64 != 0 {
				signer = outsider
			}
			if signMode&32 != 0 {
				cmd.Actor = signer.pub.ID()
			}
			effectiveSig = Sign(signer.id, "protocol", cmd)
		}

		beforeBundle := p.Bundle()
		beforeHash := Hash(beforeBundle)
		memHead, memErr := p.Apply(cmd, effectiveSig, height)
		if memErr != nil {
			if Hash(p.Bundle()) != beforeHash {
				t.Fatalf("rejected command mutated in-memory Protocol: err=%v", memErr)
			}
			// Sample invalid inputs through ProtocolStore.Apply to verify fail-closed store path too.
			if signMode&0x80 == 0 || len(cmdJSON) == 0 || cmdJSON[0]&15 != 0 {
				return
			}
		}

		// Exercise ProtocolStore.Apply + reopen durability invariant for EVERY accepted command
		// (and sampled rejected commands).
		dir := filepath.Join(t.TempDir(), "proto")
		store, err := OpenProtocolStore(dir, storeKey)
		if err != nil {
			t.Fatal(err)
		}
		id, err := store.Create(st.spec)
		if err != nil {
			t.Fatal(err)
		}
		if len(st.events) > 0 {
			steps := make([]ProtocolStep, len(st.events))
			for i, ev := range st.events {
				ev := ev
				steps[i] = func(ProtocolView) (ProtocolCommand, []byte, bool, error) {
					return ev.Command, ev.Signature, true, nil
				}
			}
			if _, err := store.Transact(id, st.events[len(st.events)-1].Command.Height, steps...); err != nil {
				// Prefix events may span different heights; fall back to direct Apply when heights vary.
				for _, ev := range st.events {
					if _, err := store.Apply(id, ev.Command, ev.Signature, ev.Command.Height); err != nil {
						t.Fatalf("seed prefix apply failed: %v", err)
					}
				}
			}
		}

		beforeStoreView, err := store.View(id)
		if err != nil {
			t.Fatal(err)
		}
		beforeStoreBundle, err := store.Export(id)
		if err != nil {
			t.Fatal(err)
		}

		storeHead, storeErr := store.Apply(id, cmd, effectiveSig, height)
		if memErr != nil {
			if storeErr == nil {
				t.Fatalf("ProtocolStore.Apply accepted command rejected by Protocol.Apply (%v)", memErr)
			}
			reopened, err := OpenProtocolStore(dir, storeKey)
			if err != nil {
				t.Fatal(err)
			}
			afterView, err := reopened.View(id)
			if err != nil {
				t.Fatal(err)
			}
			if Hash(afterView) != Hash(beforeStoreView) {
				t.Fatal("rejected ProtocolStore.Apply mutated persisted state")
			}
			return
		}

		if storeErr != nil {
			t.Fatalf("ProtocolStore.Apply rejected command accepted by Protocol.Apply: %v", storeErr)
		}
		if storeHead != memHead {
			t.Fatalf("head mismatch: store=%s mem=%s", storeHead, memHead)
		}

		// Critical durability invariant: any command accepted by ProtocolStore.Apply
		// MUST survive OpenProtocolStore + View + VerifyProtocolBundle.
		reopened, err := OpenProtocolStore(dir, storeKey)
		if err != nil {
			t.Fatalf("OpenProtocolStore after Apply failed: %v", err)
		}
		reopenedView, err := reopened.View(id)
		if err != nil {
			t.Fatalf("reopened.View after Apply failed: %v", err)
		}
		if Hash(reopenedView) != Hash(p.View()) {
			t.Fatalf("reopened view differs from in-memory view after Apply")
		}
		reopenedBundle, err := reopened.Export(id)
		if err != nil {
			t.Fatalf("reopened.Export after Apply failed: %v", err)
		}
		verifiedView, err := VerifyProtocolBundle(reopenedBundle, id, reopenedView.Head)
		if err != nil {
			t.Fatalf("VerifyProtocolBundle failed on reopened bundle: %v", err)
		}
		if Hash(verifiedView) != Hash(reopenedView) {
			t.Fatal("VerifyProtocolBundle view differs from reopened store View")
		}
		if len(reopenedBundle.Events) == len(beforeStoreBundle.Events)+1 {
			if reopenedView.Head != storeHead {
				t.Fatalf("advancing command head mismatch: view.Head=%s storeHead=%s", reopenedView.Head, storeHead)
			}
		} else if len(reopenedBundle.Events) == len(beforeStoreBundle.Events) {
			// Exact retry of a prior event returns that prior event's receipt without regressing head.
			if reopenedView.Head != beforeStoreView.Head {
				t.Fatalf("retry altered head: got=%s want=%s", reopenedView.Head, beforeStoreView.Head)
			}
			foundReceipt := false
			for _, ev := range reopenedBundle.Events {
				if ev.ReceiptHash == storeHead {
					foundReceipt = true
					break
				}
			}
			if !foundReceipt {
				t.Fatalf("retry returned unknown receipt %s", storeHead)
			}
		} else {
			t.Fatalf("unexpected event count delta: before=%d after=%d", len(beforeStoreBundle.Events), len(reopenedBundle.Events))
		}

		// Exact retry after reopen must remain idempotent.
		retryHead, retryErr := reopened.Apply(id, cmd, effectiveSig, height)
		if retryErr != nil || retryHead != storeHead {
			t.Fatalf("exact retry after reopen failed: head=%s want=%s err=%v", retryHead, storeHead, retryErr)
		}
	})
}

func fuzzBuildSealedAccordSeeds(tb testing.TB) ([]AccordBundle, map[[2]string]string) {
	tb.Helper()
	safety := fuzzNewActor(tb)
	sre := fuzzNewActor(tb)
	auditor := fuzzNewActor(tb)
	tally := fuzzNewActor(tb)

	// 1024-bit is the minimum modulus accepted by he.FromPublic and exercises
	// identical CDS94 OR-proof and GMR VerifyEqual paths ~8x faster for fuzzing.
	tallyKey, err := NewSealedTallyKey(1024)
	if err != nil {
		tb.Fatalf("NewSealedTallyKey: %v", err)
	}

	makeSpec := func(nonce string, mode BallotMode, minPartCount, minPartWeight uint64, singleOption bool) AccordSpec {
		opts := []AccordOption{
			{
				ID: "canary-rollout", Title: "Canary rollout", Priority: 1,
				Binding: OptionBinding{
					Kind:           BindingDisposition,
					Disposition:    "continue",
					ActionHash:     Hash("canary-act:" + nonce),
					ParametersHash: Hash("canary-params:" + nonce),
				},
			},
		}
		if !singleOption {
			opts = append(opts, AccordOption{
				ID: "hold-and-remediate", Title: "Hold and remediate", Priority: 2,
				Binding: OptionBinding{
					Kind:           BindingDisposition,
					Disposition:    "hold",
					ActionHash:     Hash("hold-act:" + nonce),
					ParametersHash: Hash("hold-params:" + nonce),
				},
			})
		}
		return AccordSpec{
			Version:      AccordVersion,
			Nonce:        nonce,
			Purpose:      "Sealed fuzz accord " + nonce,
			Scope:        "fuzz/sealed",
			PolicyHash:   Hash("policy:" + nonce),
			Participants: []Public{safety.pub, sre.pub, auditor.pub, tally.pub},
			Roles: []AccordRoleGrant{
				{
					ID: "safety-vote", Actor: safety.pub.ID(), Scope: "fuzz/sealed",
					DomainRoles: []string{"safety"},
					Permissions: []AccordPermission{AccordPermitVote},
					Weight:      2, ExpiresAtHeight: 15, LimitsHash: Hash("safety-lim"),
				},
				{
					ID: "sre-vote", Actor: sre.pub.ID(), Scope: "fuzz/sealed",
					DomainRoles: []string{"sre"},
					Permissions: []AccordPermission{AccordPermitVote},
					Weight:      1, ExpiresAtHeight: 15, LimitsHash: Hash("sre-lim"),
				},
				{
					ID: "auditor-veto", Actor: auditor.pub.ID(), Scope: "fuzz/sealed",
					DomainRoles:     []string{"auditor"},
					Permissions:     []AccordPermission{AccordPermitVeto},
					ExpiresAtHeight: 15, LimitsHash: Hash("auditor-lim"),
				},
				{
					ID: "tally-resolve", Actor: tally.pub.ID(), Scope: "fuzz/sealed",
					Permissions:     []AccordPermission{AccordPermitResolve},
					ExpiresAtHeight: 20, LimitsHash: Hash("tally-lim"),
				},
			},
			Options:         opts,
			VoteByHeight:    10,
			ResolveByHeight: 20,
			Rules: DecisionRules{
				BallotMode:                 mode,
				BallotPrivacy:              BallotPrivacySealedPaillier,
				MinParticipationCount:      minPartCount,
				MinParticipationWeight:     minPartWeight,
				MinApprovalCount:           1,
				MinApprovalWeight:          2,
				MandatoryRoles:             []RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}},
				Veto:                       VetoPolicy{Mode: VetoBlocking, MaxVetoesPerActor: 1, AllowedDomainRoles: []string{"auditor"}},
				TieBreak:                   TieBreakLowestPriority,
				RequireIndependentResolver: true,
			},
			SealedTally: &SealedTallyConfig{
				PublicKey:      tallyKey.PublicKey(),
				TallyAuthority: tally.pub.ID(),
			},
			MaxEvents: 32,
		}
	}

	castSealed := func(a *Accord, actor fuzzActor, grant, reqID string, height uint64, choices map[string]BallotPosition) {
		b := a.Bundle()
		sb, err := EncryptSealedBallot(b.Spec, a.View().ID, actor.pub.ID(), choices, Hash("rat:"+reqID))
		if err != nil {
			tb.Fatalf("EncryptSealedBallot(%s): %v", reqID, err)
		}
		fuzzAccordApply(tb, a, actor, grant, "vote", reqID, height, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: sb}
		})
	}

	resolveSealed := func(a *Accord, reqID string, height uint64) {
		proof, err := tallyKey.TallyAccord(a.Bundle())
		if err != nil {
			tb.Fatalf("TallyAccord(%s): %v", reqID, err)
		}
		fuzzAccordApply(tb, a, tally, "tally-resolve", "resolve", reqID, height, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("res:" + reqID), SealedTally: proof}
		})
	}

	// 1. Decided sealed single-choice Accord with mandatory safety role + veto + dissent.
	aSingle, err := NewAccord(makeSpec("fuzz-sealed-single", BallotSingleChoice, 2, 3, false))
	if err != nil {
		tb.Fatal(err)
	}
	fuzzAccordApply(tb, aSingle, auditor, "auditor-veto", "veto", "veto-hold", 2, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "hold-and-remediate", ReasonHash: Hash("veto-hold")}
	})
	castSealed(aSingle, safety, "safety-vote", "v-saf", 3, map[string]BallotPosition{
		"canary-rollout":     BallotApprove,
		"hold-and-remediate": BallotDissent,
	})
	castSealed(aSingle, sre, "sre-vote", "v-sre", 4, map[string]BallotPosition{
		"canary-rollout":     BallotDissent,
		"hold-and-remediate": BallotApprove,
	})
	resolveSealed(aSingle, "res-single", 10)

	// 2. Decided sealed approval Accord (exercises BallotApproval path without SingleChoiceProof).
	aApproval, err := NewAccord(makeSpec("fuzz-sealed-approval", BallotApproval, 1, 2, true))
	if err != nil {
		tb.Fatal(err)
	}
	castSealed(aApproval, safety, "safety-vote", "v-saf-app", 2, map[string]BallotPosition{
		"canary-rollout": BallotApprove,
	})
	resolveSealed(aApproval, "res-approval", 10)

	// 3. Deadlocked sealed Accord (below quorum).
	aDeadlock, err := NewAccord(makeSpec("fuzz-sealed-deadlock", BallotSingleChoice, 2, 3, true))
	if err != nil {
		tb.Fatal(err)
	}
	castSealed(aDeadlock, sre, "sre-vote", "v-sre-dl", 2, map[string]BallotPosition{
		"canary-rollout": BallotAbstain,
	})
	resolveSealed(aDeadlock, "res-deadlock", 10)

	// 4. Open sealed Accord (1 encrypted ballot, unresolved).
	aOpen, err := NewAccord(makeSpec("fuzz-sealed-open", BallotSingleChoice, 2, 3, true))
	if err != nil {
		tb.Fatal(err)
	}
	castSealed(aOpen, safety, "safety-vote", "v-saf-open", 2, map[string]BallotPosition{
		"canary-rollout": BallotApprove,
	})

	// 5. Expired sealed Accord.
	aExpired, err := NewAccord(makeSpec("fuzz-sealed-expired", BallotSingleChoice, 2, 3, true))
	if err != nil {
		tb.Fatal(err)
	}
	fuzzAccordApply(tb, aExpired, tally, "tally-resolve", "expire", "exp-sealed", 20, func(c *AccordCommand) {
		c.Expire = &ExpirePayload{ReasonHash: Hash("expired-sealed")}
	})

	bundles := []AccordBundle{
		aSingle.Bundle(),
		aApproval.Bundle(),
		aDeadlock.Bundle(),
		aOpen.Bundle(),
		aExpired.Bundle(),
	}
	seedViews := make(map[[2]string]string, len(bundles))
	for _, b := range bundles {
		id := b.Spec.ID()
		head := id
		if len(b.Events) > 0 {
			head = b.Events[len(b.Events)-1].ReceiptHash
		}
		v, err := VerifyAccordBundle(b, id, head)
		if err != nil {
			tb.Fatalf("seed sealed AccordBundle %s failed verification: %v", b.Spec.Nonce, err)
		}
		if len(v.Votes) != 0 {
			tb.Fatalf("seed sealed AccordBundle %s exposed plaintext votes", b.Spec.Nonce)
		}
		seedViews[[2]string{id, head}] = Hash(v)
	}
	return bundles, seedViews
}

func FuzzVerifySealedAccordBundle(f *testing.F) {
	bundles, seedViewHashes := fuzzBuildSealedAccordSeeds(f)

	for _, b := range bundles {
		raw, err := json.Marshal(b)
		if err != nil {
			f.Fatal(err)
		}
		id := b.Spec.ID()
		head := id
		if len(b.Events) > 0 {
			head = b.Events[len(b.Events)-1].ReceiptHash
		}
		f.Add(raw, id, head)
	}

	// Targeted adversarial mutations on the decided single-choice sealed bundle.
	decided := bundles[0]
	decidedID := decided.Spec.ID()
	decidedHead := decided.Events[len(decided.Events)-1].ReceiptHash
	addMutated := func(mutate func(*AccordBundle)) {
		b := AccordBundle{Spec: cloneAccordSpec(decided.Spec), Events: cloneAccordEvents(decided.Events)}
		mutate(&b)
		if raw, err := json.Marshal(b); err == nil {
			f.Add(raw, decidedID, decidedHead)
		}
	}
	addMutated(func(b *AccordBundle) {
		for i := range b.Events {
			if b.Events[i].Command.Vote != nil && b.Events[i].Command.Vote.Sealed != nil {
				b.Events[i].Command.Vote.Sealed.Options[0].ApproveCT[0] ^= 0xff
				break
			}
		}
	})
	addMutated(func(b *AccordBundle) {
		for i := range b.Events {
			if b.Events[i].Command.Vote != nil && b.Events[i].Command.Vote.Sealed != nil {
				b.Events[i].Command.Vote.Sealed.Options[0].ApproveProof[0] ^= 0xff
				break
			}
		}
	})
	addMutated(func(b *AccordBundle) {
		for i := range b.Events {
			if b.Events[i].Command.Vote != nil && b.Events[i].Command.Vote.Sealed != nil {
				b.Events[i].Command.Vote.Sealed.SingleChoiceProof = nil
				break
			}
		}
	})
	addMutated(func(b *AccordBundle) {
		for i := range b.Events {
			if b.Events[i].Command.Resolve != nil && b.Events[i].Command.Resolve.SealedTally != nil {
				b.Events[i].Command.Resolve.SealedTally.Options[0].ApproveCount++
				break
			}
		}
	})
	addMutated(func(b *AccordBundle) {
		for i := range b.Events {
			if b.Events[i].Command.Resolve != nil && b.Events[i].Command.Resolve.SealedTally != nil {
				b.Events[i].Command.Resolve.SealedTally.Options[0].ApproveCountProof[0] ^= 0xff
				break
			}
		}
	})
	addMutated(func(b *AccordBundle) {
		for i := range b.Events {
			if b.Events[i].Command.Resolve != nil && b.Events[i].Command.Resolve.SealedTally != nil {
				b.Events[i].Command.Resolve.SealedTally.Options[0].RoleTallies[0].ApproveWeightProof[0] ^= 0xff
				break
			}
		}
	})
	addMutated(func(b *AccordBundle) {
		b.Spec.SealedTally.PublicKey = append([]byte{0x00}, b.Spec.SealedTally.PublicKey...)
	})

	f.Add([]byte(`{`), decidedID, decidedHead)
	f.Add([]byte(`{}`), decidedID, decidedHead)
	f.Add([]byte(`null`), "", "")
	f.Add([]byte(`{"spec":{"version":1,"sealed_tally":{"tally_authority":"bad\u0000id"}}}`), decidedID, decidedHead)
	f.Add([]byte(`[]`), "not-hex", "not-hex")

	checkAccepted := func(t *testing.T, bundle AccordBundle, id, head string, view AccordView) {
		t.Helper()
		if view.ID != id || view.Head != head {
			t.Fatalf("verified sealed view pins mismatch: got (%s,%s), want (%s,%s)", view.ID, view.Head, id, head)
		}
		if err := bundle.Spec.Validate(); err != nil {
			t.Fatalf("verified sealed bundle has invalid spec: %v", err)
		}
		if bundle.Spec.Rules.BallotPrivacy == BallotPrivacySealedPaillier {
			if bundle.Spec.SealedTally == nil {
				t.Fatal("verified sealed bundle missing SealedTally config")
			}
			if len(view.Votes) != 0 {
				t.Fatalf("verified sealed bundle exposed %d plaintext votes", len(view.Votes))
			}
		}
		view2, err := VerifyAccordBundle(bundle, id, head)
		if err != nil || Hash(view) != Hash(view2) {
			t.Fatalf("non-deterministic sealed verification: %v", err)
		}
		if wantHash, ok := seedViewHashes[[2]string{id, head}]; ok && Hash(view) != wantHash {
			t.Fatalf("mutated sealed bundle verified with original seed pins (%s,%s)", id, head)
		}

		// Fail-closed checks on mutated pins, sealed ciphertexts, OR-proofs, and GMR tally proofs.
		if _, err := VerifyAccordBundle(bundle, fuzzFlipHex(id), head); err == nil {
			t.Fatal("VerifyAccordBundle accepted mutated expectedAccordID")
		}
		if _, err := VerifyAccordBundle(bundle, id, fuzzFlipHex(head)); err == nil {
			t.Fatal("VerifyAccordBundle accepted mutated expectedHead")
		}
		if len(bundle.Events) > 0 {
			mutSig := AccordBundle{Spec: cloneAccordSpec(bundle.Spec), Events: cloneAccordEvents(bundle.Events)}
			mutSig.Events[0].Signature[0] ^= 0x01
			if _, err := VerifyAccordBundle(mutSig, id, head); err == nil {
				t.Fatal("VerifyAccordBundle accepted flipped signature bit")
			}
			for i, ev := range bundle.Events {
				if ev.Command.Vote != nil && ev.Command.Vote.Sealed != nil && len(ev.Command.Vote.Sealed.Options) > 0 {
					mutCT := AccordBundle{Spec: cloneAccordSpec(bundle.Spec), Events: cloneAccordEvents(bundle.Events)}
					if len(mutCT.Events[i].Command.Vote.Sealed.Options[0].ApproveCT) > 0 {
						mutCT.Events[i].Command.Vote.Sealed.Options[0].ApproveCT[0] ^= 0x01
						if _, err := VerifyAccordBundle(mutCT, id, head); err == nil {
							t.Fatal("VerifyAccordBundle accepted mutated sealed ApproveCT")
						}
					}
					break
				}
			}
			for i, ev := range bundle.Events {
				if ev.Command.Resolve != nil && ev.Command.Resolve.SealedTally != nil && len(ev.Command.Resolve.SealedTally.Options) > 0 {
					mutProof := AccordBundle{Spec: cloneAccordSpec(bundle.Spec), Events: cloneAccordEvents(bundle.Events)}
					if len(mutProof.Events[i].Command.Resolve.SealedTally.Options[0].ApproveCountProof) > 0 {
						mutProof.Events[i].Command.Resolve.SealedTally.Options[0].ApproveCountProof[0] ^= 0x01
						if _, err := VerifyAccordBundle(mutProof, id, head); err == nil {
							t.Fatal("VerifyAccordBundle accepted mutated SealedTally ApproveCountProof")
						}
					}
					break
				}
			}
		}
	}

	f.Fuzz(func(t *testing.T, raw []byte, expectedID, expectedHead string) {
		var bundle AccordBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			if _, vErr := VerifyAccordBundle(AccordBundle{}, expectedID, expectedHead); vErr == nil {
				t.Fatal("VerifyAccordBundle accepted zero bundle")
			}
			return
		}
		if view, err := VerifyAccordBundle(bundle, expectedID, expectedHead); err == nil {
			checkAccepted(t, bundle, expectedID, expectedHead, view)
		}
		if bundle.Spec.Validate() == nil {
			derivedID := bundle.Spec.ID()
			derivedHead := derivedID
			if len(bundle.Events) > 0 {
				derivedHead = bundle.Events[len(bundle.Events)-1].ReceiptHash
			}
			if derivedID != expectedID || derivedHead != expectedHead {
				if view, err := VerifyAccordBundle(bundle, derivedID, derivedHead); err == nil {
					checkAccepted(t, bundle, derivedID, derivedHead, view)
				}
			}
		}
	})
}

func fuzzBuildGoalPlanWithGatesSeeds(tb testing.TB) ([]GoalPlan, map[[2]string]string) {
	tb.Helper()
	planner := fuzzNewActor(tb)
	authority := fuzzNewActor(tb)

	makePlan := func(nonce string, build func(goalID string, apply func(head, reqID string, gates []AccordGate, tasks ...TaskSpec) string)) GoalPlan {
		dir := filepath.Join(tb.TempDir(), nonce)
		key := bytes.Repeat([]byte{0x6b}, 32)
		goals, err := OpenGoalStore(dir, key)
		if err != nil {
			tb.Fatal(err)
		}
		goalID, err := goals.Create(GoalSpec{
			Nonce:                nonce,
			Purpose:              "Fuzz goal plan with gates " + nonce,
			ConstraintsHash:      Hash("constraints:" + nonce),
			CompletionPolicyHash: Hash("completion:" + nonce),
			Planners:             []Public{planner.pub},
		})
		if err != nil {
			tb.Fatal(err)
		}
		apply := func(head, reqID string, gates []AccordGate, tasks ...TaskSpec) string {
			rev := PlanRevision{
				GoalID:    goalID,
				Head:      head,
				Planner:   planner.pub.ID(),
				RequestID: reqID,
				Gates:     gates,
				Tasks:     tasks,
			}
			nextHead, err := goals.Apply(rev, Sign(planner.id, PlanSignatureDomain, rev))
			if err != nil {
				tb.Fatalf("goals.Apply(%s/%s): %v", nonce, reqID, err)
			}
			return nextHead
		}
		if build != nil {
			build(goalID, apply)
		}
		plan, err := goals.View(goalID)
		if err != nil {
			tb.Fatal(err)
		}
		return plan
	}

	makeTask := func(goalID, nonce string, deps []TaskDependency, gateDeps ...TaskGateDependency) TaskSpec {
		return TaskSpec{
			GoalID:            goalID,
			Nonce:             nonce,
			Purpose:           "Task " + nonce,
			Scope:             "fuzz/" + nonce,
			SpecificationHash: Hash("spec:" + nonce),
			AcceptanceHash:    Hash("acc:" + nonce),
			FailurePolicyHash: Hash("fail:" + nonce),
			Authority:         authority.pub,
			Outputs:           []string{"out"},
			FailureOutputs:    []string{"diag"},
			Dependencies:      deps,
			GateDependencies:  gateDeps,
		}
	}

	// 1. Rich multi-revision conditional DAG covering all 3 terminal RequiredPhase values,
	// ExpectedCommitment, ExpectedDeadlockReason, AllowedOptions, and multi-gate fan-in.
	richPlan := makePlan("fuzz-gates-rich", func(goalID string, apply func(string, string, []AccordGate, ...TaskSpec) string) {
		upPatch := makeTask(goalID, "up-patch", nil)
		upSafety := makeTask(goalID, "up-safety", nil)
		h1 := apply(goalID, "rev-1", nil, upPatch, upSafety)

		releaseGate := AccordGate{
			ID:             "release-gate",
			GoalID:         goalID,
			AccordID:       Hash("accord-release"),
			Purpose:        "Select rollout strategy",
			AllowedOptions: []string{"full-rollout", "canary-rollout", "hold-and-remediate"},
		}
		canaryTask := makeTask(
			goalID, "canary-task",
			[]TaskDependency{
				{Input: "patch", TaskID: upPatch.ID(), ProtocolID: Hash("p1"), Head: Hash("h1"), Slot: "out", Digest: Hash("d1"), Outcome: TaskAccepted},
				{Input: "safety", TaskID: upSafety.ID(), ProtocolID: Hash("p2"), Head: Hash("h2"), Slot: "out", Digest: Hash("d2"), Outcome: TaskIncomplete},
			},
			TaskGateDependency{
				GateID:             "release-gate",
				RequiredPhase:      AccordPhaseDecided,
				OptionID:           "canary-rollout",
				ExpectedCommitment: Hash("canary-binding"),
			},
		)
		deadlockTask := makeTask(
			goalID, "deadlock-task", nil,
			TaskGateDependency{
				GateID:                 "release-gate",
				RequiredPhase:          AccordPhaseDeadlocked,
				ExpectedDeadlockReason: DeadlockNoQuorum,
			},
		)
		expiredTask := makeTask(
			goalID, "expired-task", nil,
			TaskGateDependency{
				GateID:        "release-gate",
				RequiredPhase: AccordPhaseExpired,
			},
		)
		h2 := apply(h1, "rev-2", []AccordGate{releaseGate}, canaryTask, deadlockTask, expiredTask)

		auditGate := AccordGate{
			ID:       "audit-gate",
			GoalID:   goalID,
			AccordID: Hash("accord-audit"),
			Purpose:  "Secondary unrestricted audit gate",
		}
		dualGateTask := makeTask(
			goalID, "dual-gate-task", nil,
			TaskGateDependency{GateID: "release-gate", RequiredPhase: AccordPhaseDecided, OptionID: "full-rollout"},
			TaskGateDependency{GateID: "audit-gate", RequiredPhase: AccordPhaseDecided, OptionID: "audit-pass"},
		)
		apply(h2, "rev-3", []AccordGate{auditGate}, dualGateTask)
	})

	// 2. Gate-only revision followed by a task revision referencing the prior-revision gate.
	gateOnlyPlan := makePlan("fuzz-gates-only-rev", func(goalID string, apply func(string, string, []AccordGate, ...TaskSpec) string) {
		g := AccordGate{
			ID:             "policy-gate",
			GoalID:         goalID,
			AccordID:       Hash("accord-policy"),
			Purpose:        "Declare gate before tasks",
			AllowedOptions: []string{"approve"},
		}
		h1 := apply(goalID, "rev-gate-only", []AccordGate{g})
		t1 := makeTask(goalID, "gated-after", nil, TaskGateDependency{
			GateID:        "policy-gate",
			RequiredPhase: AccordPhaseDecided,
			OptionID:      "approve",
		})
		apply(h1, "rev-task", nil, t1)
	})

	// 3. Genesis plan (0 revisions).
	genesisPlan := makePlan("fuzz-gates-genesis", nil)

	plans := []GoalPlan{richPlan, gateOnlyPlan, genesisPlan}
	seedHashes := make(map[[2]string]string, len(plans))
	for _, p := range plans {
		gid := p.Spec.ID()
		if err := VerifyGoalPlan(p, gid, p.Head); err != nil {
			tb.Fatalf("seed GoalPlan %s failed verification: %v", p.Spec.Nonce, err)
		}
		seedHashes[[2]string{gid, p.Head}] = Hash(p)
	}
	return plans, seedHashes
}

func FuzzVerifyGoalPlanWithGates(f *testing.F) {
	plans, seedPlanHashes := fuzzBuildGoalPlanWithGatesSeeds(f)

	for _, p := range plans {
		raw, err := json.Marshal(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw, p.Spec.ID(), p.Head)
	}

	// Targeted adversarial mutations on richPlan.
	rich := plans[0]
	richGoalID := rich.Spec.ID()
	richHead := rich.Head
	addMutated := func(mutate func(*GoalPlan)) {
		rawBase, err := json.Marshal(rich)
		if err != nil {
			f.Fatal(err)
		}
		var clone GoalPlan
		if err := json.Unmarshal(rawBase, &clone); err != nil {
			f.Fatal(err)
		}
		mutate(&clone)
		if raw, err := json.Marshal(clone); err == nil {
			f.Add(raw, richGoalID, richHead)
		}
	}
	addMutated(func(p *GoalPlan) { p.Revisions[1].Signature[0] ^= 0xff })
	addMutated(func(p *GoalPlan) { p.Revisions = p.Revisions[:len(p.Revisions)-1] })
	addMutated(func(p *GoalPlan) {
		p.Revisions[1].Revision.Gates[0].AccordID = fuzzFlipHex(p.Revisions[1].Revision.Gates[0].AccordID)
	})
	addMutated(func(p *GoalPlan) { p.Revisions[1].Revision.Gates[0].ID = "bad\x00gate" })
	addMutated(func(p *GoalPlan) {
		p.Revisions[1].Revision.Tasks[0].GateDependencies[0].RequiredPhase = AccordPhaseOpen
	})
	addMutated(func(p *GoalPlan) { p.Revisions[1].Revision.Tasks[0].GateDependencies[0].OptionID = "disallowed-opt" })
	addMutated(func(p *GoalPlan) { p.Revisions[1].Revision.Tasks[0].GateDependencies[0].GateID = "missing-gate" })
	addMutated(func(p *GoalPlan) {
		p.Revisions[1].Revision.Tasks[1].GateDependencies[0].OptionID = "forbidden-on-deadlock"
	})
	addMutated(func(p *GoalPlan) {
		p.Revisions[1].Revision.Tasks[2].GateDependencies[0].ExpectedCommitment = Hash("forbidden-on-expired")
	})
	addMutated(func(p *GoalPlan) { p.Revisions[2].Revision.Gates[0].ID = "release-gate" })

	f.Add([]byte(`{`), richGoalID, richHead)
	f.Add([]byte(`{}`), richGoalID, richHead)
	f.Add([]byte(`null`), "", "")
	f.Add([]byte(`[]`), "not-hex", "not-hex")

	checkAccepted := func(t *testing.T, plan GoalPlan, goalID, head string) {
		t.Helper()
		if plan.Spec.ID() != goalID || plan.Head != head {
			t.Fatalf("verified GoalPlan pin mismatch: got (%s,%s), want (%s,%s)", plan.Spec.ID(), plan.Head, goalID, head)
		}
		if err := VerifyGoalPlan(plan, goalID, head); err != nil {
			t.Fatalf("non-deterministic VerifyGoalPlan: %v", err)
		}
		if wantHash, ok := seedPlanHashes[[2]string{goalID, head}]; ok && Hash(plan) != wantHash {
			t.Fatalf("mutated GoalPlan verified under original seed pins (%s,%s)", goalID, head)
		}

		// Verify gate and task-gate invariants across all accepted revisions.
		declaredGates := make(map[string]AccordGate)
		for _, signed := range plan.Revisions {
			if len(signed.Revision.Tasks) == 0 && len(signed.Revision.Gates) == 0 {
				t.Fatal("verified GoalPlan contained empty revision")
			}
			for _, g := range signed.Revision.Gates {
				if err := g.validate(goalID); err != nil {
					t.Fatalf("verified GoalPlan has invalid gate %q: %v", g.ID, err)
				}
				if _, dup := declaredGates[g.ID]; dup {
					t.Fatalf("verified GoalPlan has duplicate gate %q", g.ID)
				}
				declaredGates[g.ID] = g
			}
			for _, task := range signed.Revision.Tasks {
				if err := task.validate(goalID); err != nil {
					t.Fatalf("verified GoalPlan has invalid task %q: %v", task.Nonce, err)
				}
				for _, gd := range task.GateDependencies {
					g, ok := declaredGates[gd.GateID]
					if !ok {
						t.Fatalf("verified GoalPlan task %q references undeclared gate %q", task.Nonce, gd.GateID)
					}
					if !isTerminalAccordPhase(gd.RequiredPhase) {
						t.Fatalf("verified GoalPlan task %q has non-terminal gate phase %q", task.Nonce, gd.RequiredPhase)
					}
					if gd.RequiredPhase == AccordPhaseDecided && len(g.AllowedOptions) > 0 && !slices.Contains(g.AllowedOptions, gd.OptionID) {
						t.Fatalf("verified GoalPlan task %q option %q outside AllowedOptions %v", task.Nonce, gd.OptionID, g.AllowedOptions)
					}
				}
			}
		}

		// Fail-closed checks on mutated pins and plan fields.
		if err := VerifyGoalPlan(plan, fuzzFlipHex(goalID), head); err == nil {
			t.Fatal("VerifyGoalPlan accepted mutated expectedGoalID")
		}
		if err := VerifyGoalPlan(plan, goalID, fuzzFlipHex(head)); err == nil {
			t.Fatal("VerifyGoalPlan accepted mutated expectedHead")
		}
		mutSpec := plan
		mutSpec.Spec.Purpose += "-mut"
		if err := VerifyGoalPlan(mutSpec, goalID, head); err == nil {
			t.Fatal("VerifyGoalPlan accepted mutated Spec.Purpose")
		}
		if len(plan.Revisions) > 0 {
			rawCopy, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			var mutSig GoalPlan
			if err := json.Unmarshal(rawCopy, &mutSig); err != nil {
				t.Fatal(err)
			}
			mutSig.Revisions[0].Signature[0] ^= 0x01
			if err := VerifyGoalPlan(mutSig, goalID, head); err == nil {
				t.Fatal("VerifyGoalPlan accepted flipped revision signature bit")
			}

			mutTrunc := plan
			mutTrunc.Revisions = plan.Revisions[:len(plan.Revisions)-1]
			if err := VerifyGoalPlan(mutTrunc, goalID, head); err == nil {
				t.Fatal("VerifyGoalPlan accepted truncated revision list")
			}
		}
	}

	f.Fuzz(func(t *testing.T, raw []byte, expectedGoalID, expectedHead string) {
		var plan GoalPlan
		if err := json.Unmarshal(raw, &plan); err != nil {
			if vErr := VerifyGoalPlan(GoalPlan{}, expectedGoalID, expectedHead); vErr == nil {
				t.Fatal("VerifyGoalPlan accepted zero GoalPlan")
			}
			return
		}
		if err := VerifyGoalPlan(plan, expectedGoalID, expectedHead); err == nil {
			checkAccepted(t, plan, expectedGoalID, expectedHead)
		}
		if plan.Spec.validate() == nil {
			derivedGoalID := plan.Spec.ID()
			derivedHead := plan.Head
			if derivedGoalID != expectedGoalID || derivedHead != expectedHead {
				if err := VerifyGoalPlan(plan, derivedGoalID, derivedHead); err == nil {
					checkAccepted(t, plan, derivedGoalID, derivedHead)
				}
			}
		}
	})
}
