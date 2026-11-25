// Run an evidence-gated release governance Accord over real upstream
// coordination handoffs. Simulated agents use separate Ed25519 keys in one
// local process; temporary keys and directories are discarded on exit.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/WillBeebe/nexum/v2/nex"
)

const (
	releaseDissentRationale = "Prefer single-step Monday 16:00 UTC rollout once staging rollback snapshot is restored"
	accordScope             = "release/governance"
)

type actor struct {
	identity nex.Identity
	public   nex.Public
}

func newActor() (actor, error) {
	id, err := nex.NewIdentity()
	if err != nil {
		return actor{}, err
	}
	pub, err := id.Public()
	return actor{identity: id, public: pub}, err
}

type artifact struct {
	name, content, mediaType string
}

func (a artifact) named() nex.NamedArtifact {
	digest := sha256.Sum256([]byte(a.content))
	return nex.NamedArtifact{
		Name: a.name,
		Ref: nex.ArtifactRef{
			Digest:    hex.EncodeToString(digest[:]),
			Size:      uint64(len(a.content)),
			MediaType: a.mediaType,
		},
	}
}

type upstream struct {
	goal     string
	planner  actor
	witness  actor
	plans    *nex.GoalStore
	attempts *nex.ProtocolStore
	tasks    *nex.CoordinationStore
}

func openUpstream(dir string, key []byte, planner, witness actor) (*upstream, error) {
	plans, err := nex.OpenGoalStore(filepath.Join(dir, "plans"), key)
	if err != nil {
		return nil, err
	}
	attempts, err := nex.OpenProtocolStore(filepath.Join(dir, "attempts"), key)
	if err != nil {
		return nil, err
	}
	tasks, err := nex.OpenCoordinationStore(filepath.Join(dir, "tasks"), key, plans, attempts)
	if err != nil {
		return nil, err
	}
	goal, err := plans.Create(nex.GoalSpec{
		Nonce:                "release-evidence-v1",
		Purpose:              "Collect independently verified release readiness handoffs",
		ConstraintsHash:      nex.Hash("Use local fixtures and perform no deployment"),
		CompletionPolicyHash: nex.Hash("Feed verified task handoffs into a collective governance Accord"),
		Planners:             []nex.Public{planner.public},
	})
	if err != nil {
		return nil, err
	}
	return &upstream{
		goal: goal, planner: planner, witness: witness,
		plans: plans, attempts: attempts, tasks: tasks,
	}, nil
}

func (u *upstream) task(name, purpose, acceptance, output string) nex.TaskSpec {
	return nex.TaskSpec{
		GoalID:            u.goal,
		Nonce:             name,
		Purpose:           purpose,
		Scope:             "release/" + name,
		Authority:         u.planner.public,
		SpecificationHash: nex.Hash(purpose),
		AcceptanceHash:    nex.Hash(acceptance),
		FailurePolicyHash: nex.Hash("Preserve partial evidence and missing witness obligations"),
		Outputs:           []string{output},
	}
}

type taskAttempt struct {
	lease     nex.TaskLease
	spec      nex.ProtocolSpec
	worker    actor
	claim     nex.ClaimRequest
	signature []byte
}

func (u *upstream) claim(task nex.TaskSpec, height uint64) (taskAttempt, error) {
	worker, err := newActor()
	if err != nil {
		return taskAttempt{}, err
	}
	grant := func(id string, who actor, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{
			ID: id, Actor: who.public.ID(), Label: id, Scope: task.Scope, Permissions: perms,
			ExpiresAtHeight: height + 12, LimitsHash: nex.Hash(task.Scope), EvidenceObligation: task.AcceptanceHash,
		}
	}
	spec := nex.ProtocolSpec{
		Version: nex.ProtocolVersionV2, TaskID: task.ID(), Generation: 1,
		Nonce: task.Nonce + "-gen-1", Purpose: task.Purpose, IntendedOutcome: task.Purpose,
		Scope: task.Scope, SpecificationHash: task.SpecificationHash,
		AcceptanceHash: task.AcceptanceHash, FailurePolicyHash: task.FailurePolicyHash,
		Initiator:    u.planner.public.ID(),
		Participants: []nex.Public{u.planner.public, worker.public, u.witness.public},
		Roles: []nex.RoleGrant{
			grant("owner", u.planner, nex.PermitCommit, nex.PermitDecide, nex.PermitReturn),
			grant("worker", worker, nex.PermitWork, nex.PermitReturn),
			grant("witness", u.witness, nex.PermitReview),
		},
		WorkByHeight: height + 8, ReturnByHeight: height + 12,
		RequiredWitnesses: []string{u.witness.public.ID()}, DissentPolicy: "block", MaxEvents: 16,
		Return: nex.ReturnRequirements{SuccessArtifacts: task.Outputs, AllowedDisposition: []string{"continue", "retry"}},
	}
	p, err := nex.NewProtocol(spec)
	if err != nil {
		return taskAttempt{}, err
	}
	req := nex.ClaimRequest{
		GoalID: u.goal, TaskID: task.ID(), WorkerID: worker.public.ID(),
		RequestID: spec.Nonce, ProtocolID: p.View().ID,
		ExpectedGeneration: 0, LeaseUntilHeight: height + 14,
	}
	sig := nex.Sign(u.planner.identity, nex.ClaimSignatureDomain, req)
	lease, err := u.tasks.Claim(req, sig, spec, height)
	return taskAttempt{lease: lease, spec: spec, worker: worker, claim: req, signature: sig}, err
}

func (u *upstream) work(a taskAttempt, height uint64, out artifact, review func(string) error) (string, error) {
	apply := func(who actor, grant, action string, fill func(*nex.ProtocolCommand)) (string, error) {
		scope := a.spec.Scope
		if action == "admit" {
			scope = ""
		}
		cmd, err := u.attempts.Prepare(a.lease.ProtocolID, who.public.ID(), grant, scope, action, action, height)
		if err != nil {
			return "", err
		}
		if fill != nil {
			fill(&cmd)
		}
		return u.attempts.Apply(a.lease.ProtocolID, cmd, nex.Sign(who.identity, "protocol", cmd), height)
	}
	for _, participant := range []actor{u.planner, a.worker, u.witness} {
		if _, err := apply(participant, "", "admit", nil); err != nil {
			return "", err
		}
	}
	if _, err := apply(u.planner, "owner", "commit", nil); err != nil {
		return "", err
	}

	named := out.named()
	report := nex.WorkReport{
		Outcome: nex.WorkCompleted, Stage: "produce " + out.name, ReasonHash: nex.Hash(a.spec.Purpose),
		Evidence: []string{named.Ref.Digest},
		Manifest: &nex.EvidenceManifest{Outputs: []nex.NamedArtifact{named}, MethodHash: nex.Hash("local fixture")},
	}
	if _, err := apply(a.worker, "worker", "report", func(cmd *nex.ProtocolCommand) { cmd.Report = &report }); err != nil {
		return "", err
	}
	if review == nil {
		// Witness unavailable at the return deadline: close honestly as incomplete
		// while preserving the worker's partial observation artifact.
		height = a.spec.ReturnByHeight
		return apply(u.planner, "owner", "incomplete", func(cmd *nex.ProtocolCommand) {
			cmd.Incomplete = &nex.IncompleteReturn{
				ReasonHash: nex.Hash("required safety witness did not respond before deadline"),
				Evidence:   report.Evidence,
				Artifacts:  []nex.NamedArtifact{named},
			}
		})
	}
	if err := named.Ref.Verify(strings.NewReader(out.content)); err != nil {
		return "", err
	}
	if err := review(out.content); err != nil {
		return "", err
	}
	if _, err := apply(u.witness, "witness", "review", func(cmd *nex.ProtocolCommand) {
		cmd.Review = &nex.WitnessReview{
			ReportHash:     nex.Hash(report),
			AssessmentHash: nex.Hash("independent fixture check passed"),
		}
	}); err != nil {
		return "", err
	}
	res := &nex.Resolution{ReportHash: nex.Hash(report), Outcome: "accept", ReasonHash: nex.Hash("witness confirmed output")}
	if _, err := apply(u.planner, "owner", "resolve", func(cmd *nex.ProtocolCommand) { cmd.Resolution = res }); err != nil {
		return "", err
	}
	view, err := u.attempts.View(a.lease.ProtocolID)
	if err != nil {
		return "", err
	}
	return apply(a.worker, "worker", "return", func(cmd *nex.ProtocolCommand) {
		cmd.Return = &nex.ReturnManifest{
			ResolutionHash:  nex.Hash(res),
			ReviewsHash:     nex.Hash(view.Reviews),
			Evidence:        report.Evidence,
			Artifacts:       []nex.ReturnArtifact{{ID: named.Name, Commitment: named.Ref.Digest, ReuseRestrictions: "Verify bytes before rollout"}},
			Uncertainty:     "Review covers synthetic staging fixtures only",
			SafeAssumptions: []string{"No deployment was attempted"},
			Disposition:     "continue",
		}
	})
}

type verifiedTask struct {
	name        string
	task        nex.TaskSpec
	result      nex.TaskResult
	artifact    artifact
	handoffJSON []byte
}

func downstreamRolloutSpec(release, sre, safety actor, nonce, scope, purpose, acceptance string) nex.ProtocolSpec {
	grant := func(id string, who actor, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{
			ID: id, Actor: who.public.ID(), Label: id, Scope: scope, Permissions: perms,
			ExpiresAtHeight: 40, LimitsHash: nex.Hash(scope + ":" + id), EvidenceObligation: nex.Hash(acceptance),
		}
	}
	return nex.ProtocolSpec{
		Version: nex.ProtocolVersionV2, Nonce: nonce, Purpose: purpose, IntendedOutcome: purpose,
		Scope: scope, SpecificationHash: nex.Hash(purpose), AcceptanceHash: nex.Hash(acceptance),
		FailurePolicyHash: nex.Hash("Abort rollout and preserve rollback diagnostics"),
		Initiator:         release.public.ID(),
		Participants:      []nex.Public{release.public, sre.public, safety.public},
		Roles: []nex.RoleGrant{
			grant("owner", release, nex.PermitCommit, nex.PermitDecide, nex.PermitReturn),
			grant("worker", sre, nex.PermitWork, nex.PermitReturn),
			grant("witness", safety, nex.PermitReview),
		},
		WorkByHeight: 20, ReturnByHeight: 40,
		RequiredWitnesses: []string{safety.public.ID()}, DissentPolicy: "block", MaxEvents: 16,
		Return: nex.ReturnRequirements{
			SuccessArtifacts:   []string{"rollout-report"},
			AllowedDisposition: []string{"continue", "retry"},
		},
	}
}

type optionSummary struct {
	OptionID                string   `json:"option_id"`
	GuardPassed             bool     `json:"guard_passed"`
	SatisfiedEvidence       []string `json:"satisfied_evidence,omitempty"`
	FailedPredicates        []string `json:"failed_predicates,omitempty"`
	ApproveCount            uint64   `json:"approve_count"`
	ApproveWeight           uint64   `json:"approve_weight"`
	DissentCount            uint64   `json:"dissent_count"`
	DissentWeight           uint64   `json:"dissent_weight"`
	VetoEffective           bool     `json:"veto_effective"`
	Eligible                bool     `json:"eligible"`
	DisqualificationReasons []string `json:"disqualification_reasons,omitempty"`
}

type report struct {
	Example                     string                     `json:"example"`
	UpstreamOutcomes            map[string]nex.TaskOutcome `json:"upstream_outcomes"`
	AccordPhase                 nex.AccordPhase            `json:"accord_phase"`
	WinningOption               string                     `json:"winning_option"`
	WinningBindingKind          nex.BindingKind            `json:"winning_binding_kind"`
	ParticipatingCount          uint64                     `json:"participating_count"`
	ParticipatingWeight         uint64                     `json:"participating_weight"`
	Options                     []optionSummary            `json:"options"`
	WinningDissentsPreserved    int                        `json:"winning_dissents_preserved"`
	WinningDissentRationaleHash string                     `json:"winning_dissent_rationale_hash"`
	BoundedVetoCapEnforced      bool                       `json:"bounded_veto_cap_enforced"`
	ReopenRetryIdempotent       bool                       `json:"reopen_retry_idempotent"`
	TerminalRetryIdempotent     bool                       `json:"terminal_retry_idempotent"`
	OfflineBundleVerified       bool                       `json:"offline_bundle_verified"`
	OfflineArtifactsVerified    int                        `json:"offline_artifacts_verified"`
	DisqualifiedBindingRejected bool                       `json:"disqualified_binding_rejected"`
	AuthorizedDownstreamPhase   string                     `json:"authorized_downstream_phase"`
	DownstreamMatchesCommitment bool                       `json:"downstream_matches_commitment"`
}

type runArtifacts struct {
	report     report
	bundleJSON []byte
	accordID   string
	finalHead  string
}

func main() {
	dir, err := os.MkdirTemp("", "nex-accord-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := func() error {
		defer os.RemoveAll(dir)
		return runTo(dir, os.Stdout)
	}(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runTo(dir string, out io.Writer) error {
	res, err := execute(dir)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(res.report)
}

func run(dir string) (report, error) {
	res, err := execute(dir)
	if err != nil {
		return report{}, err
	}
	return res.report, nil
}

func execute(dir string) (runArtifacts, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return runArtifacts{}, err
	}

	// Distinct authenticated identities for upstream coordination and multi-role deliberation.
	planner, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	witness, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	release, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	sre, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	safety, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	security, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}

	// Stage 1: Execute three real upstream coordination tasks producing portable TaskHandoffs.
	up, err := openUpstream(dir, key, planner, witness)
	if err != nil {
		return runArtifacts{}, err
	}
	patchTask := up.task("patch", "Prepare retry configuration", "Retry limit is between 1 and 3", "config")
	windowTask := up.task("window", "Confirm release maintenance window", "Schedules agree on the selected window", "window")
	safetyTask := up.task("safety", "Verify staging rollback snapshot", "Independent witness confirms rollback readiness", "observation")
	rev := nex.PlanRevision{
		GoalID: up.goal, Head: up.goal, Planner: planner.public.ID(),
		RequestID: "upstream-plan-1", Tasks: []nex.TaskSpec{patchTask, windowTask, safetyTask},
	}
	if _, err := up.plans.Apply(rev, nex.Sign(planner.identity, nex.PlanSignatureDomain, rev)); err != nil {
		return runArtifacts{}, err
	}

	const upstreamHeight = 1
	patchAttempt, err := up.claim(patchTask, upstreamHeight)
	if err != nil {
		return runArtifacts{}, err
	}
	windowAttempt, err := up.claim(windowTask, upstreamHeight)
	if err != nil {
		return runArtifacts{}, err
	}
	safetyAttempt, err := up.claim(safetyTask, upstreamHeight)
	if err != nil {
		return runArtifacts{}, err
	}

	configArt := artifact{"config", `{"max_attempts":3}`, "application/json"}
	windowArt := artifact{"window", "Monday 16:00 UTC", "text/plain"}
	safetyArt := artifact{"observation", "No rollback snapshot is referenced in staging", "text/plain"}

	checkConfig := func(body string) error {
		var cfg struct {
			MaxAttempts int `json:"max_attempts"`
		}
		if err := json.Unmarshal([]byte(body), &cfg); err != nil {
			return err
		}
		if cfg.MaxAttempts < 1 || cfg.MaxAttempts > 3 {
			return errors.New("retry limit outside reviewed range")
		}
		return nil
	}
	checkWindow := func(body string) error {
		if body != "Monday 16:00 UTC" {
			return errors.New("window outside shared schedule")
		}
		return nil
	}

	jobs := []struct {
		name    string
		task    nex.TaskSpec
		attempt taskAttempt
		out     artifact
		review  func(string) error
	}{
		{"patch", patchTask, patchAttempt, configArt, checkConfig},
		{"window", windowTask, windowAttempt, windowArt, checkWindow},
		{"safety", safetyTask, safetyAttempt, safetyArt, nil},
	}

	type jobDone struct {
		index int
		head  string
		err   error
	}
	doneCh := make(chan jobDone, len(jobs))
	for i, job := range jobs {
		go func() {
			head, err := up.work(job.attempt, upstreamHeight+1, job.out, job.review)
			doneCh <- jobDone{index: i, head: head, err: err}
		}()
	}
	var finished [3]verifiedTask
	for range jobs {
		ev := <-doneCh
		job := jobs[ev.index]
		if ev.err != nil {
			return runArtifacts{}, fmt.Errorf("upstream task %q: %w", job.name, ev.err)
		}
		res, err := up.tasks.Finalize(job.attempt.lease, ev.head, safetyAttempt.spec.ReturnByHeight)
		if err != nil {
			return runArtifacts{}, err
		}
		handoff, err := up.tasks.ExportHandoff(job.attempt.claim, job.attempt.signature)
		if err != nil {
			return runArtifacts{}, err
		}
		wire, err := json.Marshal(handoff)
		if err != nil {
			return runArtifacts{}, err
		}
		finished[ev.index] = verifiedTask{
			name: job.name, task: job.task, result: res, artifact: job.out, handoffJSON: wire,
		}
	}
	patchVerified, windowVerified, safetyVerified := finished[0], finished[1], finished[2]

	// Stage 2: Define competing downstream commitments and an evidence-gated Accord.
	fullRolloutSpec := downstreamRolloutSpec(
		release, sre, safety,
		"full-rollout-v2", "release/full",
		"Execute full production rollout of retry configuration",
		"All regions healthy with verified staging rollback snapshot",
	)
	canaryRolloutSpec := downstreamRolloutSpec(
		release, sre, safety,
		"canary-rollout-v2", "release/canary",
		"Execute bounded 5% canary rollout with heightened rollback monitoring",
		"Canary error budget remains green while rollback snapshot is remediated",
	)
	holdActionHash := nex.Hash("Hold Monday 16:00 UTC release until rollback snapshot is independently verified")
	holdParamsHash := nex.Hash(`{"window":"Monday 16:00 UTC","block_reason":"missing_rollback_snapshot"}`)

	accordSpec := nex.AccordSpec{
		Version:    nex.AccordVersion,
		Nonce:      "release-governance-v1",
		Purpose:    "Select release execution plan gated by cryptographically verified upstream task handoffs",
		Scope:      accordScope,
		PolicyHash: nex.Hash("Full rollout requires accepted patch, window, and complete unwitnessed-free safety handoffs; canary requires safety and SRE approval"),
		Participants: []nex.Public{
			planner.public, release.public, sre.public, safety.public, security.public,
		},
		Roles: []nex.AccordRoleGrant{
			{
				ID: "coordinator", Actor: planner.public.ID(), Scope: accordScope,
				Permissions:     []nex.AccordPermission{nex.AccordPermitAttest, nex.AccordPermitResolve},
				ExpiresAtHeight: 20, LimitsHash: nex.Hash("independent evidence attester and deterministic resolver"),
			},
			{
				ID: "release-voter", Actor: release.public.ID(), Scope: accordScope,
				DomainRoles: []string{"release"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("release engineering vote"),
			},
			{
				ID: "sre-voter", Actor: sre.public.ID(), Scope: accordScope,
				DomainRoles: []string{"sre"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("sre operational readiness vote"),
			},
			{
				ID: "safety-reviewer", Actor: safety.public.ID(), Scope: accordScope,
				DomainRoles: []string{"safety"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote, nex.AccordPermitVeto},
				Weight: 3, ExpiresAtHeight: 15, LimitsHash: nex.Hash("safety vote and bounded evidence-cited veto"),
			},
			{
				ID: "security-reviewer", Actor: security.public.ID(), Scope: accordScope,
				DomainRoles: []string{"security"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote, nex.AccordPermitVeto},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("security vote and bounded evidence-cited veto"),
			},
		},
		Evidence: []nex.EvidenceSlot{
			{
				ID: "patch", Kind: nex.EvidenceTaskHandoff,
				GoalID: up.goal, TaskID: patchVerified.task.ID(),
				ExpectedAuthority:  planner.public.ID(),
				ExpectedResultHash: nex.Hash(patchVerified.result),
				MinGeneration:      1,
			},
			{
				ID: "window", Kind: nex.EvidenceTaskHandoff,
				GoalID: up.goal, TaskID: windowVerified.task.ID(),
				ExpectedAuthority:  planner.public.ID(),
				ExpectedResultHash: nex.Hash(windowVerified.result),
				MinGeneration:      1,
			},
			{
				// Demonstrates RequiredAttester + MinGeneration delegation alongside exact ExpectedResultHash pinning.
				ID: "safety", Kind: nex.EvidenceTaskHandoff,
				GoalID: up.goal, TaskID: safetyVerified.task.ID(),
				ExpectedAuthority: planner.public.ID(),
				MinGeneration:     1,
				RequiredAttester:  planner.public.ID(),
			},
		},
		Options: []nex.AccordOption{
			{
				ID: "full-rollout", Title: "Full production rollout across all regions", Priority: 1,
				Guard: nex.OptionGuard{
					AllOf: []nex.EvidencePredicate{
						{EvidenceID: "patch", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "config", Digest: configArt.named().Ref.Digest},
						{EvidenceID: "window", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "window", Digest: windowArt.named().Ref.Digest},
						{EvidenceID: "safety", Op: nex.GuardOutcomeIn, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}},
						// Fails closed on incomplete/unwitnessed handoffs even though HasWitnessDissent is false.
						{EvidenceID: "safety", Op: nex.GuardNoWitnessDissent},
					},
				},
				ExtraMandatoryRoles: []nex.RoleRequirement{{Role: "security", MinApprovals: 1, MinWeight: 2}},
				Binding:             nex.OptionBinding{Kind: nex.BindingProtocolSpec, ProtocolSpec: &fullRolloutSpec},
			},
			{
				ID: "canary-rollout", Title: "Bounded 5% canary rollout while rollback snapshot is remediated", Priority: 2,
				Guard: nex.OptionGuard{
					AllOf: []nex.EvidencePredicate{
						{EvidenceID: "patch", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "config", Digest: configArt.named().Ref.Digest},
						{EvidenceID: "window", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "window", Digest: windowArt.named().Ref.Digest},
						{EvidenceID: "safety", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted, nex.TaskIncomplete}, Slot: "observation", Digest: safetyArt.named().Ref.Digest},
					},
				},
				ExtraMandatoryRoles: []nex.RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}},
				Binding:             nex.OptionBinding{Kind: nex.BindingProtocolSpec, ProtocolSpec: &canaryRolloutSpec},
			},
			{
				ID: "hold-and-remediate", Title: "Hold release and remediate staging rollback snapshot", Priority: 3,
				Guard: nex.OptionGuard{
					AnyOf: []nex.EvidencePredicate{
						{EvidenceID: "safety", Op: nex.GuardOutcomeIn, Outcomes: []nex.TaskOutcome{nex.TaskIncomplete, nex.TaskRejected}},
						{EvidenceID: "safety", Op: nex.GuardHasWitnessDissent},
					},
				},
				Binding: nex.OptionBinding{
					Kind:           nex.BindingDisposition,
					Disposition:    "hold",
					ActionHash:     holdActionHash,
					ParametersHash: holdParamsHash,
				},
			},
		},
		VoteByHeight:    10,
		ResolveByHeight: 20,
		Rules: nex.DecisionRules{
			BallotMode:              nex.BallotSingleChoice,
			MinParticipationCount:   3,
			MinParticipationWeight:  6,
			MinApprovalCount:        2,
			MinApprovalWeight:       5,
			MinApprovalMarginWeight: 3,
			MandatoryRoles:          []nex.RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 3}},
			Veto: nex.VetoPolicy{
				Mode:               nex.VetoBlocking,
				MaxVetoesPerActor:  1,
				RequireEvidence:    true,
				AllowedDomainRoles: []string{"safety", "security"},
			},
			TieBreak:                   nex.TieBreakLowestPriority,
			RequireIndependentResolver: true,
		},
		MaxEvents: 64,
	}

	// Stage 3: Persist and drive the Accord through encrypted AccordStore with reopen + exact retry.
	accordDir := filepath.Join(dir, "accords")
	accords, err := nex.OpenAccordStore(accordDir, key)
	if err != nil {
		return runArtifacts{}, err
	}
	accordID, err := accords.Create(accordSpec)
	if err != nil {
		return runArtifacts{}, err
	}

	signAndApply := func(store *nex.AccordStore, who actor, grant, action, reqID string, height uint64, fill func(*nex.AccordCommand)) (nex.AccordCommand, []byte, string, error) {
		cmd, err := store.Prepare(accordID, who.public.ID(), grant, accordScope, action, reqID, height)
		if err != nil {
			return nex.AccordCommand{}, nil, "", err
		}
		if fill != nil {
			fill(&cmd)
		}
		sig, err := nex.SignAccordCommand(who.identity, cmd)
		if err != nil {
			return nex.AccordCommand{}, nil, "", err
		}
		receipt, err := store.Apply(accordID, cmd, sig, height)
		return cmd, sig, receipt, err
	}

	// Attest all three wire-decoded TaskHandoff proofs before voting.
	for i, vt := range finished {
		var wireHandoff nex.TaskHandoff
		if err := json.Unmarshal(vt.handoffJSON, &wireHandoff); err != nil {
			return runArtifacts{}, err
		}
		if _, _, _, err := signAndApply(accords, planner, "coordinator", "attest", "attest-"+vt.name, uint64(i+1), func(cmd *nex.AccordCommand) {
			cmd.Attest = &nex.AttestPayload{EvidenceID: vt.name, Handoff: &wireHandoff}
		}); err != nil {
			return runArtifacts{}, fmt.Errorf("attest %s: %w", vt.name, err)
		}
	}

	// Release prefers full-rollout and explicitly dissents on canary-rollout with a rationale digest.
	if _, _, _, err := signAndApply(accords, release, "release-voter", "vote", "vote-release-full", 4, func(cmd *nex.AccordCommand) {
		cmd.Vote = &nex.VotePayload{
			OptionID:      "full-rollout",
			Position:      nex.BallotApprove,
			RationaleHash: nex.Hash("Patch and window passed; prefer full rollout if rollback can be waived"),
		}
	}); err != nil {
		return runArtifacts{}, err
	}
	dissentCmd, dissentSig, dissentReceipt, err := signAndApply(accords, release, "release-voter", "vote", "vote-release-canary-dissent", 5, func(cmd *nex.AccordCommand) {
		cmd.Vote = &nex.VotePayload{
			OptionID:      "canary-rollout",
			Position:      nex.BallotDissent,
			RationaleHash: nex.Hash(releaseDissentRationale),
		}
	})
	if err != nil {
		return runArtifacts{}, err
	}

	// Simulate a lost response and process restart: reopen AccordStore with the SAME key
	// and retry the exact signed command without calling Prepare again.
	accords, err = nex.OpenAccordStore(accordDir, key)
	if err != nil {
		return runArtifacts{}, err
	}
	retryReceipt, err := accords.Apply(accordID, dissentCmd, dissentSig, 5)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("reopen idempotent retry failed: %w", err)
	}
	reopenRetryOK := retryReceipt == dissentReceipt

	// Safety records dissent + evidence-cited blocking veto on full-rollout, verifies the
	// MaxVetoesPerActor=1 cap, and approves canary-rollout.
	if _, _, _, err := signAndApply(accords, safety, "safety-reviewer", "vote", "vote-safety-full-dissent", 6, func(cmd *nex.AccordCommand) {
		cmd.Vote = &nex.VotePayload{
			OptionID:      "full-rollout",
			Position:      nex.BallotDissent,
			RationaleHash: nex.Hash("Staging rollback readiness is incomplete"),
		}
	}); err != nil {
		return runArtifacts{}, err
	}
	if _, _, _, err := signAndApply(accords, safety, "safety-reviewer", "veto", "veto-safety-full", 6, func(cmd *nex.AccordCommand) {
		cmd.Veto = &nex.VetoPayload{
			OptionID:    "full-rollout",
			ReasonHash:  nex.Hash("Blocking full rollout due to incomplete staging rollback handoff"),
			EvidenceIDs: []string{"safety"},
		}
	}); err != nil {
		return runArtifacts{}, err
	}
	// Attempting a second veto violates MaxVetoesPerActor=1 and must fail closed.
	_, _, _, secondVetoErr := signAndApply(accords, safety, "safety-reviewer", "veto", "veto-safety-hold-excess", 6, func(cmd *nex.AccordCommand) {
		cmd.Veto = &nex.VetoPayload{
			OptionID:    "hold-and-remediate",
			ReasonHash:  nex.Hash("Excess second veto beyond per-actor cap"),
			EvidenceIDs: []string{"safety"},
		}
	})
	if !errors.Is(secondVetoErr, nex.ErrAccordAuthority) {
		return runArtifacts{}, fmt.Errorf("second veto got %v, want ErrAccordAuthority", secondVetoErr)
	}
	if _, _, _, err := signAndApply(accords, safety, "safety-reviewer", "vote", "vote-safety-canary", 7, func(cmd *nex.AccordCommand) {
		cmd.Vote = &nex.VotePayload{
			OptionID:      "canary-rollout",
			Position:      nex.BallotApprove,
			RationaleHash: nex.Hash("5% blast radius is acceptable while staging rollback snapshot is restored"),
		}
	}); err != nil {
		return runArtifacts{}, err
	}
	if _, _, _, err := signAndApply(accords, sre, "sre-voter", "vote", "vote-sre-canary", 8, func(cmd *nex.AccordCommand) {
		cmd.Vote = &nex.VotePayload{
			OptionID:      "canary-rollout",
			Position:      nex.BallotApprove,
			RationaleHash: nex.Hash("SRE can monitor 5% canary and abort rapidly"),
		}
	}); err != nil {
		return runArtifacts{}, err
	}
	if _, _, _, err := signAndApply(accords, security, "security-reviewer", "vote", "vote-security-canary", 9, func(cmd *nex.AccordCommand) {
		cmd.Vote = &nex.VotePayload{
			OptionID:      "canary-rollout",
			Position:      nex.BallotApprove,
			RationaleHash: nex.Hash("Retry config within reviewed bounds; canary preserves containment"),
		}
	}); err != nil {
		return runArtifacts{}, err
	}

	// Independent resolver closes deliberation deterministically at VoteByHeight (10).
	_, _, finalHead, err := signAndApply(accords, planner, "coordinator", "resolve", "resolve-release", 10, func(cmd *nex.AccordCommand) {
		cmd.Resolve = &nex.ResolvePayload{ReasonHash: nex.Hash("Voting window closed; evaluate evidence guards and collective tally")}
	})
	if err != nil {
		return runArtifacts{}, err
	}

	// Reopen after terminal resolution and confirm historical exact retry still returns original receipt.
	reopenedFinal, err := nex.OpenAccordStore(accordDir, key)
	if err != nil {
		return runArtifacts{}, err
	}
	terminalRetry, err := reopenedFinal.Apply(accordID, dissentCmd, dissentSig, 5)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("post-terminal historical retry failed: %w", err)
	}
	terminalRetryOK := terminalRetry == dissentReceipt

	// Stage 4: Export portable AccordBundle across an offline wire boundary (zero private keys, zero source store).
	exported, err := reopenedFinal.Export(accordID)
	if err != nil {
		return runArtifacts{}, err
	}
	bundleJSON, err := json.Marshal(exported)
	if err != nil {
		return runArtifacts{}, err
	}
	var wireBundle nex.AccordBundle
	if err := json.Unmarshal(bundleJSON, &wireBundle); err != nil {
		return runArtifacts{}, err
	}

	verifiedView, err := nex.VerifyAccordBundle(wireBundle, accordID, finalHead)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("offline VerifyAccordBundle failed: %w", err)
	}
	if verifiedView.Outcome == nil || verifiedView.Phase != nex.AccordPhaseDecided {
		return runArtifacts{}, fmt.Errorf("unexpected verified phase: %q", verifiedView.Phase)
	}

	// Offline consumer verifies raw upstream artifact bytes against kernel-derived ArtifactRefs.
	rawArtifacts := map[string]string{
		"config":      configArt.content,
		"window":      windowArt.content,
		"observation": safetyArt.content,
	}
	offlineArtifacts := 0
	for _, fact := range verifiedView.Outcome.EvidenceSummary {
		for _, ref := range fact.ArtifactRefs {
			content, ok := rawArtifacts[ref.Name]
			if !ok {
				return runArtifacts{}, fmt.Errorf("unexpected artifact ref %q", ref.Name)
			}
			if err := ref.Ref.Verify(strings.NewReader(content)); err != nil {
				return runArtifacts{}, fmt.Errorf("offline artifact %q verify: %w", ref.Name, err)
			}
			offlineArtifacts++
		}
	}

	// Stage 5: Enforceable downstream binding — disqualified full-rollout is rejected;
	// winning canary-rollout is created directly from the verified AccordBundle and committed.
	if _, _, err := nex.AuthorizeProtocolFromAccord(wireBundle, accordID, finalHead, fullRolloutSpec); !errors.Is(err, nex.ErrAccordBinding) {
		return runArtifacts{}, fmt.Errorf("disqualified full-rollout authorize got %v, want ErrAccordBinding", err)
	}
	if _, err := nex.AuthorizeDispositionFromAccord(wireBundle, accordID, finalHead, "hold", holdActionHash, holdParamsHash); !errors.Is(err, nex.ErrAccordBinding) {
		return runArtifacts{}, fmt.Errorf("non-winning disposition authorize got %v, want ErrAccordBinding", err)
	}

	downstreamStore, err := nex.OpenProtocolStore(filepath.Join(dir, "downstream-protocols"), key)
	if err != nil {
		return runArtifacts{}, err
	}
	downstreamID, _, err := nex.CreateProtocolFromAccord(downstreamStore, wireBundle, accordID, finalHead)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("CreateProtocolFromAccord failed: %w", err)
	}
	if downstreamID != verifiedView.Outcome.WinningCommitment {
		return runArtifacts{}, fmt.Errorf("downstream ID %s != winning commitment %s", downstreamID, verifiedView.Outcome.WinningCommitment)
	}

	// Admit and commit the authorized downstream canary protocol.
	applyDownstream := func(who actor, grant, scope, action string, height uint64) error {
		cmd, err := downstreamStore.Prepare(downstreamID, who.public.ID(), grant, scope, action, action+"-"+who.public.ID()[:8], height)
		if err != nil {
			return err
		}
		_, err = downstreamStore.Apply(downstreamID, cmd, nex.Sign(who.identity, "protocol", cmd), height)
		return err
	}
	for i, participant := range []actor{release, sre, safety} {
		if err := applyDownstream(participant, "", "", "admit", uint64(i+1)); err != nil {
			return runArtifacts{}, err
		}
	}
	if err := applyDownstream(release, "owner", canaryRolloutSpec.Scope, "commit", 4); err != nil {
		return runArtifacts{}, err
	}
	downstreamView, err := downstreamStore.View(downstreamID)
	if err != nil {
		return runArtifacts{}, err
	}

	// Build concise deterministic report.
	optSummaries := make([]optionSummary, 0, len(verifiedView.Outcome.Tallies))
	for _, t := range verifiedView.Outcome.Tallies {
		var failed []string
		for _, fp := range t.FailedPredicates {
			failed = append(failed, fmt.Sprintf("%s:%s:%s", fp.EvidenceID, fp.Op, fp.Reason))
		}
		optSummaries = append(optSummaries, optionSummary{
			OptionID:                t.OptionID,
			GuardPassed:             t.GuardPassed,
			SatisfiedEvidence:       slices.Clone(t.SatisfiedEvidenceIDs),
			FailedPredicates:        failed,
			ApproveCount:            t.ApproveCount,
			ApproveWeight:           t.ApproveWeight,
			DissentCount:            t.DissentCount,
			DissentWeight:           t.DissentWeight,
			VetoEffective:           t.VetoEffective,
			Eligible:                t.Eligible,
			DisqualificationReasons: slices.Clone(t.DisqualificationReasons),
		})
	}
	dissentHash := ""
	if len(verifiedView.Outcome.WinningOptionDissents) > 0 {
		dissentHash = verifiedView.Outcome.WinningOptionDissents[0].RationaleHash
	}

	rep := report{
		Example: "accord",
		UpstreamOutcomes: map[string]nex.TaskOutcome{
			"patch":  patchVerified.result.Outcome,
			"window": windowVerified.result.Outcome,
			"safety": safetyVerified.result.Outcome,
		},
		AccordPhase:                 verifiedView.Phase,
		WinningOption:               verifiedView.Outcome.WinningOptionID,
		WinningBindingKind:          verifiedView.Outcome.WinningBinding.Kind,
		ParticipatingCount:          verifiedView.Outcome.ParticipatingCount,
		ParticipatingWeight:         verifiedView.Outcome.ParticipatingWeight,
		Options:                     optSummaries,
		WinningDissentsPreserved:    len(verifiedView.Outcome.WinningOptionDissents),
		WinningDissentRationaleHash: dissentHash,
		BoundedVetoCapEnforced:      errors.Is(secondVetoErr, nex.ErrAccordAuthority),
		ReopenRetryIdempotent:       reopenRetryOK,
		TerminalRetryIdempotent:     terminalRetryOK,
		OfflineBundleVerified:       true,
		OfflineArtifactsVerified:    offlineArtifacts,
		DisqualifiedBindingRejected: true,
		AuthorizedDownstreamPhase:   downstreamView.Phase,
		DownstreamMatchesCommitment: downstreamID == verifiedView.Outcome.WinningCommitment,
	}
	return runArtifacts{
		report:     rep,
		bundleJSON: bundleJSON,
		accordID:   accordID,
		finalHead:  finalHead,
	}, nil
}
