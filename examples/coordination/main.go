// Run a small release-planning goal with independent attempts and a verified
// handoff. The simulated agents use separate signing keys in one local process.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WillBeebe/nexum/v2/nex"
)

type actor struct {
	identity nex.Identity
	public   nex.Public
}

func newActor() (actor, error) {
	identity, err := nex.NewIdentity()
	if err != nil {
		return actor{}, err
	}
	public, err := identity.Public()
	return actor{identity, public}, err
}

type artifact struct {
	name, content, mediaType string
}

func (a artifact) named() nex.NamedArtifact {
	digest := sha256.Sum256([]byte(a.content))
	return nex.NamedArtifact{Name: a.name, Ref: nex.ArtifactRef{
		Digest: hex.EncodeToString(digest[:]), Size: uint64(len(a.content)), MediaType: a.mediaType,
	}}
}

type demo struct {
	goal     string
	planner  actor
	witness  actor
	plans    *nex.GoalStore
	attempts *nex.ProtocolStore
	tasks    *nex.CoordinationStore
}

func openDemo(dir string) (*demo, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	planner, err := newActor()
	if err != nil {
		return nil, err
	}
	witness, err := newActor()
	if err != nil {
		return nil, err
	}
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
		Nonce: "release-decision", Purpose: "Prepare a release recommendation",
		ConstraintsHash:      nex.Hash("Use synthetic fixtures and perform no deployment"),
		CompletionPolicyHash: nex.Hash("Combine an independently reviewed patch and window with the safety handoff"),
		Planners:             []nex.Public{planner.public},
	})
	if err != nil {
		return nil, err
	}
	return &demo{goal: goal, planner: planner, witness: witness, plans: plans, attempts: attempts, tasks: tasks}, nil
}

func (d *demo) task(name, purpose, acceptance, output string, deps ...nex.TaskDependency) nex.TaskSpec {
	return nex.TaskSpec{
		GoalID: d.goal, Nonce: name, Purpose: purpose, Scope: "release/" + name, Authority: d.planner.public,
		SpecificationHash: nex.Hash(purpose), AcceptanceHash: nex.Hash(acceptance),
		FailurePolicyHash: nex.Hash("Preserve the available evidence and name missing obligations"),
		Outputs:           []string{output}, Dependencies: deps,
	}
}

func (d *demo) appendTasks(head, request string, tasks ...nex.TaskSpec) (string, error) {
	revision := nex.PlanRevision{GoalID: d.goal, Head: head, Planner: d.planner.public.ID(), RequestID: request, Tasks: tasks}
	return d.plans.Apply(revision, nex.Sign(d.planner.identity, nex.PlanSignatureDomain, revision))
}

type attempt struct {
	lease     nex.TaskLease
	spec      nex.ProtocolSpec
	worker    actor
	claim     nex.ClaimRequest
	signature []byte
}

func (d *demo) claim(task nex.TaskSpec, generation, height uint64) (attempt, error) {
	worker, err := newActor()
	if err != nil {
		return attempt{}, err
	}
	grant := func(id string, who actor, permissions ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{
			ID: id, Actor: who.public.ID(), Label: id, Scope: task.Scope, Permissions: permissions,
			ExpiresAtHeight: height + 12, LimitsHash: nex.Hash(task.Scope), EvidenceObligation: task.AcceptanceHash,
		}
	}
	spec := nex.ProtocolSpec{
		Version: nex.ProtocolVersionV2, TaskID: task.ID(), Generation: generation + 1,
		Nonce: fmt.Sprintf("%s-%d", task.Nonce, generation+1), Purpose: task.Purpose, IntendedOutcome: task.Purpose,
		Scope: task.Scope, SpecificationHash: task.SpecificationHash, AcceptanceHash: task.AcceptanceHash, FailurePolicyHash: task.FailurePolicyHash,
		Initiator: d.planner.public.ID(), Participants: []nex.Public{d.planner.public, worker.public, d.witness.public},
		Roles: []nex.RoleGrant{
			grant("owner", d.planner, nex.PermitCommit, nex.PermitDecide, nex.PermitReturn),
			grant("worker", worker, nex.PermitWork, nex.PermitReturn),
			grant("witness", d.witness, nex.PermitReview),
		},
		WorkByHeight: height + 8, ReturnByHeight: height + 12,
		RequiredWitnesses: []string{d.witness.public.ID()}, DissentPolicy: "block", MaxEvents: 16,
		Return: nex.ReturnRequirements{SuccessArtifacts: task.Outputs, AllowedDisposition: []string{"continue", "retry"}},
	}
	p, err := nex.NewProtocol(spec)
	if err != nil {
		return attempt{}, err
	}
	request := nex.ClaimRequest{
		GoalID: d.goal, TaskID: task.ID(), WorkerID: worker.public.ID(), RequestID: spec.Nonce,
		ProtocolID: p.View().ID, ExpectedGeneration: generation, LeaseUntilHeight: height + 14,
	}
	signature := nex.Sign(d.planner.identity, nex.ClaimSignatureDomain, request)
	lease, err := d.tasks.Claim(request, signature, spec, height)
	return attempt{lease: lease, spec: spec, worker: worker, claim: request, signature: signature}, err
}

func (d *demo) work(a attempt, height uint64, inputs []nex.NamedArtifact, output artifact, review func(string) error) (string, error) {
	apply := func(actor actor, grant, action string, fill func(*nex.ProtocolCommand)) (string, error) {
		scope := a.spec.Scope
		if action == "admit" {
			scope = ""
		}
		cmd, err := d.attempts.Prepare(a.lease.ProtocolID, actor.public.ID(), grant, scope, action, action, height)
		if err != nil {
			return "", err
		}
		if fill != nil {
			fill(&cmd)
		}
		return d.attempts.Apply(a.lease.ProtocolID, cmd, nex.Sign(actor.identity, "protocol", cmd), height)
	}
	for _, participant := range []actor{d.planner, a.worker, d.witness} {
		if _, err := apply(participant, "", "admit", nil); err != nil {
			return "", err
		}
	}
	if _, err := apply(d.planner, "owner", "commit", nil); err != nil {
		return "", err
	}

	named := output.named()
	report := nex.WorkReport{
		Outcome: nex.WorkCompleted, Stage: "produce " + output.name, ReasonHash: nex.Hash(a.spec.Purpose),
		Evidence: []string{named.Ref.Digest},
		Manifest: &nex.EvidenceManifest{Inputs: inputs, Outputs: []nex.NamedArtifact{named}, MethodHash: nex.Hash("local fixture")},
	}
	if _, err := apply(a.worker, "worker", "report", func(cmd *nex.ProtocolCommand) { cmd.Report = &report }); err != nil {
		return "", err
	}
	if review == nil {
		// Advance the host's clock to the return deadline while the required
		// witness is unavailable. An admitted returner can preserve the report.
		height = a.spec.ReturnByHeight
		return apply(d.planner, "owner", "incomplete", func(cmd *nex.ProtocolCommand) {
			cmd.Incomplete = &nex.IncompleteReturn{
				ReasonHash: nex.Hash("required witness did not respond before the deadline"),
				Evidence:   report.Evidence,
				Artifacts:  []nex.NamedArtifact{named},
			}
		})
	}
	if err := named.Ref.Verify(strings.NewReader(output.content)); err != nil {
		return "", err
	}
	if err := review(output.content); err != nil {
		return "", err
	}
	if _, err := apply(d.witness, "witness", "review", func(cmd *nex.ProtocolCommand) {
		cmd.Review = &nex.WitnessReview{ReportHash: nex.Hash(report), AssessmentHash: nex.Hash("fixture check passed")}
	}); err != nil {
		return "", err
	}
	resolution := &nex.Resolution{ReportHash: nex.Hash(report), Outcome: "accept", ReasonHash: nex.Hash("witness confirmed output")}
	if _, err := apply(d.planner, "owner", "resolve", func(cmd *nex.ProtocolCommand) { cmd.Resolution = resolution }); err != nil {
		return "", err
	}
	view, err := d.attempts.View(a.lease.ProtocolID)
	if err != nil {
		return "", err
	}
	return apply(a.worker, "worker", "return", func(cmd *nex.ProtocolCommand) {
		cmd.Return = &nex.ReturnManifest{
			ResolutionHash: nex.Hash(resolution), ReviewsHash: nex.Hash(view.Reviews), Evidence: report.Evidence,
			Artifacts:   []nex.ReturnArtifact{{ID: named.Name, Commitment: named.Ref.Digest, ReuseRestrictions: "Verify against the named input"}},
			Uncertainty: "Review covers the local fixture only", SafeAssumptions: []string{"No deployment was attempted"}, Disposition: "continue",
		}
	})
}

type completedTask struct {
	result   nex.TaskResult
	artifact artifact
	handoff  []byte
}

func (c completedTask) dependency(input string, outcome nex.TaskOutcome) nex.TaskDependency {
	return nex.TaskDependency{
		Input: input, TaskID: c.result.Lease.TaskID, ProtocolID: c.result.Lease.ProtocolID,
		Head: c.result.Head, Slot: c.artifact.name, Digest: c.artifact.named().Ref.Digest, Outcome: outcome,
	}
}

func (c completedTask) input(name string) (nex.NamedArtifact, error) {
	// The receiver has only the transported bundle and the task/result pins
	// obtained separately from its authenticated coordination channel.
	var handoff nex.TaskHandoff
	if err := json.Unmarshal(c.handoff, &handoff); err != nil {
		return nex.NamedArtifact{}, err
	}
	result, err := nex.VerifyTaskHandoff(handoff, c.result.Lease.TaskID, nex.Hash(c.result))
	if err != nil {
		return nex.NamedArtifact{}, err
	}
	ref := c.artifact.named().Ref
	for _, binding := range result.Artifacts {
		if binding.Slot == c.artifact.name && binding.Digest == ref.Digest {
			return nex.NamedArtifact{Name: name, Ref: ref}, ref.Verify(strings.NewReader(c.artifact.content))
		}
	}
	return nex.NamedArtifact{}, fmt.Errorf("missing verified binding for %q", c.artifact.name)
}

type report struct {
	Patch              nex.TaskOutcome `json:"patch"`
	Window             nex.TaskOutcome `json:"window"`
	Safety             nex.TaskOutcome `json:"safety"`
	Recommendation     nex.TaskOutcome `json:"recommendation"`
	Decision           string          `json:"decision"`
	StaleClaimRejected bool            `json:"stale_claim_rejected"`
	IncompleteBlocked  bool            `json:"incomplete_blocked_as_success"`
	PortableHandoffs   int             `json:"portable_handoffs_verified"`
}

func main() {
	dir, err := os.MkdirTemp("", "nex-coordination-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := func() error {
		defer os.RemoveAll(dir)
		result, err := run(dir)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// All four contributions use the same agreement API. The application supplies
// the work and review logic as well as the host's logical height.
func run(dir string) (report, error) {
	d, err := openDemo(dir)
	if err != nil {
		return report{}, err
	}
	patch := d.task("patch", "Prepare retry configuration", "Retry count is between 1 and 3", "config")
	window := d.task("window", "Find a mutually available release window", "Both schedules include the selected window", "window")
	safety := d.task("safety", "Check staging rollback readiness", "An independent review confirms a rollback snapshot", "observation")
	planHead, err := d.appendTasks(d.goal, "first-tasks", patch, window, safety)
	if err != nil {
		return report{}, err
	}

	config := artifact{"config", `{"max_attempts":3}`, "application/json"}
	checkConfig := func(body string) error {
		var value struct {
			MaxAttempts int `json:"max_attempts"`
		}
		if err := json.Unmarshal([]byte(body), &value); err != nil {
			return err
		}
		if value.MaxAttempts < 1 || value.MaxAttempts > 3 {
			return errors.New("retry limit outside the reviewed range")
		}
		return nil
	}

	oldPatch, err := d.claim(patch, 0, 1)
	if err != nil {
		return report{}, err
	}
	oldHead, err := d.work(oldPatch, 2, nil, config, checkConfig)
	if err != nil {
		return report{}, err
	}
	// The first worker completed an agreement but never finalized it.
	// Once its lease expires, a new worker must sign a fresh attempt.
	const workHeight = 16
	newPatch, err := d.claim(patch, oldPatch.lease.Generation, workHeight)
	if err != nil {
		return report{}, err
	}
	if _, err := d.tasks.Finalize(oldPatch.lease, oldHead, workHeight); !errors.Is(err, nex.ErrTaskStale) {
		return report{}, fmt.Errorf("old generation finalize got %v, want stale lease", err)
	}
	windowAttempt, err := d.claim(window, 0, workHeight)
	if err != nil {
		return report{}, err
	}
	safetyAttempt, err := d.claim(safety, 0, workHeight)
	if err != nil {
		return report{}, err
	}

	availability := []map[string]bool{
		{"Monday 09:00 UTC": true, "Monday 16:00 UTC": true},
		{"Monday 16:00 UTC": true, "Tuesday 09:00 UTC": true},
	}
	checkWindow := func(candidate string) error {
		for _, schedule := range availability {
			if !schedule[candidate] {
				return errors.New("selected window is missing from a schedule")
			}
		}
		return nil
	}
	findWindow := func() (artifact, error) {
		for _, candidate := range []string{"Monday 09:00 UTC", "Monday 16:00 UTC", "Tuesday 09:00 UTC"} {
			if checkWindow(candidate) == nil {
				return artifact{"window", candidate, "text/plain"}, nil
			}
		}
		return artifact{}, errors.New("no common release window")
	}
	parallel := []struct {
		attempt attempt
		produce func() (artifact, error)
		review  func(string) error
	}{
		{newPatch, func() (artifact, error) { return config, nil }, checkConfig},
		{windowAttempt, findWindow, checkWindow},
		{safetyAttempt, func() (artifact, error) {
			return artifact{"observation", "No rollback snapshot is referenced in staging", "text/plain"}, nil
		}, nil},
	}

	type completion struct {
		index  int
		head   string
		output artifact
		err    error
	}
	done := make(chan completion, len(parallel))
	for i, job := range parallel {
		go func() {
			output, err := job.produce()
			if err != nil {
				done <- completion{index: i, err: err}
				return
			}
			head, err := d.work(job.attempt, workHeight+1, nil, output, job.review)
			done <- completion{i, head, output, err}
		}()
	}
	completed := make([]completion, 0, len(parallel))
	for range parallel {
		completed = append(completed, <-done)
	}
	var finished [3]completedTask
	for _, event := range completed {
		job := parallel[event.index]
		if event.err != nil {
			return report{}, fmt.Errorf("task %q: %w", job.attempt.spec.Purpose, event.err)
		}
		result, err := d.tasks.Finalize(job.attempt.lease, event.head, safetyAttempt.spec.ReturnByHeight)
		if err != nil {
			return report{}, err
		}
		handoff, err := d.tasks.ExportHandoff(job.attempt.claim, job.attempt.signature)
		if err != nil {
			return report{}, err
		}
		wire, err := json.Marshal(handoff)
		if err != nil {
			return report{}, err
		}
		finished[event.index] = completedTask{result: result, artifact: event.output, handoff: wire}
	}
	patchResult, windowResult, safetyResult := finished[0], finished[1], finished[2]

	// One possible follow-up incorrectly expects a successful safety check.
	// A separate follow-up explicitly requests the incomplete observation.
	requireSafety := d.task("deploy", "Prepare a deployment", "A reviewed rollback plan is required", "plan",
		safetyResult.dependency("rollback", nex.TaskAccepted))
	synthesis := d.task("recommend", "Synthesize the release recommendation", "Honor the safety observation", "recommendation",
		patchResult.dependency("candidate-config", nex.TaskAccepted),
		windowResult.dependency("preferred-window", nex.TaskAccepted),
		safetyResult.dependency("rollback-observation", nex.TaskIncomplete))
	if _, err := d.appendTasks(planHead, "follow-ups", requireSafety, synthesis); err != nil {
		return report{}, err
	}
	nextHeight := safetyAttempt.spec.ReturnByHeight + 1
	if _, err := d.claim(requireSafety, 0, nextHeight); !errors.Is(err, nex.ErrTaskDependency) {
		return report{}, fmt.Errorf("success-only dependency got %v, want dependency rejection", err)
	}

	inputs := make([]nex.NamedArtifact, 0, len(finished))
	for i, task := range finished {
		input, err := task.input(synthesis.Dependencies[i].Input)
		if err != nil {
			return report{}, err
		}
		inputs = append(inputs, input)
	}
	recommendation := "Hold " + windowResult.artifact.content + " release until rollback readiness is independently verified"
	synthesisAttempt, err := d.claim(synthesis, 0, nextHeight)
	if err != nil {
		return report{}, err
	}
	head, err := d.work(synthesisAttempt, nextHeight+1, inputs, artifact{"recommendation", recommendation, "text/plain"}, func(body string) error {
		if !strings.HasPrefix(body, "Hold ") || safetyResult.result.Outcome != nex.TaskIncomplete {
			return errors.New("recommendation must hold release when rollback readiness is incomplete")
		}
		return nil
	})
	if err != nil {
		return report{}, err
	}
	result, err := d.tasks.Finalize(synthesisAttempt.lease, head, nextHeight+1)
	if err != nil {
		return report{}, err
	}
	return report{
		Patch: patchResult.result.Outcome, Window: windowResult.result.Outcome, Safety: safetyResult.result.Outcome,
		Recommendation: result.Outcome, Decision: recommendation, StaleClaimRejected: true, IncompleteBlocked: true,
		PortableHandoffs: len(inputs),
	}, nil
}
