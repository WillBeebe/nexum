package nex

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

type handoffFixture struct {
	world   protocolFixture
	store   *CoordinationStore
	request ClaimRequest
	sig     []byte
	lease   TaskLease
	p       *Protocol
}

func newHandoffFixture(t *testing.T, incomplete bool) handoffFixture {
	t.Helper()
	f := newProtocolFixture(t)
	owner := protocolPublic(f.owner)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{41}, 32)
	goals, err := OpenGoalStore(filepath.Join(dir, "goals"), key)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := OpenProtocolStore(filepath.Join(dir, "attempts"), key)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenCoordinationStore(filepath.Join(dir, "tasks"), key, goals, attempts)
	if err != nil {
		t.Fatal(err)
	}
	goalID, err := goals.Create(GoalSpec{Nonce: "handoff", Purpose: "Share verified contributions",
		ConstraintsHash: Hash("scope"), CompletionPolicyHash: Hash("review"), Planners: []Public{owner}})
	if err != nil {
		t.Fatal(err)
	}
	task := TaskSpec{GoalID: goalID, Nonce: "contribution", Purpose: f.spec.Purpose, Scope: f.spec.Scope,
		SpecificationHash: f.spec.SpecificationHash, AcceptanceHash: f.spec.AcceptanceHash,
		FailurePolicyHash: f.spec.FailurePolicyHash, Authority: owner,
		Outputs: f.spec.Return.SuccessArtifacts, FailureOutputs: f.spec.Return.FailureArtifacts}
	revision := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "plan", Tasks: []TaskSpec{task}}
	if _, err := goals.Apply(revision, Sign(f.owner, PlanSignatureDomain, revision)); err != nil {
		t.Fatal(err)
	}
	f.spec.Version = ProtocolVersionV2
	f.spec.TaskID = task.ID()
	f.spec.Generation = 1
	p, err := NewProtocol(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	request := ClaimRequest{GoalID: goalID, TaskID: task.ID(), WorkerID: protocolPublic(f.worker).ID(),
		RequestID: "attempt", ProtocolID: p.View().ID, LeaseUntilHeight: 41}
	sig := Sign(f.owner, ClaimSignatureDomain, request)
	lease, err := store.Claim(request, sig, f.spec, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExportHandoff(request, sig); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unfinalized attempt exported: %v", err)
	}
	if incomplete {
		protocolApply(t, p, f.owner, "", "admit", nil)
		command := p.Prepare(owner.ID(), "owner", f.spec.Scope, "incomplete", "closeout", f.spec.ReturnByHeight)
		command.Incomplete = &IncompleteReturn{ReasonHash: Hash("participants unavailable"), Artifacts: []NamedArtifact{{Name: "failure", Ref: testArtifactRef("partial observation")}}}
		if _, err := p.Apply(command, Sign(f.owner, "protocol", command), command.Height); err != nil {
			t.Fatal(err)
		}
	} else {
		p = enterProtocol(t, f)
		answer := testArtifactRef("reviewed contribution")
		protocolApply(t, p, f.worker, "worker", "report", func(c *ProtocolCommand) {
			c.Report = &WorkReport{Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("reason"), Evidence: []string{answer.Digest},
				Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: "answer", Ref: answer}}}}
		})
		reviewProtocol(t, p, f, false)
		resolveProtocol(t, p, f, "accept")
		protocolApply(t, p, f.worker, "worker", "return", func(c *ProtocolCommand) {
			m := manifestFor(p)
			m.Artifacts[0].Commitment = answer.Digest
			c.Return = &m
		})
	}
	for _, event := range p.Bundle().Events {
		if _, err := attempts.Apply(request.ProtocolID, event.Command, event.Signature, event.Command.Height); err != nil {
			t.Fatal(err)
		}
	}
	return handoffFixture{f, store, request, sig, lease, p}
}

func (f handoffFixture) finalize(t *testing.T) TaskHandoff {
	t.Helper()
	v := f.p.View()
	if _, err := f.store.Finalize(f.lease, v.Head, v.Height); err != nil {
		t.Fatal(err)
	}
	h, err := f.store.ExportHandoff(f.request, f.sig)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTaskHandoffExportAndOfflineVerification(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		t.Run(map[bool]string{false: "accepted", true: "incomplete"}[incomplete], func(t *testing.T) {
			f := newHandoffFixture(t, incomplete)
			h := f.finalize(t)
			// The consumer has only serialized public evidence and authenticated pins.
			raw, err := json.Marshal(h)
			if err != nil {
				t.Fatal(err)
			}
			var received TaskHandoff
			if err := json.Unmarshal(raw, &received); err != nil {
				t.Fatal(err)
			}
			got, err := VerifyTaskHandoff(received, f.request.TaskID, Hash(h.Result))
			if err != nil || !reflect.DeepEqual(got, h.Result) {
				t.Fatalf("verification got %+v: %v", got, err)
			}
			want := TaskAccepted
			if incomplete {
				want = TaskIncomplete
			}
			if got.Outcome != want {
				t.Fatalf("outcome=%s want=%s", got.Outcome, want)
			}
			got.Artifacts[0].Digest = Hash("caller mutation")
			if received.Result.Artifacts[0].Digest != h.Result.Artifacts[0].Digest {
				t.Fatal("verified output aliases supplied result")
			}
			if exported, err := f.store.ExportHandoff(f.request, Sign(f.world.worker, ClaimSignatureDomain, f.request)); err == nil || !reflect.DeepEqual(exported, TaskHandoff{}) {
				t.Fatal("export accepted an unauthorized claim signature")
			}
		})
	}
}

func TestTaskHandoffRejectsSubstitution(t *testing.T) {
	f := newHandoffFixture(t, false)
	original := f.finalize(t)
	tests := []struct {
		name   string
		change func(*TaskHandoff)
		repin  bool
	}{
		{"task terms", func(h *TaskHandoff) { h.Task.Purpose = "different task" }, false},
		{"foreign task pin", func(h *TaskHandoff) {
			h.Claim.TaskID = Hash("foreign task")
			h.ClaimSignature = Sign(f.world.owner, ClaimSignatureDomain, h.Claim)
		}, false},
		{"claim signer", func(h *TaskHandoff) { h.ClaimSignature = Sign(f.world.worker, ClaimSignatureDomain, h.Claim) }, false},
		{"worker", func(h *TaskHandoff) {
			h.Claim.WorkerID = protocolPublic(f.world.owner).ID()
			h.ClaimSignature = Sign(f.world.owner, ClaimSignatureDomain, h.Claim)
		}, false},
		{"generation", func(h *TaskHandoff) {
			h.Claim.ExpectedGeneration++
			h.ClaimSignature = Sign(f.world.owner, ClaimSignatureDomain, h.Claim)
		}, false},
		{"lease", func(h *TaskHandoff) { h.Result.Lease.LeaseUntilHeight++ }, true},
		{"artifact", func(h *TaskHandoff) { h.Result.Artifacts[0].Digest = Hash("unreviewed bytes") }, true},
		{"wildcard outcome", func(h *TaskHandoff) { h.Result.Outcome = "*" }, true},
		{"missing outcome", func(h *TaskHandoff) { h.Result.Outcome = "" }, true},
		{"truncated transcript", func(h *TaskHandoff) { h.Protocol.Events = h.Protocol.Events[:len(h.Protocol.Events)-1] }, false},
		{"forged event", func(h *TaskHandoff) { h.Protocol.Events[0].Signature[0] ^= 1 }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := cloneProtocol(original)
			test.change(&h)
			pin := Hash(original.Result)
			if test.repin {
				// Even a pinned receipt must agree with its signed evidence.
				pin = Hash(h.Result)
			}
			got, err := VerifyTaskHandoff(h, f.request.TaskID, pin)
			if !errors.Is(err, ErrTaskHandoff) || !reflect.DeepEqual(got, TaskResult{}) {
				t.Fatalf("invalid handoff returned %+v: %v", got, err)
			}
		})
	}
	for _, pins := range [][2]string{{"", Hash(original.Result)}, {f.request.TaskID, ""}, {Hash("other task"), Hash(original.Result)}, {f.request.TaskID, Hash("newer result")}} {
		if result, err := VerifyTaskHandoff(original, pins[0], pins[1]); !errors.Is(err, ErrTaskHandoff) || !reflect.DeepEqual(result, TaskResult{}) {
			t.Fatalf("ignored independent pins: %+v %v", result, err)
		}
	}
}

func TestTaskHandoffIncompleteCannotAuthorizeSuccess(t *testing.T) {
	f := newHandoffFixture(t, true)
	h := f.finalize(t)
	h.Result.Outcome = TaskAccepted
	if result, err := VerifyTaskHandoff(h, f.request.TaskID, Hash(h.Result)); !errors.Is(err, ErrTaskHandoff) || !reflect.DeepEqual(result, TaskResult{}) {
		t.Fatalf("incomplete evidence authorized success: %+v %v", result, err)
	}
}

func TestTaskHandoffRejectsTerminalEventAfterLease(t *testing.T) {
	f := newHandoffFixture(t, true)
	h := f.finalize(t)
	p, err := NewProtocol(h.Protocol.Spec)
	if err != nil {
		t.Fatal(err)
	}
	admission := h.Protocol.Events[0]
	if _, err := p.Apply(admission.Command, admission.Signature, admission.Command.Height); err != nil {
		t.Fatal(err)
	}
	closeout := h.Protocol.Events[1].Command
	closeout.Height = h.Result.Lease.LeaseUntilHeight
	if _, err := p.Apply(closeout, Sign(f.world.owner, "protocol", closeout), closeout.Height); err != nil {
		t.Fatal(err)
	}
	h.Protocol = p.Bundle()
	h.Result.Head = p.View().Head
	if result, err := VerifyTaskHandoff(h, f.request.TaskID, Hash(h.Result)); !errors.Is(err, ErrTaskHandoff) || !reflect.DeepEqual(result, TaskResult{}) {
		t.Fatalf("late terminal event accepted: %+v %v", result, err)
	}
}
