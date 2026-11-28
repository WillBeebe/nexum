package nex

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCoordinationClaimCASAndRecovery(t *testing.T) {
	f := newProtocolFixture(t)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{21}, 32)
	goals, err := OpenGoalStore(filepath.Join(dir, "goals"), key)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := OpenProtocolStore(filepath.Join(dir, "attempts"), key)
	if err != nil {
		t.Fatal(err)
	}
	tasksDir := filepath.Join(dir, "tasks")
	tasks, err := OpenCoordinationStore(tasksDir, key, goals, attempts)
	if err != nil {
		t.Fatal(err)
	}
	owner := protocolPublic(f.owner)
	goal := GoalSpec{Nonce: "claim-race", Purpose: "Coordinate work", ConstraintsHash: Hash("constraints"),
		CompletionPolicyHash: Hash("policy"), Planners: []Public{owner}}
	goalID, err := goals.Create(goal)
	if err != nil {
		t.Fatal(err)
	}
	task := TaskSpec{GoalID: goalID, Nonce: "task", Purpose: f.spec.Purpose, Scope: f.spec.Scope,
		SpecificationHash: f.spec.SpecificationHash, AcceptanceHash: f.spec.AcceptanceHash,
		FailurePolicyHash: f.spec.FailurePolicyHash, Authority: owner,
		Outputs: f.spec.Return.SuccessArtifacts, FailureOutputs: f.spec.Return.FailureArtifacts}
	rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "plan", Tasks: []TaskSpec{task}}
	if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}

	type candidate struct {
		spec ProtocolSpec
		req  ClaimRequest
		sig  []byte
	}
	makeCandidate := func(name string, generation, leaseUntil uint64) candidate {
		t.Helper()
		spec := f.spec
		spec.Version = ProtocolVersionV2
		spec.TaskID, spec.Generation = task.ID(), generation
		spec.Nonce = name
		p, err := NewProtocol(spec)
		if err != nil {
			t.Fatal(err)
		}
		req := ClaimRequest{GoalID: goalID, TaskID: task.ID(), ProtocolID: p.View().ID,
			WorkerID: protocolPublic(f.worker).ID(), RequestID: name,
			ExpectedGeneration: generation - 1, LeaseUntilHeight: leaseUntil}
		return candidate{spec, req, Sign(f.owner, ClaimSignatureDomain, req)}
	}
	a, b := makeCandidate("a", 1, 41), makeCandidate("b", 1, 42)
	if _, err := tasks.Claim(a.req, Sign(f.worker, ClaimSignatureDomain, a.req), a.spec, 1); err == nil {
		t.Fatal("worker issued a lease without the task authority")
	}

	// The protocol can exist before its lease does. Crash before the task rename
	// and verify that no caller receives a usable lease until the claim commits.
	fault := errors.New("injected pre-rename failure")
	tasks.store.commitHook = func(stage string) error {
		if stage == "before-rename" {
			return fault
		}
		return nil
	}
	if lease, err := tasks.Claim(a.req, a.sig, a.spec, 1); !errors.Is(err, fault) || lease != (TaskLease{}) {
		t.Fatalf("lease=%+v err=%v", lease, err)
	}
	if _, err := tasks.Finalize(TaskLease{GoalID: goalID, TaskID: task.ID(), ProtocolID: a.req.ProtocolID}, a.req.ProtocolID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan attempt authorized a result: %v", err)
	}
	tasks.store.commitHook = nil

	// Separate handles exercise the actual per-task OS lock.
	other, err := OpenCoordinationStore(tasksDir, key, goals, attempts)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		candidate candidate
		lease     TaskLease
		err       error
	}
	results := make(chan outcome, 2)
	claim := func(s *CoordinationStore, c candidate) {
		lease, err := s.Claim(c.req, c.sig, c.spec, 1)
		results <- outcome{c, lease, err}
	}
	go claim(tasks, a)
	go claim(other, b)
	first, second := <-results, <-results
	if first.err != nil {
		first, second = second, first
	}
	if first.err != nil || !errors.Is(second.err, ErrTaskStale) || first.lease.Generation != 1 {
		t.Fatalf("first=%+v second=%+v", first.err, second.err)
	}
	winner := first.candidate
	if got, err := other.Claim(winner.req, winner.sig, winner.spec, 2); err != nil || got != first.lease {
		t.Fatalf("exact claim retry: %+v %v", got, err)
	}
	if lease, err := other.Claim(winner.req, winner.sig, winner.spec, first.lease.LeaseUntilHeight); !errors.Is(err, ErrTaskStale) || lease != (TaskLease{}) {
		t.Fatalf("expired claim retry: %+v %v", lease, err)
	}
}

func TestStatusAtReclaimableBeforeLeaseExpiryAndDiscoverGoal(t *testing.T) {
	f := newHandoffFixture(t, true)
	v := f.p.View()
	closeoutHeight := v.Height
	if closeoutHeight >= f.lease.LeaseUntilHeight {
		t.Fatalf("fixture closeout height %d not before lease %d", closeoutHeight, f.lease.LeaseUntilHeight)
	}
	if _, err := f.store.Finalize(f.lease, v.Head, closeoutHeight); err != nil {
		t.Fatal(err)
	}
	status, err := f.store.StatusAt(f.request.GoalID, f.request.TaskID, closeoutHeight)
	if err != nil {
		t.Fatal(err)
	}
	if status != "reclaimable" {
		t.Fatalf("StatusAt=%q want reclaimable before lease expiry", status)
	}

	first, lockReads, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight)
	if err != nil {
		t.Fatal(err)
	}
	if lockReads == 0 {
		t.Fatal("first DiscoverGoal expected lockReads > 0")
	}
	if len(first) != 1 || first[0].Status != "reclaimable" || first[0].TaskID != f.request.TaskID {
		t.Fatalf("first discovery=%+v", first)
	}

	second, lockReads, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight)
	if err != nil {
		t.Fatal(err)
	}
	if lockReads != 0 {
		t.Fatalf("cached DiscoverGoal lockReads=%d want 0", lockReads)
	}
	if len(second) != 1 || second[0].Status != "reclaimable" {
		t.Fatalf("second discovery=%+v", second)
	}

	other, err := OpenCoordinationStore(f.store.store.dir, bytes.Repeat([]byte{41}, 32), f.store.goals, f.store.attempts)
	if err != nil {
		t.Fatal(err)
	}
	spec := f.world.spec
	spec.Version = ProtocolVersionV2
	spec.TaskID = f.request.TaskID
	spec.Generation = 2
	spec.Nonce = "reclaim"
	p, err := NewProtocol(spec)
	if err != nil {
		t.Fatal(err)
	}
	req := ClaimRequest{
		GoalID: f.request.GoalID, TaskID: f.request.TaskID, ProtocolID: p.View().ID,
		WorkerID: protocolPublic(f.world.worker).ID(), RequestID: "reclaim",
		ExpectedGeneration: 1, LeaseUntilHeight: f.lease.LeaseUntilHeight,
	}
	sig := Sign(f.world.owner, ClaimSignatureDomain, req)
	if _, err := other.Claim(req, sig, spec, 2); err != nil {
		t.Fatal(err)
	}

	third, lockReads, err := f.store.DiscoverGoal(f.request.GoalID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if lockReads == 0 {
		t.Fatal("DiscoverGoal after foreign mutation expected lockReads > 0")
	}
	if len(third) != 1 || third[0].Status != "active" || third[0].Generation != 2 {
		t.Fatalf("after reclaim discovery=%+v", third)
	}
}

func TestDiscoverGoalAuthenticatesCiphertextOnInPlaceTamper(t *testing.T) {
	f := newHandoffFixture(t, true)
	v := f.p.View()
	closeoutHeight := v.Height
	if _, err := f.store.Finalize(f.lease, v.Head, closeoutHeight); err != nil {
		t.Fatal(err)
	}

	// 1. Warm the DiscoverGoal cache and verify second call hits cache while still authenticating ciphertext.
	first, misses1, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight)
	if err != nil {
		t.Fatal(err)
	}
	if misses1 != 1 || len(first) != 1 || first[0].Status != "reclaimable" {
		t.Fatalf("first warm discovery misses=%d res=%+v", misses1, first)
	}
	stats1 := f.store.Stats()

	second, misses2, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight)
	if err != nil {
		t.Fatal(err)
	}
	if misses2 != 0 || len(second) != 1 || second[0].Status != "reclaimable" {
		t.Fatalf("second warm discovery misses=%d res=%+v", misses2, second)
	}
	stats2 := f.store.Stats()
	if stats2.AuthDecryptOps <= stats1.AuthDecryptOps || stats2.CacheHits <= stats1.CacheHits {
		t.Fatalf("expected warm DiscoverGoal to authenticate ciphertext and hit cache: before=%+v after=%+v", stats1, stats2)
	}
	if stats2.ReplayValidationOps != stats1.ReplayValidationOps {
		t.Fatalf("expected warm DiscoverGoal to skip checkpoint replay/validation: before=%+v after=%+v", stats1, stats2)
	}

	// 2. Modify stored ciphertext IN PLACE on the exact same inode, preserving size and restoring ModTime.
	cpPath := f.store.store.path(f.request.TaskID)
	origInfo, err := os.Lstat(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	origBytes, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(origBytes)
	tampered[len(tampered)-1] ^= 0xff

	fh, err := os.OpenFile(cpPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fh.WriteAt(tampered, 0); err != nil {
		fh.Close()
		t.Fatal(err)
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(cpPath, origInfo.ModTime(), origInfo.ModTime()); err != nil {
		t.Fatal(err)
	}

	afterTamperInfo, err := os.Lstat(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(origInfo, afterTamperInfo) || afterTamperInfo.Size() != origInfo.Size() || !afterTamperInfo.ModTime().Equal(origInfo.ModTime()) {
		t.Fatalf("in-place tamper setup did not preserve inode/size/mtime: orig=%v/%d after=%v/%d",
			origInfo.ModTime(), origInfo.Size(), afterTamperInfo.ModTime(), afterTamperInfo.Size())
	}

	// 3. Require DiscoverGoal to reject corrupted ciphertext with ErrCorruptStore instead of returning stale cache.
	if _, _, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("DiscoverGoal after in-place ciphertext tamper returned err=%v, want ErrCorruptStore", err)
	}

	// Restore valid ciphertext and verify DiscoverGoal recovers cleanly.
	fhRestore, err := os.OpenFile(cpPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fhRestore.WriteAt(origBytes, 0); err != nil {
		fhRestore.Close()
		t.Fatal(err)
	}
	_ = fhRestore.Sync()
	_ = fhRestore.Close()
	_ = os.Chtimes(cpPath, origInfo.ModTime(), origInfo.ModTime())

	recovered, missesRec, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight)
	if err != nil || missesRec != 0 || len(recovered) != 1 || recovered[0].Status != "reclaimable" {
		t.Fatalf("DiscoverGoal after restoring valid ciphertext: err=%v misses=%d res=%+v", err, missesRec, recovered)
	}

	// 4. Confirm legitimate updates through another store handle remain immediately visible.
	other, err := OpenCoordinationStore(f.store.store.dir, bytes.Repeat([]byte{41}, 32), f.store.goals, f.store.attempts)
	if err != nil {
		t.Fatal(err)
	}
	spec := f.world.spec
	spec.Version = ProtocolVersionV2
	spec.TaskID = f.request.TaskID
	spec.Generation = 2
	spec.Nonce = "legit-cross-handle-update"
	spec.WorkByHeight = closeoutHeight + 5
	spec.ReturnByHeight = closeoutHeight + 8
	for i := range spec.Roles {
		spec.Roles[i].ExpiresAtHeight = closeoutHeight + 8
	}
	p, err := NewProtocol(spec)
	if err != nil {
		t.Fatal(err)
	}
	req := ClaimRequest{
		GoalID: f.request.GoalID, TaskID: f.request.TaskID, ProtocolID: p.View().ID,
		WorkerID: protocolPublic(f.world.worker).ID(), RequestID: "legit-cross-handle-update",
		ExpectedGeneration: 1, LeaseUntilHeight: closeoutHeight + 12,
	}
	sig := Sign(f.world.owner, ClaimSignatureDomain, req)
	if _, err := other.Claim(req, sig, spec, closeoutHeight); err != nil {
		t.Fatal(err)
	}

	updated, missesUpd, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight)
	if err != nil {
		t.Fatal(err)
	}
	if missesUpd == 0 || len(updated) != 1 || updated[0].Status != "active" || updated[0].Generation != 2 {
		t.Fatalf("DiscoverGoal after legitimate cross-handle update: misses=%d res=%+v", missesUpd, updated)
	}
}

func TestCoordinationStoreCacheInvalidatedBeforeUncertainWrite(t *testing.T) {
	f := newHandoffFixture(t, true)
	v := f.p.View()
	closeoutHeight := v.Height

	// Warm the cache for this task before Finalize.
	if _, _, err := f.store.DiscoverGoal(f.request.GoalID, closeoutHeight); err != nil {
		t.Fatal(err)
	}
	f.store.mu.Lock()
	_, warm := f.store.cache[f.request.TaskID]
	f.store.mu.Unlock()
	if !warm {
		t.Fatal("expected DiscoverGoal to warm task cache")
	}

	// Inject ErrCommitUncertain after os.Rename during Finalize; cache must ALREADY be invalidated!
	f.store.store.commitHook = func(stage string) error {
		if stage == "after-rename" {
			return errors.New("injected post-rename sync failure")
		}
		return nil
	}
	_, err := f.store.Finalize(f.lease, v.Head, closeoutHeight)
	f.store.store.commitHook = nil
	if !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("expected ErrCommitUncertain, got %v", err)
	}
	f.store.mu.Lock()
	_, stillCached := f.store.cache[f.request.TaskID]
	f.store.mu.Unlock()
	if stillCached {
		t.Fatal("stale pre-rename entry remained in CoordinationStore cache after uncertain Finalize write")
	}
}

func TestDiscoverGoalSurfacesCorruptDependency(t *testing.T) {
	planner, goal, first := planFixture(t)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{43}, 32)
	goals, err := OpenGoalStore(filepath.Join(dir, "goals"), key)
	if err != nil {
		t.Fatal(err)
	}
	goalID, err := goals.Create(goal)
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Nonce = "downstream"
	second.Purpose = "Consume upstream artifact"
	second.Dependencies = []TaskDependency{{
		Input: "upstream", TaskID: first.ID(), ProtocolID: Hash("proto-upstream"),
		Head: Hash("head-upstream"), Slot: "change", Digest: Hash("digest-upstream"), Outcome: TaskAccepted,
	}}
	rev := PlanRevision{
		GoalID: goalID, Head: goalID, Planner: goal.Planners[0].ID(), RequestID: "r1",
		Tasks: []TaskSpec{first, second},
	}
	if _, err := goals.Apply(rev, Sign(planner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}
	protocols, err := OpenProtocolStore(filepath.Join(dir, "protocols"), key)
	if err != nil {
		t.Fatal(err)
	}
	coord, err := OpenCoordinationStore(filepath.Join(dir, "coord"), key, goals, protocols)
	if err != nil {
		t.Fatal(err)
	}
	// When upstream is merely unclaimed, DiscoverGoal must not perform a redundant s.Result read.
	unclaimed, misses, err := coord.DiscoverGoal(goalID, 1)
	if err != nil {
		t.Fatalf("DiscoverGoal unclaimed: %v", err)
	}
	if misses != 0 || len(unclaimed) != 2 || unclaimed[1].DependenciesReady {
		t.Fatalf("unexpected unclaimed discovery: misses=%d out=%+v", misses, unclaimed)
	}
	// Write corrupt ciphertext at the upstream dependency's coordination path; DiscoverGoal must surface ErrCorruptStore.
	if err := os.WriteFile(coord.store.path(first.ID()), []byte("corrupt-ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := coord.DiscoverGoal(goalID, 1); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("expected DiscoverGoal to surface ErrCorruptStore on corrupt dependency, got %v", err)
	}
}

func TestLoadAuthenticatedCachedRejectsWrongGoalID(t *testing.T) {
	f := newHandoffFixture(t, true)
	v := f.p.View()
	if _, err := f.store.Finalize(f.lease, v.Head, v.Height); err != nil {
		t.Fatal(err)
	}
	// Warm the cache under the real goal ID.
	if _, misses, err := f.store.DiscoverGoal(f.request.GoalID, v.Height); err != nil || misses != 1 {
		t.Fatalf("warm DiscoverGoal: misses=%d err=%v", misses, err)
	}
	// Querying the same task checkpoint under a different goal ID must still fail
	// with ErrCorruptStore instead of returning the warm cached state.
	otherGoal := Hash("foreign-goal")
	err := f.store.store.withLocked(f.request.TaskID, func(tx checkpointTx) error {
		_, _, err := f.store.loadAuthenticatedCached(tx, otherGoal, f.request.TaskID)
		return err
	})
	if !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("loadAuthenticatedCached with wrong goalID got %v, want ErrCorruptStore", err)
	}
}

func TestCoordinationDownstreamDependencyEnforcementAndRejection(t *testing.T) {
	f := newProtocolFixture(t)
	dir := t.TempDir()
	key := bytes.Repeat([]byte{47}, 32)
	goals, err := OpenGoalStore(filepath.Join(dir, "goals"), key)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := OpenProtocolStore(filepath.Join(dir, "attempts"), key)
	if err != nil {
		t.Fatal(err)
	}
	coord, err := OpenCoordinationStore(filepath.Join(dir, "tasks"), key, goals, attempts)
	if err != nil {
		t.Fatal(err)
	}
	owner := protocolPublic(f.owner)
	workerID := protocolPublic(f.worker).ID()
	goalID, err := goals.Create(GoalSpec{
		Nonce: "dep-enforcement", Purpose: "Verify rejection handoff and downstream input binding",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	upstream := TaskSpec{
		GoalID: goalID, Nonce: "upstream", Purpose: f.spec.Purpose, Scope: f.spec.Scope,
		SpecificationHash: f.spec.SpecificationHash, AcceptanceHash: f.spec.AcceptanceHash,
		FailurePolicyHash: f.spec.FailurePolicyHash, Authority: owner,
		Outputs: []string{"answer"}, FailureOutputs: []string{"failure"},
	}
	rev1 := PlanRevision{
		GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "plan-1", Tasks: []TaskSpec{upstream},
	}
	planHead, err := goals.Apply(rev1, Sign(f.owner, PlanSignatureDomain, rev1))
	if err != nil {
		t.Fatal(err)
	}

	makeSpec := func(taskID, nonce string, gen uint64) ProtocolSpec {
		s := cloneProtocol(f.spec)
		s.Version = ProtocolVersionV2
		s.TaskID = taskID
		s.Generation = gen
		s.Nonce = nonce
		return s
	}
	syncEvents := func(p *Protocol, protocolID string) {
		t.Helper()
		for _, ev := range p.Bundle().Events {
			if _, err := attempts.Apply(protocolID, ev.Command, ev.Signature, ev.Command.Height); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Generation 1 of upstream ends in a "reject" resolution (TaskRejected).
	spec1 := makeSpec(upstream.ID(), "up-gen-1", 1)
	p1, err := NewProtocol(spec1)
	if err != nil {
		t.Fatal(err)
	}
	req1 := ClaimRequest{
		GoalID: goalID, TaskID: upstream.ID(), WorkerID: workerID,
		RequestID: "claim-up-1", ProtocolID: p1.View().ID, ExpectedGeneration: 0, LeaseUntilHeight: 41,
	}
	sig1 := Sign(f.owner, ClaimSignatureDomain, req1)
	lease1, err := coord.Claim(req1, sig1, spec1, 1)
	if err != nil {
		t.Fatal(err)
	}
	f1 := f
	f1.spec = spec1
	p1 = enterProtocol(t, f1)
	reportProtocol(t, p1, f1, WorkFailedSafely)
	reviewProtocol(t, p1, f1, false)
	resolveProtocol(t, p1, f1, "reject")
	protocolApply(t, p1, f.owner, "owner", "return", func(c *ProtocolCommand) {
		m := manifestFor(p1)
		c.Return = &m
	})
	syncEvents(p1, req1.ProtocolID)
	v1 := p1.View()
	res1, err := coord.Finalize(lease1, v1.Head, v1.Height)
	if err != nil {
		t.Fatal(err)
	}
	if res1.Outcome != TaskRejected || len(res1.Artifacts) != 1 || res1.Artifacts[0].Slot != "failure" {
		t.Fatalf("rejected attempt result = %+v", res1)
	}
	// Exact Finalize retry succeeds even after lease expiry; mismatched head fails.
	if retry, err := coord.Finalize(lease1, v1.Head, lease1.LeaseUntilHeight+5); err != nil || retry.Head != res1.Head {
		t.Fatalf("post-expiry Finalize retry = (%+v, %v)", retry, err)
	}
	if _, err := coord.Finalize(lease1, Hash("wrong-head"), v1.Height); !errors.Is(err, ErrTaskStale) {
		t.Fatalf("Finalize with wrong head got %v, want ErrTaskStale", err)
	}

	// Generation 2 reclaims upstream before gen-1 lease expiry and gets accepted.
	spec2 := makeSpec(upstream.ID(), "up-gen-2", 2)
	p2, err := NewProtocol(spec2)
	if err != nil {
		t.Fatal(err)
	}
	req2 := ClaimRequest{
		GoalID: goalID, TaskID: upstream.ID(), WorkerID: workerID,
		RequestID: "claim-up-2", ProtocolID: p2.View().ID, ExpectedGeneration: 1, LeaseUntilHeight: 41,
	}
	sig2 := Sign(f.owner, ClaimSignatureDomain, req2)
	lease2, err := coord.Claim(req2, sig2, spec2, v1.Height)
	if err != nil {
		t.Fatal(err)
	}
	f2 := f
	f2.spec = spec2
	p2 = enterProtocol(t, f2)
	upAnswer := testArtifactRef("upstream verified answer")
	protocolApply(t, p2, f.worker, "worker", "report", func(c *ProtocolCommand) {
		c.Report = &WorkReport{
			Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("done"), Evidence: []string{upAnswer.Digest},
			Manifest: &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: "answer", Ref: upAnswer}}},
		}
	})
	reviewProtocol(t, p2, f2, false)
	resolveProtocol(t, p2, f2, "accept")
	protocolApply(t, p2, f.worker, "worker", "return", func(c *ProtocolCommand) {
		m := manifestFor(p2)
		m.Artifacts[0].Commitment = upAnswer.Digest
		c.Return = &m
	})
	syncEvents(p2, req2.ProtocolID)
	v2 := p2.View()
	res2, err := coord.Finalize(lease2, v2.Head, v2.Height)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Outcome != TaskAccepted {
		t.Fatalf("gen-2 outcome = %s, want accepted", res2.Outcome)
	}
	// Generation 1's TaskRejected handoff remains exportable and offline-verifiable after gen-2 acceptance.
	rejectedHandoff, err := coord.ExportHandoff(req1, sig1)
	if err != nil {
		t.Fatalf("ExportHandoff for prior rejected gen failed: %v", err)
	}
	verifiedRej, err := VerifyTaskHandoff(rejectedHandoff, upstream.ID(), Hash(rejectedHandoff.Result))
	if err != nil || verifiedRej.Outcome != TaskRejected {
		t.Fatalf("VerifyTaskHandoff rejected gen = (%+v, %v)", verifiedRej, err)
	}

	// Add two downstream tasks: one pins the exact accepted upstream output,
	// one pins a mismatched digest.
	downstreamOK := TaskSpec{
		GoalID: goalID, Nonce: "downstream-ok", Purpose: f.spec.Purpose, Scope: f.spec.Scope,
		SpecificationHash: f.spec.SpecificationHash, AcceptanceHash: f.spec.AcceptanceHash,
		FailurePolicyHash: f.spec.FailurePolicyHash, Authority: owner,
		Outputs: []string{"answer"}, FailureOutputs: []string{"failure"},
		Dependencies: []TaskDependency{{
			Input: "up_input", TaskID: upstream.ID(), ProtocolID: req2.ProtocolID,
			Head: res2.Head, Slot: "answer", Digest: upAnswer.Digest, Outcome: TaskAccepted,
		}},
	}
	downstreamBadPin := downstreamOK
	downstreamBadPin.Nonce = "downstream-bad-pin"
	downstreamBadPin.Dependencies = []TaskDependency{{
		Input: "up_input", TaskID: upstream.ID(), ProtocolID: req2.ProtocolID,
		Head: res2.Head, Slot: "answer", Digest: Hash("wrong-digest"), Outcome: TaskAccepted,
	}}
	rev2 := PlanRevision{
		GoalID: goalID, Head: planHead, Planner: owner.ID(), RequestID: "plan-2",
		Tasks: []TaskSpec{downstreamOK, downstreamBadPin},
	}
	if _, err := goals.Apply(rev2, Sign(f.owner, PlanSignatureDomain, rev2)); err != nil {
		t.Fatal(err)
	}

	// DiscoverGoal flags ready vs mismatch accurately.
	discovered, _, err := coord.DiscoverGoal(goalID, v2.Height)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovered) != 3 || !discovered[1].DependenciesReady || discovered[1].DependenciesMismatch {
		t.Fatalf("downstreamOK discovery = %+v", discovered[1])
	}
	if discovered[2].DependenciesReady || !discovered[2].DependenciesMismatch {
		t.Fatalf("downstreamBadPin discovery = %+v", discovered[2])
	}

	// Claiming downstreamBadPin must fail with ErrTaskDependency.
	badSpec := makeSpec(downstreamBadPin.ID(), "down-bad-gen-1", 1)
	badP, err := NewProtocol(badSpec)
	if err != nil {
		t.Fatal(err)
	}
	badReq := ClaimRequest{
		GoalID: goalID, TaskID: downstreamBadPin.ID(), WorkerID: workerID,
		RequestID: "claim-bad", ProtocolID: badP.View().ID, ExpectedGeneration: 0, LeaseUntilHeight: 41,
	}
	if _, err := coord.Claim(badReq, Sign(f.owner, ClaimSignatureDomain, badReq), badSpec, 1); !errors.Is(err, ErrTaskDependency) {
		t.Fatalf("Claim with mismatched dependency got %v, want ErrTaskDependency", err)
	}

	// Claim downstreamOK, complete its protocol WITHOUT declaring the required
	// dependency digest in WorkReport.Manifest.Inputs -> Finalize must reject with ErrTaskDependency.
	downSpec := makeSpec(downstreamOK.ID(), "down-ok-gen-1", 1)
	downP, err := NewProtocol(downSpec)
	if err != nil {
		t.Fatal(err)
	}
	downReq := ClaimRequest{
		GoalID: goalID, TaskID: downstreamOK.ID(), WorkerID: workerID,
		RequestID: "claim-down-1", ProtocolID: downP.View().ID, ExpectedGeneration: 0, LeaseUntilHeight: 41,
	}
	downLease, err := coord.Claim(downReq, Sign(f.owner, ClaimSignatureDomain, downReq), downSpec, 1)
	if err != nil {
		t.Fatal(err)
	}
	fd := f
	fd.spec = downSpec
	downP = enterProtocol(t, fd)
	downAnswer := testArtifactRef("downstream answer")
	protocolApply(t, downP, f.worker, "worker", "report", func(c *ProtocolCommand) {
		c.Report = &WorkReport{
			Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("done"), Evidence: []string{downAnswer.Digest},
			Manifest: &EvidenceManifest{
				MethodHash: Hash("method"),
				Inputs:     []NamedArtifact{{Name: "up_input", Ref: testArtifactRef("wrong input bytes")}},
				Outputs:    []NamedArtifact{{Name: "answer", Ref: downAnswer}},
			},
		}
	})
	reviewProtocol(t, downP, fd, false)
	resolveProtocol(t, downP, fd, "accept")
	protocolApply(t, downP, f.worker, "worker", "return", func(c *ProtocolCommand) {
		m := manifestFor(downP)
		m.Artifacts[0].Commitment = downAnswer.Digest
		c.Return = &m
	})
	syncEvents(downP, downReq.ProtocolID)
	dv := downP.View()
	if _, err := coord.Finalize(downLease, dv.Head, dv.Height); !errors.Is(err, ErrTaskDependency) {
		t.Fatalf("Finalize omitting verified dependency input got %v, want ErrTaskDependency", err)
	}

	// Reclaim downstreamOK after gen-1 lease expiry with the exact upstream digest
	// declared in WorkReport.Manifest.Inputs -> Finalize and offline handoff succeed.
	downSpec2 := makeSpec(downstreamOK.ID(), "down-ok-gen-2", 2)
	downSpec2.WorkByHeight = 60
	downSpec2.ReturnByHeight = 80
	for i := range downSpec2.Roles {
		downSpec2.Roles[i].ExpiresAtHeight = 80
	}
	downP2, err := NewProtocol(downSpec2)
	if err != nil {
		t.Fatal(err)
	}
	downReq2 := ClaimRequest{
		GoalID: goalID, TaskID: downstreamOK.ID(), WorkerID: workerID,
		RequestID: "claim-down-2", ProtocolID: downP2.View().ID, ExpectedGeneration: 1, LeaseUntilHeight: 81,
	}
	downSig2 := Sign(f.owner, ClaimSignatureDomain, downReq2)
	downLease2, err := coord.Claim(downReq2, downSig2, downSpec2, downLease.LeaseUntilHeight)
	if err != nil {
		t.Fatal(err)
	}
	fd2 := f
	fd2.spec = downSpec2
	downP2 = enterProtocol(t, fd2)
	protocolApply(t, downP2, f.worker, "worker", "report", func(c *ProtocolCommand) {
		c.Report = &WorkReport{
			Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("done"), Evidence: []string{downAnswer.Digest},
			Manifest: &EvidenceManifest{
				MethodHash: Hash("method"),
				Inputs:     []NamedArtifact{{Name: "up_input", Ref: upAnswer}},
				Outputs:    []NamedArtifact{{Name: "answer", Ref: downAnswer}},
			},
		}
	})
	reviewProtocol(t, downP2, fd2, false)
	resolveProtocol(t, downP2, fd2, "accept")
	protocolApply(t, downP2, f.worker, "worker", "return", func(c *ProtocolCommand) {
		m := manifestFor(downP2)
		m.Artifacts[0].Commitment = downAnswer.Digest
		c.Return = &m
	})
	syncEvents(downP2, downReq2.ProtocolID)
	dv2 := downP2.View()
	downRes2, err := coord.Finalize(downLease2, dv2.Head, dv2.Height)
	if err != nil || downRes2.Outcome != TaskAccepted {
		t.Fatalf("Finalize with matching dependency input = (%+v, %v)", downRes2, err)
	}
	downHandoff, err := coord.ExportHandoff(downReq2, downSig2)
	if err != nil {
		t.Fatalf("ExportHandoff downstream accepted failed: %v", err)
	}
	if got, err := VerifyTaskHandoff(downHandoff, downstreamOK.ID(), Hash(downHandoff.Result)); err != nil || got.Outcome != TaskAccepted {
		t.Fatalf("VerifyTaskHandoff downstream = (%+v, %v)", got, err)
	}
}
