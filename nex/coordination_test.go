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
