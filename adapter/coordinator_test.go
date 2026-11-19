package adapter

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

type testEpochSealer struct {
	err   error
	calls int
	last  struct {
		scope string
		gen   uint64
	}
}

func (s *testEpochSealer) SealFenceEpoch(_ context.Context, scope string, generation uint64) error {
	s.calls++
	s.last.scope = scope
	s.last.gen = generation
	return s.err
}

func TestDurableCoordinatorLifecycleAndAntiRollback(t *testing.T) {
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "coord")
	if _, err := OpenCoordinator(dir, []byte("short")); !errors.Is(err, ErrStorageKey) {
		t.Fatalf("expected ErrStorageKey, got %v", err)
	}

	coord, err := OpenCoordinator(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coord.Current(); !errors.Is(err, ErrFenced) {
		t.Fatalf("unissued Current: %v", err)
	}
	if _, err := coord.Historical(); !errors.Is(err, ErrFenced) {
		t.Fatalf("unissued Historical: %v", err)
	}
	if coord.Admission() != "stopped" {
		t.Fatalf("unissued Admission: %s", coord.Admission())
	}

	f1, err := coord.Issue("owner-a")
	if err != nil || f1.Generation != 1 || f1.Owner != "owner-a" || len(f1.Token) != 32 {
		t.Fatalf("Issue: %+v %v", f1, err)
	}
	if _, err := coord.Issue("owner-b"); !errors.Is(err, ErrConcurrentOwner) {
		t.Fatalf("duplicate active Issue: %v", err)
	}

	// Reopening from disk preserves generation 1 and refuses Issue rollback.
	reopened, err := OpenCoordinator(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := reopened.Current()
	if err != nil || !FencesEqual(cur, f1) {
		t.Fatalf("reopened Current mismatch: %+v %v", cur, err)
	}
	if _, err := reopened.Issue("owner-b"); !errors.Is(err, ErrConcurrentOwner) {
		t.Fatalf("reopened Issue must refuse concurrent owner: %v", err)
	}

	if err := reopened.StopAdmission(); err != nil {
		t.Fatal(err)
	}
	if coord.Admission() != "stopped" {
		t.Fatalf("first handle must observe stopped admission on disk, got %s", coord.Admission())
	}
	inner := &blockingAuth{}
	ownerA := BindCoordinatorOwner(coord, "owner-a", f1, inner)
	if _, err := ownerA.Submit(ownerEnv(fenceItem(), f1.Generation), f1); !errors.Is(err, ErrAdmissionStopped) {
		t.Fatalf("expected ErrAdmissionStopped, got %v", err)
	}
	if err := reopened.Resume(); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerA.Submit(ownerEnv(fenceItem(), f1.Generation), f1); err != nil || inner.calls != 1 {
		t.Fatalf("expected Submit after Resume to succeed: %v calls=%d", err, inner.calls)
	}

	if err := coord.RecordCheckpoint("head-gen-1"); err != nil {
		t.Fatal(err)
	}
	fenced, err := reopened.StopAndFence("owner-a")
	if err != nil || !FencesEqual(fenced, f1) {
		t.Fatalf("StopAndFence: %+v %v", fenced, err)
	}
	// Even without calling ownerA.Deactivate(), cross-handle Submit fails immediately.
	if _, err := ownerA.Submit(ownerEnv(fenceItem(), f1.Generation), f1); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale ownerA Submit after StopAndFence: %v", err)
	}

	reopenedAfterFence, err := OpenCoordinator(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopenedAfterFence.Issue("owner-b"); !errors.Is(err, ErrActivation) {
		t.Fatalf("Issue after fence must be permanently refused: %v", err)
	}
	hist, err := reopenedAfterFence.Historical()
	if err != nil || !FencesEqual(hist, f1) {
		t.Fatalf("Historical mismatch: %+v %v", hist, err)
	}

	srcDataDir := filepath.Join(t.TempDir(), "src-data")
	if err := os.Mkdir(srcDataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDataDir, "state.bin"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	dstDataDir := filepath.Join(t.TempDir(), "dst-data")
	if err := HandoffCoordinatorDir(reopenedAfterFence, srcDataDir, dstDataDir); err != nil {
		t.Fatal(err)
	}

	if _, err := ActivateCoordinatorReplacement(reopenedAfterFence, ownerA, "owner-b", "head-gen-1", inner); !errors.Is(err, ErrConcurrentOwner) {
		t.Fatalf("expected ErrConcurrentOwner before Deactivate: %v", err)
	}
	ownerA.Deactivate()
	if _, err := ActivateCoordinatorReplacement(reopenedAfterFence, ownerA, "owner-b", "wrong-head", inner); !errors.Is(err, ErrActivation) {
		t.Fatalf("expected ErrActivation on wrong head: %v", err)
	}
	ownerB, err := ActivateCoordinatorReplacement(reopenedAfterFence, ownerA, "owner-b", "head-gen-1", inner)
	if err != nil || ownerB.Fence.Generation != 2 || !ownerB.Active {
		t.Fatalf("ActivateCoordinatorReplacement: %+v %v", ownerB, err)
	}

	// Test MaxUint64 generation overflow refusal.
	if err := reopenedAfterFence.withLock(func() error {
		rec, err := reopenedAfterFence.readLocked()
		if err != nil {
			return err
		}
		rec.Generation = math.MaxUint64
		rec.State = coordStateFencedProven
		rec.FenceProof = true
		rec.Admission = coordAdmissionStopped
		rec.Checkpoint = Checkpoint{Head: "head-max", Generation: math.MaxUint64, Set: true}
		return reopenedAfterFence.writeLocked(rec)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := reopenedAfterFence.Activate("owner-c", "head-max"); !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("expected ErrGenerationOverflow, got %v", err)
	}

	// Tampering with coordinator.gate fails closed with ErrCorrupt.
	gatePath := filepath.Join(dir, coordinatorGateFile)
	raw, err := os.ReadFile(gatePath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(gatePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCoordinator(dir, key); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt on tampered coordinator.gate, got %v", err)
	}
}

func TestDurableCoordinatorEpochSealerFailureAndRecovery(t *testing.T) {
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "coord-sealer")
	coord, err := OpenCoordinator(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	sealErr := errors.New("destination rpc unreachable")
	sealer := &testEpochSealer{err: sealErr}
	coord.SetEpochSealer("scope-alpha", sealer)

	f1, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := coord.RecordCheckpoint("head-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := coord.StopAndFence("owner-a"); !errors.Is(err, sealErr) {
		t.Fatalf("expected sealer error, got %v", err)
	}
	if sealer.calls != 1 || sealer.last.scope != "scope-alpha" || sealer.last.gen != 1 {
		t.Fatalf("unexpected sealer call: %+v", sealer)
	}

	// Coordinator must now be durably in fenced_unproven: old owner fenced,
	// AND takeover refused across reopen until ConfirmFenceProof succeeds.
	reopened, err := OpenCoordinator(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	reopened.SetEpochSealer("scope-alpha", sealer)
	if _, err := reopened.Current(); !errors.Is(err, ErrFenced) {
		t.Fatalf("expected ErrFenced on unproven fence Current, got %v", err)
	}
	hist, err := reopened.Historical()
	if err != nil || !FencesEqual(hist, f1) {
		t.Fatalf("Historical on unproven fence: %+v %v", hist, err)
	}
	if err := reopened.Authorize(f1, func() error { return nil }); !errors.Is(err, ErrFenced) {
		t.Fatalf("Authorize must reject unproven fenced generation: %v", err)
	}
	if _, err := reopened.Activate("owner-b", "head-1"); !errors.Is(err, ErrActivation) {
		t.Fatalf("Activate must refuse unproven fence: %v", err)
	}
	if err := reopened.ConfirmFenceProof("owner-a"); !errors.Is(err, sealErr) {
		t.Fatalf("ConfirmFenceProof while sealer still fails: %v", err)
	}

	sealer.err = nil
	if err := reopened.ConfirmFenceProof("owner-a"); err != nil {
		t.Fatalf("ConfirmFenceProof recovery failed: %v", err)
	}
	f2, err := reopened.Activate("owner-b", "head-1")
	if err != nil || f2.Generation != 2 || f2.Owner != "owner-b" {
		t.Fatalf("Activate after ConfirmFenceProof: %+v %v", f2, err)
	}
}

func TestSharedVaultDirectoryIgnoresControlGatesAndAvoidsLockCycle(t *testing.T) {
	w := newStoreWorld(t)
	key := testKey(t)
	sharedDir := filepath.Join(t.TempDir(), "shared-vault")

	outbox, err := OpenOutbox(sharedDir, key)
	if err != nil {
		t.Fatal(err)
	}
	effects, err := OpenEffects(sharedDir, key)
	if err != nil {
		t.Fatal(err)
	}
	coord, err := OpenCoordinator(sharedDir, key)
	if err != nil {
		t.Fatal(err)
	}
	f1, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}

	// Outbox item and Effect intent in two separate tenants/IDs; control files
	// coordinator.gate and admission.gate sit in the same directory without .box.
	op, err := w.store.Prepare(w.contract.ID(), "shared-lock", "lock", "artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
	if err != nil {
		t.Fatal(err)
	}
	item := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.contract.ID(), OperationID: "shared-lock", Kind: KindAgreement, SignedObject: raw, Destination: "authority-1", CreatedAt: w.now}
	if err := outbox.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	if err := outbox.SealAdmission(f1.Generation); err != nil {
		t.Fatal(err)
	}
	due, err := outbox.Due(tenant)
	if err != nil || len(due) != 1 {
		t.Fatalf("Due failed when control gates shared vault dir: %v %v", due, err)
	}

	effectsDir := filepath.Join(t.TempDir(), "effects-only")
	effectsIsolated, err := OpenEffects(effectsDir, key)
	if err != nil {
		t.Fatal(err)
	}
	// Also verify EffectAdapter sharing the exact directory with DurableCoordinator
	// does not deadlock when Guard calls coord.Authorize under effects.Apply!
	intent := EffectIntent{Tenant: "effect-tenant", EffectID: "eff-shared", AgreementID: w.contract.ID(), Evidence: "ev"}
	if err := effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	_ = effectsIsolated
	sink := NewMemoryDestination()
	sink.Guard = coord
	if err := effects.Apply(intent.Tenant, intent.EffectID, sink, f1); err != nil {
		t.Fatalf("effects.Apply in shared dir with DurableCoordinator failed: %v", err)
	}
	if sink.Executions(intent.EffectID) != 1 {
		t.Fatalf("expected 1 execution, got %d", sink.Executions(intent.EffectID))
	}
}

func TestDurableCoordinatorSubprocessCrashAndCrossProcessFence(t *testing.T) {
	key := testKey(t)
	keyHex := hex.EncodeToString(key)
	coordDir := filepath.Join(t.TempDir(), "coord-proc")
	effectsDir := filepath.Join(t.TempDir(), "effects-proc")

	// Phase 1: Child 1 issues gen 1, checkpoints, fences, activates gen 2, checkpoints, and exits abruptly.
	out1 := runCoordHelper(t, map[string]string{
		"NEX_COORD_HELPER_MODE": "crash-after-gen2",
		"NEX_COORD_DIR":         coordDir,
		"NEX_COORD_KEY_HEX":     keyHex,
	})
	gen2TokenHex := strings.TrimSpace(out1)
	if len(gen2TokenHex) != 64 {
		t.Fatalf("expected 32-byte hex token from child 1, got %q", gen2TokenHex)
	}

	// Phase 2: Child 2 reopens after crash, verifies gen 2 token, verifies Issue is refused, and fences gen 2.
	runCoordHelper(t, map[string]string{
		"NEX_COORD_HELPER_MODE":  "verify-gen2-and-fence",
		"NEX_COORD_DIR":          coordDir,
		"NEX_COORD_KEY_HEX":      keyHex,
		"NEX_EXPECTED_TOKEN_HEX": gen2TokenHex,
	})

	// Phase 3: Parent reopens, verifies duplicate Issue is refused, activates gen 3,
	// and tests live cross-process flock blocking during StopAndFence!
	coord, err := OpenCoordinator(coordDir, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coord.Issue("owner-c"); !errors.Is(err, ErrActivation) {
		t.Fatalf("expected ErrActivation on duplicate Issue after restart, got %v", err)
	}
	f3, err := coord.Activate("owner-c", "head-gen2")
	if err != nil || f3.Generation != 3 {
		t.Fatalf("Activate gen 3: %+v %v", f3, err)
	}
	if err := coord.RecordCheckpoint("head-gen3"); err != nil {
		t.Fatal(err)
	}

	// Launch Child 3 holding Authorize lock inside Owner.Submit across OS processes.
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoordinatorSubprocessHelper$")
	cmd.Env = append(os.Environ(),
		"NEX_COORD_HELPER_MODE=hold-submit",
		"NEX_COORD_DIR="+coordDir,
		"NEX_COORD_KEY_HEX="+keyHex,
		"NEX_FENCE_TOKEN_HEX="+hex.EncodeToString(f3.Token),
		"NEX_FENCE_GEN=3",
		"NEX_FENCE_OWNER=owner-c",
	)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(stdoutPipe)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ENTERED_SUBMIT" {
		_ = stdinPipe.Close()
		_ = cmd.Wait()
		t.Fatalf("child did not enter Submit: line=%q err=%v stderr=%s", line, err, stderrBuf.String())
	}

	// While Child 3 holds the coordinator flock inside Authorize, Parent's StopAndFence MUST block.
	stopDone := make(chan error, 1)
	go func() {
		_, err := coord.StopAndFence("owner-c")
		stopDone <- err
	}()
	select {
	case err := <-stopDone:
		_ = stdinPipe.Close()
		_ = cmd.Wait()
		t.Fatalf("StopAndFence returned while cross-process Submit was in flight: %v", err)
	case <-time.After(80 * time.Millisecond):
	}

	// Release Child 3 so its in-flight Submit finishes cleanly; StopAndFence then completes.
	if err := stdinPipe.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("hold-submit child failed: %v stderr=%s", err, stderrBuf.String())
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("StopAndFence after child release failed: %v", err)
	}

	// Phase 4: Child 4 (separate OS process still holding f3 and Owner.Active=true)
	// attempts both Owner.Submit and EffectAdapter.Apply — both MUST be fenced!
	effects, err := OpenEffects(effectsDir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := effects.Intend(EffectIntent{Tenant: tenant, EffectID: "cross-proc-eff", AgreementID: "agreement-fence", Evidence: "ev"}); err != nil {
		t.Fatal(err)
	}
	runCoordHelper(t, map[string]string{
		"NEX_COORD_HELPER_MODE": "stale-process-submit-and-effect",
		"NEX_COORD_DIR":         coordDir,
		"NEX_EFFECTS_DIR":       effectsDir,
		"NEX_COORD_KEY_HEX":     keyHex,
		"NEX_FENCE_TOKEN_HEX":   hex.EncodeToString(f3.Token),
		"NEX_FENCE_GEN":         "3",
		"NEX_FENCE_OWNER":       "owner-c",
	})
}

func TestOutboxDurableStopAdmissionAcrossProcesses(t *testing.T) {
	w := newStoreWorld(t)
	key := testKey(t)
	keyHex := hex.EncodeToString(key)
	outboxDir := filepath.Join(t.TempDir(), "outbox-proc")

	outbox, err := OpenOutbox(outboxDir, key)
	if err != nil {
		t.Fatal(err)
	}
	first := w.enqueueLock(t, outbox, "op-before-stop")
	outbox.StopAdmission()

	op2, err := w.store.Prepare(w.contract.ID(), "op-after-stop", "lock", "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := EncodeOperation(op2, nex.Sign(w.buyer, "operation", op2), w.now)
	if err != nil {
		t.Fatal(err)
	}

	// Child process opens the same Outbox directory after StopAdmission():
	// Enqueue MUST fail with ErrAdmissionStopped while existing items remain readable.
	runCoordHelper(t, map[string]string{
		"NEX_COORD_HELPER_MODE": "outbox-expect-stopped",
		"NEX_OUTBOX_DIR":        outboxDir,
		"NEX_COORD_KEY_HEX":     keyHex,
		"NEX_AGREEMENT_ID":      w.contract.ID(),
		"NEX_EXISTING_OP_ID":    first.OperationID,
		"NEX_SIGNED_HEX":        hex.EncodeToString(raw2),
	})

	// Seal at generation 2, then resume at generation 3; child process can now Enqueue.
	if err := outbox.SealAdmission(2); err != nil {
		t.Fatal(err)
	}
	if err := outbox.ResumeAdmission(3); err != nil {
		t.Fatal(err)
	}
	runCoordHelper(t, map[string]string{
		"NEX_COORD_HELPER_MODE": "outbox-expect-open",
		"NEX_OUTBOX_DIR":        outboxDir,
		"NEX_COORD_KEY_HEX":     keyHex,
		"NEX_AGREEMENT_ID":      w.contract.ID(),
		"NEX_SIGNED_HEX":        hex.EncodeToString(raw2),
	})
	got, err := outbox.Get(tenant, "op-after-stop")
	if err != nil || got.Status != StatusPending {
		t.Fatalf("expected child Enqueue after ResumeAdmission to persist, got %+v %v", got, err)
	}
}

func runCoordHelper(t *testing.T, env map[string]string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoordinatorSubprocessHelper$")
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess helper (%s) failed: %v\noutput:\n%s", env["NEX_COORD_HELPER_MODE"], err, string(out))
	}
	raw := string(out)
	if idx := strings.Index(raw, "HELPER_RESULT:"); idx >= 0 {
		line := raw[idx+len("HELPER_RESULT:"):]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		return strings.TrimSpace(line)
	}
	return raw
}

func TestCoordinatorSubprocessHelper(t *testing.T) {
	mode := os.Getenv("NEX_COORD_HELPER_MODE")
	if mode == "" {
		return
	}
	key, err := hex.DecodeString(os.Getenv("NEX_COORD_KEY_HEX"))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}

	switch mode {
	case "crash-after-gen2":
		coord, err := OpenCoordinator(os.Getenv("NEX_COORD_DIR"), key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coord.Issue("owner-a"); err != nil {
			t.Fatal(err)
		}
		if err := coord.RecordCheckpoint("head-gen1"); err != nil {
			t.Fatal(err)
		}
		if _, err := coord.StopAndFence("owner-a"); err != nil {
			t.Fatal(err)
		}
		f2, err := coord.Activate("owner-b", "head-gen1")
		if err != nil {
			t.Fatal(err)
		}
		if err := coord.RecordCheckpoint("head-gen2"); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("HELPER_RESULT:%s\n", hex.EncodeToString(f2.Token))
		os.Exit(0)

	case "verify-gen2-and-fence":
		coord, err := OpenCoordinator(os.Getenv("NEX_COORD_DIR"), key)
		if err != nil {
			t.Fatal(err)
		}
		cur, err := coord.Current()
		if err != nil {
			t.Fatal(err)
		}
		if cur.Generation != 2 || cur.Owner != "owner-b" || hex.EncodeToString(cur.Token) != os.Getenv("NEX_EXPECTED_TOKEN_HEX") {
			t.Fatalf("unexpected current fence after crash: %+v", cur)
		}
		if _, err := coord.Issue("owner-c"); !errors.Is(err, ErrConcurrentOwner) {
			t.Fatalf("expected ErrConcurrentOwner, got %v", err)
		}
		if _, err := coord.StopAndFence("owner-b"); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)

	case "hold-submit":
		coord, err := OpenCoordinator(os.Getenv("NEX_COORD_DIR"), key)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := hex.DecodeString(os.Getenv("NEX_FENCE_TOKEN_HEX"))
		if err != nil {
			t.Fatal(err)
		}
		fence := Fence{Version: Version, Generation: 3, Owner: os.Getenv("NEX_FENCE_OWNER"), Token: tok}
		holdAuth := &pipeHoldAuth{in: os.Stdin, out: os.Stdout}
		owner := BindCoordinatorOwner(coord, fence.Owner, fence, holdAuth)
		if _, err := owner.Submit(ownerEnv(fenceItem(), fence.Generation), fence); err != nil {
			t.Fatalf("in-flight submit failed: %v", err)
		}
		os.Exit(0)

	case "stale-process-submit-and-effect":
		coord, err := OpenCoordinator(os.Getenv("NEX_COORD_DIR"), key)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := hex.DecodeString(os.Getenv("NEX_FENCE_TOKEN_HEX"))
		if err != nil {
			t.Fatal(err)
		}
		fence := Fence{Version: Version, Generation: 3, Owner: os.Getenv("NEX_FENCE_OWNER"), Token: tok}
		inner := &blockingAuth{}
		owner := BindCoordinatorOwner(coord, fence.Owner, fence, inner)
		owner.Active = true
		if _, err := owner.Submit(ownerEnv(fenceItem(), fence.Generation), fence); !errors.Is(err, ErrFenced) || inner.calls != 0 {
			t.Fatalf("expected cross-process ErrFenced on Submit, got err=%v calls=%d", err, inner.calls)
		}
		effects, err := OpenEffects(os.Getenv("NEX_EFFECTS_DIR"), key)
		if err != nil {
			t.Fatal(err)
		}
		sink := NewMemoryDestination()
		sink.Guard = coord
		err = effects.Apply(tenant, "cross-proc-eff", sink, fence)
		if !errors.Is(err, ErrEffectUnknown) {
			t.Fatalf("expected ErrEffectUnknown when Guard refuses with OutcomeNotDispatched, got %v", err)
		}
		if sink.Executions("cross-proc-eff") != 0 {
			t.Fatalf("fenced cross-process effect executed %d times", sink.Executions("cross-proc-eff"))
		}
		rec, err := effects.Get(tenant, "cross-proc-eff")
		if err != nil || rec.Phase != EffectPhaseIntended {
			t.Fatalf("expected effect to remain intended after pre-dispatch fence refusal, got %+v %v", rec, err)
		}
		os.Exit(0)

	case "outbox-expect-stopped":
		outbox, err := OpenOutbox(os.Getenv("NEX_OUTBOX_DIR"), key)
		if err != nil {
			t.Fatal(err)
		}
		sealed, _, err := outbox.AdmissionSealed()
		if err != nil || !sealed {
			t.Fatalf("expected AdmissionSealed=true in child process, got sealed=%v err=%v", sealed, err)
		}
		if _, err := outbox.Get(tenant, os.Getenv("NEX_EXISTING_OP_ID")); err != nil {
			t.Fatalf("expected existing item to remain readable: %v", err)
		}
		raw, err := hex.DecodeString(os.Getenv("NEX_SIGNED_HEX"))
		if err != nil {
			t.Fatal(err)
		}
		item := OutboundItem{
			Version:      Version,
			Tenant:       tenant,
			AgreementID:  os.Getenv("NEX_AGREEMENT_ID"),
			OperationID:  "op-after-stop",
			Kind:         KindAgreement,
			SignedObject: raw,
			Destination:  "authority-1",
			CreatedAt:    time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC),
		}
		if err := outbox.Enqueue(item); !errors.Is(err, ErrAdmissionStopped) {
			t.Fatalf("expected ErrAdmissionStopped in second process, got %v", err)
		}
		os.Exit(0)

	case "outbox-expect-open":
		outbox, err := OpenOutbox(os.Getenv("NEX_OUTBOX_DIR"), key)
		if err != nil {
			t.Fatal(err)
		}
		sealed, gen, err := outbox.AdmissionSealed()
		if err != nil || sealed || gen != 3 {
			t.Fatalf("expected resumed admission at gen 3, got sealed=%v gen=%d err=%v", sealed, gen, err)
		}
		if err := outbox.ResumeAdmission(2); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected stale generation resume refusal, got %v", err)
		}
		raw, err := hex.DecodeString(os.Getenv("NEX_SIGNED_HEX"))
		if err != nil {
			t.Fatal(err)
		}
		item := OutboundItem{
			Version:      Version,
			Tenant:       tenant,
			AgreementID:  os.Getenv("NEX_AGREEMENT_ID"),
			OperationID:  "op-after-stop",
			Kind:         KindAgreement,
			SignedObject: raw,
			Destination:  "authority-1",
			CreatedAt:    time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC),
		}
		if err := outbox.Enqueue(item); err != nil {
			t.Fatalf("Enqueue after ResumeAdmission failed in child process: %v", err)
		}
		os.Exit(0)

	default:
		t.Fatalf("unknown helper mode: %s", mode)
	}
}

type pipeHoldAuth struct {
	in  io.Reader
	out io.Writer
}

func (a *pipeHoldAuth) Apply(OutboundItem) (AuthenticatedResponse, error) {
	_, _ = fmt.Fprintln(a.out, "ENTERED_SUBMIT")
	_, _ = io.ReadAll(a.in)
	return AuthenticatedResponse{Version: Version, Kind: ResultAgreement, ReceiptHead: "head-ok"}, nil
}

func (a *pipeHoldAuth) View(string, string) (ViewSnapshot, error) {
	return ViewSnapshot{}, nil
}

func TestSQLCoordinatorValidationAndNilSafety(t *testing.T) {
	ctx := context.Background()
	key := testKey(t)
	if _, err := OpenSQLCoordinator(ctx, nil, DialectPostgres, "scope-a", key); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem on nil db, got %v", err)
	}
	dummyDB := sql.OpenDB(nil)
	defer dummyDB.Close()
	if _, err := OpenSQLCoordinator(ctx, dummyDB, "unknown", "scope-a", key); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem on unknown dialect, got %v", err)
	}
	if _, err := OpenSQLCoordinator(ctx, dummyDB, DialectPostgres, "", key); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem on empty scope, got %v", err)
	}
	if _, err := OpenSQLCoordinator(ctx, dummyDB, DialectPostgres, "scope-a", []byte("short")); !errors.Is(err, ErrStorageKey) {
		t.Fatalf("expected ErrStorageKey on short key, got %v", err)
	}

	var nilSQL *SQLCoordinator
	if _, err := nilSQL.Current(); !errors.Is(err, ErrFenced) {
		t.Fatalf("nil Current: %v", err)
	}
	if _, err := nilSQL.Historical(); !errors.Is(err, ErrFenced) {
		t.Fatalf("nil Historical: %v", err)
	}
	if nilSQL.Admission() != "stopped" {
		t.Fatalf("nil Admission: %s", nilSQL.Admission())
	}
	if err := nilSQL.Authorize(Fence{}, func() error { return nil }); !errors.Is(err, ErrItem) {
		t.Fatalf("nil Authorize: %v", err)
	}
	if err := nilSQL.AuthorizeTx(ctx, nil, Fence{}, func(*sql.Tx) error { return nil }); !errors.Is(err, ErrItem) {
		t.Fatalf("nil AuthorizeTx: %v", err)
	}
	if err := HandoffCoordinatorDir(nilSQL, "a", "b"); !errors.Is(err, ErrActivation) {
		t.Fatalf("nil HandoffCoordinatorDir: %v", err)
	}
}
