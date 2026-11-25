package adapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type inspectingSealer struct {
	coord FenceCoordinator
	hist  Fence
	adm   string
	err   error
}

func (s *inspectingSealer) SealFenceEpoch(_ context.Context, _ string, _ uint64) error {
	s.hist, s.err = s.coord.Historical()
	if s.err != nil {
		return s.err
	}
	if _, err := s.coord.Current(); !errors.Is(err, ErrFenced) {
		return errors.New("expected Current to report ErrFenced during SealFenceEpoch")
	}
	s.adm = s.coord.Admission()
	return nil
}

type blockingSealer struct {
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSealer) SealFenceEpoch(_ context.Context, _ string, _ uint64) error {
	close(s.entered)
	<-s.release
	return nil
}

// Regression test for BUG-10: DurableCoordinator must release coordinator.lock
// before invoking EpochSealer.SealFenceEpoch in both StopAndFenceContext and
// ConfirmFenceProofContext so other handles immediately observe ErrFenced and
// callbacks into Historical()/Current() never deadlock.
func TestV202DurableCoordinatorEpochSealerReleasesLock(t *testing.T) {
	t.Run("StopAndFenceDoesNotBlockOtherHandlesDuringRPC", func(t *testing.T) {
		key := testKey(t)
		dir := filepath.Join(t.TempDir(), "coord-block")
		c1, err := OpenCoordinator(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		c2, err := OpenCoordinator(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		f1, err := c1.Issue("owner-a")
		if err != nil {
			t.Fatal(err)
		}
		sealer := &blockingSealer{
			entered: make(chan struct{}),
			release: make(chan struct{}),
		}
		c1.SetEpochSealer("scope-1", sealer)

		stopDone := make(chan error, 1)
		go func() {
			_, err := c1.StopAndFence("owner-a")
			stopDone <- err
		}()
		<-sealer.entered

		// fenced_unproven is persisted and lock is released, so c2 immediately
		// observes ErrFenced on Authorize/Current and f1 on Historical.
		authDone := make(chan error, 1)
		go func() {
			if _, err := c2.Current(); !errors.Is(err, ErrFenced) {
				authDone <- errors.New("expected Current ErrFenced")
				return
			}
			hist, err := c2.Historical()
			if err != nil || !FencesEqual(hist, f1) {
				authDone <- errors.New("expected Historical f1")
				return
			}
			authDone <- c2.Authorize(f1, func() error { return nil })
		}()

		select {
		case err := <-authDone:
			close(sealer.release)
			if stopErr := <-stopDone; stopErr != nil {
				t.Fatalf("StopAndFence failed: %v", stopErr)
			}
			if !errors.Is(err, ErrFenced) {
				t.Fatalf("expected Authorize ErrFenced, got %v", err)
			}
		case <-time.After(500 * time.Millisecond):
			close(sealer.release)
			<-stopDone
			<-authDone
			t.Fatal("c2.Authorize/Current/Historical blocked while StopAndFence ran SealFenceEpoch")
		}
	})

	t.Run("StopAndFenceSealerInspectsHistoricalNoDeadlock", func(t *testing.T) {
		key := testKey(t)
		dir := filepath.Join(t.TempDir(), "coord-deadlock")
		c, err := OpenCoordinator(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		f1, err := c.Issue("owner-a")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.RecordCheckpoint("head-1"); err != nil {
			t.Fatal(err)
		}
		sealer := &inspectingSealer{coord: c}
		c.SetEpochSealer("scope-deadlock", sealer)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			_, err := c.StopAndFenceContext(ctx, "owner-a")
			done <- err
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("StopAndFenceContext failed: %v", err)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("StopAndFenceContext deadlocked when EpochSealer called Historical()")
		}
		if !FencesEqual(sealer.hist, f1) || sealer.adm != "stopped" {
			t.Fatalf("unexpected sealer inspection: hist=%+v adm=%q", sealer.hist, sealer.adm)
		}
		f2, err := c.Activate("owner-b", "head-1")
		if err != nil || f2.Generation != 2 {
			t.Fatalf("Activate after proven fence failed: f2=%+v err=%v", f2, err)
		}
	})

	t.Run("ConfirmFenceProofReleasesLockAndAllowsInspection", func(t *testing.T) {
		key := testKey(t)
		dir := filepath.Join(t.TempDir(), "coord-confirm")
		c1, err := OpenCoordinator(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		c2, err := OpenCoordinator(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		f1, err := c1.Issue("owner-a")
		if err != nil {
			t.Fatal(err)
		}
		if err := c1.RecordCheckpoint("head-1"); err != nil {
			t.Fatal(err)
		}
		// Force fenced_unproven via failing sealer.
		failSealer := &testEpochSealer{err: errors.New("transient rpc error")}
		c1.SetEpochSealer("scope-confirm", failSealer)
		if _, err := c1.StopAndFence("owner-a"); err == nil {
			t.Fatal("expected initial StopAndFence failure")
		}

		// ConfirmFenceProof with blocking sealer must not block c2.Authorize.
		blocker := &blockingSealer{entered: make(chan struct{}), release: make(chan struct{})}
		c1.SetEpochSealer("scope-confirm", blocker)
		confirmDone := make(chan error, 1)
		go func() {
			confirmDone <- c1.ConfirmFenceProof("owner-a")
		}()
		<-blocker.entered

		authDone := make(chan error, 1)
		go func() {
			authDone <- c2.Authorize(f1, func() error { return nil })
		}()
		select {
		case err := <-authDone:
			close(blocker.release)
			if cerr := <-confirmDone; cerr != nil {
				t.Fatalf("ConfirmFenceProof failed: %v", cerr)
			}
			if !errors.Is(err, ErrFenced) {
				t.Fatalf("expected ErrFenced, got %v", err)
			}
		case <-time.After(500 * time.Millisecond):
			close(blocker.release)
			<-confirmDone
			<-authDone
			t.Fatal("c2.Authorize blocked during ConfirmFenceProof SealFenceEpoch")
		}

		// Also verify inspectingSealer in ConfirmFenceProofContext after DisableFenceProof.
		if err := c1.DisableFenceProof(); err != nil {
			t.Fatal(err)
		}
		inspector := &inspectingSealer{coord: c1}
		c1.SetEpochSealer("scope-confirm", inspector)
		done := make(chan error, 1)
		go func() {
			done <- c1.ConfirmFenceProofContext(context.Background(), "owner-a")
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("ConfirmFenceProofContext with inspectingSealer failed: %v", err)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("ConfirmFenceProofContext deadlocked when sealer called Historical()")
		}
		if _, err := c1.Activate("owner-b", "head-1"); err != nil {
			t.Fatalf("Activate after ConfirmFenceProof failed: %v", err)
		}
	})
}

// wrappedCoordinator delegates only FenceCoordinator without implementing HandoffReady.
type wrappedCoordinator struct {
	inner FenceCoordinator
}

func (w wrappedCoordinator) Authorize(f Fence, fn func() error) error {
	return w.inner.Authorize(f, fn)
}
func (w wrappedCoordinator) Current() (Fence, error)           { return w.inner.Current() }
func (w wrappedCoordinator) Historical() (Fence, error)        { return w.inner.Historical() }
func (w wrappedCoordinator) Admission() string                 { return w.inner.Admission() }
func (w wrappedCoordinator) Issue(owner string) (Fence, error) { return w.inner.Issue(owner) }
func (w wrappedCoordinator) RecordCheckpoint(head string) error {
	return w.inner.RecordCheckpoint(head)
}
func (w wrappedCoordinator) StopAdmission() error { return w.inner.StopAdmission() }
func (w wrappedCoordinator) Resume() error        { return w.inner.Resume() }
func (w wrappedCoordinator) StopAndFence(owner string) (Fence, error) {
	return w.inner.StopAndFence(owner)
}
func (w wrappedCoordinator) Activate(n, h string) (Fence, error) { return w.inner.Activate(n, h) }

// wrappedHandoffCoordinator delegates both FenceCoordinator and exported HandoffReady.
type wrappedHandoffCoordinator struct {
	wrappedCoordinator
	ready HandoffReady
}

func (w wrappedHandoffCoordinator) ReadyForHandoff() error { return w.ready.ReadyForHandoff() }

// Regression test for BUG-28: HandoffCoordinatorDir must enforce fence proof
// and non-empty checkpoint head even when wrapped by an external decorator,
// failing closed if HandoffReady is not implemented.
func TestV202HandoffCoordinatorDirEnforcesProofAndCheckpointThroughWrappers(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "state.bin"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("InMemoryCoordinator", func(t *testing.T) {
		coord := &Coordinator{}
		if _, err := coord.Issue("owner-a"); err != nil {
			t.Fatal(err)
		}
		if _, err := coord.StopAndFence("owner-a"); err != nil {
			t.Fatal(err)
		}
		coord.DisableFenceProof()

		// Direct call refuses missing proof + missing checkpoint.
		if err := HandoffCoordinatorDir(coord, src, filepath.Join(t.TempDir(), "dst-direct")); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected direct HandoffCoordinatorDir ErrActivation, got %v", err)
		}

		// Plain wrapper without HandoffReady MUST fail closed with ErrActivation.
		plainWrapped := wrappedCoordinator{inner: coord}
		if err := HandoffCoordinatorDir(plainWrapped, src, filepath.Join(t.TempDir(), "dst-plain")); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected plain wrapped HandoffCoordinatorDir ErrActivation, got %v", err)
		}

		// HandoffReady wrapper MUST also refuse missing proof / missing checkpoint.
		readyWrapped := wrappedHandoffCoordinator{wrappedCoordinator: wrappedCoordinator{inner: coord}, ready: coord}
		if err := HandoffCoordinatorDir(readyWrapped, src, filepath.Join(t.TempDir(), "dst-ready-unproven")); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected HandoffReady wrapper ErrActivation on unproven/no-checkpoint, got %v", err)
		}

		// Properly checkpointed + proven coordinator succeeds via HandoffReady wrapper,
		// while plain wrapper without HandoffReady still fails closed.
		readyCoord := &Coordinator{}
		if _, err := readyCoord.Issue("owner-a"); err != nil {
			t.Fatal(err)
		}
		if err := readyCoord.RecordCheckpoint("head-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := readyCoord.StopAndFence("owner-a"); err != nil {
			t.Fatal(err)
		}
		if err := HandoffCoordinatorDir(wrappedCoordinator{inner: readyCoord}, src, filepath.Join(t.TempDir(), "dst-plain-failclosed")); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected plain wrapper without HandoffReady to fail closed, got %v", err)
		}
		goodWrapped := wrappedHandoffCoordinator{wrappedCoordinator: wrappedCoordinator{inner: readyCoord}, ready: readyCoord}
		if err := HandoffCoordinatorDir(goodWrapped, src, filepath.Join(t.TempDir(), "dst-ready-ok")); err != nil {
			t.Fatalf("expected HandoffReady wrapper to succeed when proven+checkpointed, got %v", err)
		}
	})

	t.Run("DurableCoordinator", func(t *testing.T) {
		coord, err := OpenCoordinator(filepath.Join(t.TempDir(), "coord"), testKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coord.Issue("owner-a"); err != nil {
			t.Fatal(err)
		}
		if err := coord.RecordCheckpoint("head-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := coord.StopAndFence("owner-a"); err != nil {
			t.Fatal(err)
		}
		if err := coord.DisableFenceProof(); err != nil {
			t.Fatal(err)
		}
		if err := HandoffCoordinatorDir(wrappedCoordinator{inner: coord}, src, filepath.Join(t.TempDir(), "dst-unproven")); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected ErrActivation, got %v", err)
		}
		wrapped := wrappedHandoffCoordinator{wrappedCoordinator: wrappedCoordinator{inner: coord}, ready: coord}
		if err := HandoffCoordinatorDir(wrapped, src, filepath.Join(t.TempDir(), "dst-unproven-ready")); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected ErrActivation before ConfirmFenceProof, got %v", err)
		}
		if err := coord.ConfirmFenceProof("owner-a"); err != nil {
			t.Fatal(err)
		}
		if err := HandoffCoordinatorDir(wrapped, src, filepath.Join(t.TempDir(), "dst-proven-ready")); err != nil {
			t.Fatalf("expected handoff to succeed after ConfirmFenceProof, got %v", err)
		}
	})
}
