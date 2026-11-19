package adapter

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

func TestFencedHandoffRejectsOldOwnerAndStaleSnapshot(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	coord := &Coordinator{}
	srcFence, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	src := BindOwner(coord, "owner-a", srcFence, w.inner)
	w.apply(t, o, w.owner, "", "admit", "admit-owner", 1, nil)
	oldDir := filepath.Join(t.TempDir(), "old")
	if err = CopyPrivateDir(w.dir, oldDir); err != nil {
		t.Fatal(err)
	}
	w.apply(t, o, w.worker, "", "admit", "admit-worker", 2, nil)
	pending := w.enqueue(t, o, w.witness, "", "admit", "admit-witness", 3, nil)
	head := mustView(t, w).Head
	coord.RecordCheckpoint(head)
	o.StopAdmission()
	if _, err = coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	src.Deactivate()

	stale, err := nex.OpenProtocolStore(oldDir, w.key)
	if err != nil {
		t.Fatal(err)
	}
	staleView, err := stale.View(w.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ActivateReplacement(coord, src, "owner-b", staleView.Head, &ProtocolAuthority{Tenant: tenant, Store: stale}); !errors.Is(err, ErrActivation) {
		t.Fatalf("stale snapshot: %v", err)
	}

	dstDir := filepath.Join(t.TempDir(), "dst")
	if err = CopyPrivateDir(w.dir, dstDir); err != nil {
		t.Fatal(err)
	}
	dstStore, err := nex.OpenProtocolStore(dstDir, w.key)
	if err != nil {
		t.Fatal(err)
	}
	dstInner := &ProtocolAuthority{Tenant: tenant, Store: dstStore}
	dst, err := ActivateReplacement(coord, src, "owner-b", mustView(t, w).Head, dstInner)
	if err != nil {
		t.Fatal(err)
	}
	env := RoutingEnvelope{Item: pending, Generation: srcFence.Generation}
	if _, err = src.Submit(env, srcFence); !errors.Is(err, ErrFenced) {
		t.Fatal("old owner accepted", err)
	}
	current, err := coord.Current()
	if err != nil {
		t.Fatal(err)
	}
	got, err := dst.Submit(RoutingEnvelope{Item: env.Item, Generation: current.Generation}, current)
	if err != nil || got.ReceiptHead == "" {
		t.Fatal(got, err)
	}
	retry, err := dst.Submit(RoutingEnvelope{Item: env.Item, Generation: current.Generation}, current)
	if err != nil || retry.ReceiptHead != got.ReceiptHead {
		t.Fatal(retry, err)
	}
	if v, err := dstStore.View(w.id); err != nil || v.Head != got.ReceiptHead || len(v.Admitted) != 3 {
		t.Fatal(v, err)
	}
}

func TestActivationFailClosedWithoutFence(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	coord := &Coordinator{}
	if _, err := coord.Issue("owner-a"); err != nil {
		t.Fatal(err)
	}
	w.apply(t, o, w.owner, "", "admit", "admit-owner", 1, nil)
	coord.RecordCheckpoint(mustView(t, w).Head)
	if _, err := coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	coord.DisableFenceProof()
	src := &Owner{ID: "owner-a", Active: false}
	if _, err := ActivateReplacement(coord, src, "owner-b", mustView(t, w).Head, w.inner); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
}

func TestRefuseConcurrentOwnersAndDestinationRestart(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	coord := &Coordinator{}
	srcFence, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	src := BindOwner(coord, "owner-a", srcFence, w.inner)
	w.apply(t, o, w.owner, "", "admit", "admit-owner", 1, nil)
	coord.RecordCheckpoint(mustView(t, w).Head)
	if _, err = coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = ActivateReplacement(coord, src, "owner-b", mustView(t, w).Head, w.inner); !errors.Is(err, ErrConcurrentOwner) {
		t.Fatal(err)
	}
	src.Deactivate()

	dstDir := filepath.Join(t.TempDir(), "restart")
	if err = CopyPrivateDir(w.dir, dstDir); err != nil {
		t.Fatal(err)
	}
	first, err := nex.OpenProtocolStore(dstDir, w.key)
	if err != nil {
		t.Fatal(err)
	}
	_ = first
	reopened, err := nex.OpenProtocolStore(dstDir, w.key)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := ActivateReplacement(coord, src, "owner-b", mustView(t, w).Head, &ProtocolAuthority{Tenant: tenant, Store: reopened})
	if err != nil || !dst.Active {
		t.Fatal(err)
	}

	effects, err := OpenEffects(filepath.Join(t.TempDir(), "effects"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "xfer-1", AgreementID: w.id, Evidence: "tool"}
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	dest := NewMemoryDestination()
	dest.Fence = dst.Fence
	dest.LoseNext = true
	if err = effects.Apply(tenant, intent.EffectID, dest, dst.Fence); !errors.Is(err, ErrEffectUnknown) {
		t.Fatal(err)
	}
	dest.Restarted = true
	if err = effects.Apply(tenant, intent.EffectID, dest, dst.Fence); !errors.Is(err, ErrEffectReexecute) {
		t.Fatal(err)
	}
	if dest.Executions(intent.EffectID) != 1 {
		t.Fatal(dest.Executions(intent.EffectID))
	}
}

func TestOutboxCopyPreservesUnsignedRetry(t *testing.T) {
	w := newProtocolWorld(t)
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "outbox")
	o, err := OpenOutbox(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	item := w.enqueue(t, o, w.owner, "", "admit", "admit-owner", 1, nil)
	copied := filepath.Join(t.TempDir(), "outbox-b")
	if err = CopyPrivateDir(dir, copied); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenOutbox(copied, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get(tenant, item.OperationID)
	if err != nil || got.Status != StatusPending || !bytes.Equal(got.Item.SignedObject, item.SignedObject) {
		t.Fatal(got, err)
	}
	resp, err := reopened.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil || resp.ReceiptHead == "" {
		t.Fatal(resp, err)
	}
}

func TestRollbackIsAnotherFencedHandoff(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	coord := &Coordinator{}
	if _, err := coord.Issue("owner-a"); err != nil {
		t.Fatal(err)
	}
	src := BindOwner(coord, "owner-a", mustFence(t, coord), w.inner)
	w.apply(t, o, w.owner, "", "admit", "admit-owner", 1, nil)
	coord.RecordCheckpoint(mustView(t, w).Head)
	if _, err := coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	src.Deactivate()
	b, err := ActivateReplacement(coord, src, "owner-b", mustView(t, w).Head, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	w.apply(t, o, w.worker, "", "admit", "admit-worker", 2, nil)
	coord.RecordCheckpoint(mustView(t, w).Head)
	if _, err = coord.StopAndFence("owner-b"); err != nil {
		t.Fatal(err)
	}
	b.Deactivate()
	c, err := ActivateReplacement(coord, b, "owner-c", mustView(t, w).Head, w.inner)
	if err != nil || c.ID != "owner-c" {
		t.Fatal(err)
	}
	if src.Active || b.Active {
		t.Fatal("prior owners still active")
	}
}

func mustFence(t *testing.T, c *Coordinator) Fence {
	t.Helper()
	f, err := c.Current()
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type blockingAuth struct {
	entered chan struct{}
	release chan struct{}
	calls   int
}

func (a *blockingAuth) Apply(OutboundItem) (AuthenticatedResponse, error) {
	a.calls++
	if a.entered != nil {
		close(a.entered)
		a.entered = nil
	}
	if a.release != nil {
		<-a.release
	}
	return AuthenticatedResponse{Version: Version, Kind: ResultAgreement, ReceiptHead: "head"}, nil
}

func (a *blockingAuth) View(string, string) (ViewSnapshot, error) { return ViewSnapshot{}, nil }

func ownerEnv(item OutboundItem, generation uint64) RoutingEnvelope {
	return RoutingEnvelope{Item: item, Generation: generation}
}

func fenceItem() OutboundItem {
	return OutboundItem{Version: Version, Tenant: tenant, AgreementID: "agreement-fence", OperationID: "op-fence", Kind: KindProtocol, SignedObject: []byte("signed")}
}

func TestCoordinatorZeroValueAndIssueRules(t *testing.T) {
	var coord Coordinator
	if _, err := coord.Current(); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if _, err := coord.Historical(); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if coord.Admission() != "stopped" {
		t.Fatal(coord.Admission())
	}
	if _, err := coord.Issue(""); !errors.Is(err, ErrItem) {
		t.Fatal(err)
	}
	if _, err := coord.StopAndFence(""); !errors.Is(err, ErrItem) {
		t.Fatal(err)
	}
	if _, err := coord.StopAndFence("owner-a"); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if _, err := coord.Activate("", "head"); !errors.Is(err, ErrItem) {
		t.Fatal(err)
	}
	if _, err := coord.Activate("owner-b", ""); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
	if _, err := coord.Activate("owner-b", "head"); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
	if err := coord.RecordCheckpoint(""); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
	if err := coord.StopAdmission(); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if err := coord.Resume(); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	coord.DisableFenceProof()
	var owner Owner
	if _, err := owner.Submit(RoutingEnvelope{}, Fence{}); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	owner.Deactivate()
	if err := coord.Authorize(Fence{}, nil); !errors.Is(err, ErrItem) {
		t.Fatal(err)
	}

	fence, err := coord.Issue("owner-a")
	if err != nil || fence.Generation != 1 || len(fence.Token) != 32 {
		t.Fatal(fence, err)
	}
	if _, err = coord.Issue("owner-b"); !errors.Is(err, ErrConcurrentOwner) {
		t.Fatal(err)
	}
	if err = coord.RecordCheckpoint("head"); err != nil {
		t.Fatal(err)
	}
	if _, err = coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = coord.Issue("owner-b"); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
	coord.mu.Lock()
	coord.generation = math.MaxUint64
	coord.checkpoint.Generation = math.MaxUint64
	coord.mu.Unlock()
	if _, err = coord.Activate("owner-b", "head"); !errors.Is(err, ErrGenerationOverflow) {
		t.Fatal(err)
	}
	if coord.generation != math.MaxUint64 {
		t.Fatal(coord.generation)
	}
}

func TestFencedTokenIsNotCurrentAndOldOwnerCannotSubmit(t *testing.T) {
	coord := &Coordinator{}
	fence, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	inner := &blockingAuth{}
	owner := BindOwner(coord, "owner-a", fence, inner)
	if err = coord.RecordCheckpoint("head"); err != nil {
		t.Fatal(err)
	}
	if _, err = coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = coord.Current(); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	historical, err := coord.Historical()
	if err != nil || !FencesEqual(historical, fence) {
		t.Fatal(historical, err)
	}
	owner.Active = true
	if _, err = owner.Submit(ownerEnv(fenceItem(), fence.Generation), fence); !errors.Is(err, ErrFenced) || inner.calls != 0 {
		t.Fatal(err, inner.calls)
	}
	owner.Deactivate()
	next, err := ActivateReplacement(coord, owner, "owner-b", "head", inner)
	if err != nil {
		t.Fatal(err)
	}
	owner.Active = true
	if _, err = owner.Submit(ownerEnv(fenceItem(), fence.Generation), fence); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	current, err := coord.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = next.Submit(ownerEnv(fenceItem(), current.Generation), current); err != nil || inner.calls != 1 {
		t.Fatal(err, inner.calls)
	}
	if _, err = next.Submit(ownerEnv(fenceItem(), fence.Generation), fence); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
}

func TestAdmissionGateAndSubmitVersusStop(t *testing.T) {
	coord := &Coordinator{}
	fence, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	if coord.Admission() != "open" {
		t.Fatal(coord.Admission())
	}
	inner := &blockingAuth{}
	owner := BindOwner(coord, "owner-a", fence, inner)
	if err = coord.StopAdmission(); err != nil {
		t.Fatal(err)
	}
	if coord.Admission() != "stopped" || owner.Admission {
		t.Fatal(coord.Admission(), owner.Admission)
	}
	if _, err = owner.Submit(ownerEnv(fenceItem(), fence.Generation), fence); !errors.Is(err, ErrAdmissionStopped) || inner.calls != 0 {
		t.Fatal(err, inner.calls)
	}
	if err = coord.Resume(); err != nil {
		t.Fatal(err)
	}
	if coord.Admission() != "open" || !owner.Admission {
		t.Fatal(coord.Admission(), owner.Admission)
	}
	release := make(chan struct{})
	entered := make(chan struct{})
	inner.entered = entered
	inner.release = release
	done := make(chan error, 1)
	go func() {
		_, err := owner.Submit(ownerEnv(fenceItem(), fence.Generation), fence)
		done <- err
	}()
	<-entered
	stopped := make(chan error, 1)
	go func() {
		_, err := coord.StopAndFence("owner-a")
		stopped <- err
	}()
	select {
	case err = <-stopped:
		t.Fatal("stop returned during submit", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = <-stopped; err != nil {
		t.Fatal(err)
	}
	if coord.Admission() != "stopped" {
		t.Fatal(coord.Admission())
	}
	if _, err = owner.Submit(ownerEnv(fenceItem(), fence.Generation), fence); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if err = coord.Resume(); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if inner.calls != 1 {
		t.Fatal(inner.calls)
	}
}

func TestCheckpointHandoffAndEffectFence(t *testing.T) {
	coord := &Coordinator{}
	_, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "src")
	if err = os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(src, "state.txt"), []byte("head-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "dst")
	if err = HandoffPrivateDir(coord, src, dst); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
	if err = coord.RecordCheckpoint(""); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
	if err = coord.RecordCheckpoint("head"); err != nil {
		t.Fatal(err)
	}
	if _, err = coord.Activate("owner-b", "other"); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}
	if _, err = coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	coord.DisableFenceProof()
	if _, err = coord.Activate("owner-b", "head"); !errors.Is(err, ErrActivation) {
		t.Fatal("lost proof activated", err)
	}
	if _, err = coord.StopAndFence("owner-a"); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	// Proof was removed and the generation is no longer active, so activation
	// stays refused. A new StopAndFence cannot invent proof for a dead generation.
	owner := &Owner{ID: "owner-a", Active: false}
	if _, err = ActivateReplacement(coord, owner, "owner-b", "head", &blockingAuth{}); !errors.Is(err, ErrActivation) {
		t.Fatal(err)
	}

	coord = &Coordinator{}
	if _, err = coord.Issue("owner-a"); err != nil {
		t.Fatal(err)
	}
	if err = coord.RecordCheckpoint("head"); err != nil {
		t.Fatal(err)
	}
	if _, err = coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "copied")
	if err = HandoffPrivateDir(coord, src, copied); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(copied, "state.txt"))
	if err != nil || string(got) != "head-bytes" {
		t.Fatal(string(got), err)
	}
	world := filepath.Join(t.TempDir(), "world")
	if err = os.Mkdir(world, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(world, 0755); err != nil {
		t.Fatal(err)
	}
	if err = CopyPrivateDir(src, world); !errors.Is(err, ErrStorageDir) {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err = os.Symlink(src, link); err != nil {
		t.Fatal(err)
	}
	if err = CopyPrivateDir(link, filepath.Join(t.TempDir(), "via-link")); !errors.Is(err, ErrStorageDir) {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(src, "state.txt"), filepath.Join(src, "alias")); err != nil {
		t.Fatal(err)
	}
	if err = CopyPrivateDir(src, filepath.Join(t.TempDir(), "alias-dst")); !errors.Is(err, ErrStorageDir) {
		t.Fatal(err)
	}
	nested := &Coordinator{}
	if _, err = nested.Issue("owner-a"); err != nil {
		t.Fatal(err)
	}
	if err = nested.RecordCheckpoint("head"); err != nil {
		t.Fatal(err)
	}
	if _, err = nested.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	first, err := ActivateReplacement(nested, &Owner{Active: false}, "owner-b", "head", &blockingAuth{})
	if err != nil {
		t.Fatal(err)
	}
	if err = nested.RecordCheckpoint("head-2"); err != nil {
		t.Fatal(err)
	}
	if _, err = nested.StopAndFence("owner-b"); err != nil {
		t.Fatal(err)
	}
	first.Deactivate()
	second, err := ActivateReplacement(nested, first, "owner-c", "head-2", &blockingAuth{})
	if err != nil || second.Fence.Generation != 3 || first.Active || first.Fence.Generation != 2 {
		t.Fatal(second, err)
	}
	if _, err = first.Submit(ownerEnv(fenceItem(), first.Fence.Generation), first.Fence); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}

	live := &Coordinator{}
	liveFence, err := live.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	effects, err := OpenEffects(filepath.Join(t.TempDir(), "effects"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "fenced-effect", AgreementID: "agreement-fence", Evidence: "tool"}
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	sink := NewMemoryDestination()
	sink.Guard = live
	hold := make(chan struct{})
	entered := make(chan struct{})
	sink.entered = entered
	sink.hold = hold
	applied := make(chan error, 1)
	go func() { applied <- effects.Apply(tenant, intent.EffectID, sink, liveFence) }()
	<-entered
	fenced := make(chan error, 1)
	go func() {
		_, err := live.StopAndFence("owner-a")
		fenced <- err
	}()
	select {
	case err = <-fenced:
		t.Fatal("fence returned during effect mutation", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(hold)
	if err = <-applied; err != nil {
		t.Fatal(err)
	}
	if err = <-fenced; err != nil {
		t.Fatal(err)
	}
	if sink.Executions(intent.EffectID) != 1 {
		t.Fatal(sink.Executions(intent.EffectID))
	}
	if _, err = sink.Execute(intent, EffectRef{Tenant: intent.Tenant, EffectID: intent.EffectID, AgreementID: intent.AgreementID, Digest: effectDigest(intent), Namespace: sink.Namespace()}, liveFence); err != nil {
		t.Fatal(err)
	}
	if sink.Executions(intent.EffectID) != 1 {
		t.Fatal("old fence mutated after stop", sink.Executions(intent.EffectID))
	}
}

func TestOwnerSubmitValidatesFenceBindingWithoutPrivateCoordinatorFields(t *testing.T) {
	var coord Coordinator
	f1, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	inner := &blockingAuth{}
	ownerA := BindCoordinatorOwner(&coord, "owner-a", f1, inner)
	if !ownerA.Active || !ownerA.Admission {
		t.Fatalf("expected active owner projection: %+v", ownerA)
	}
	if _, err := ownerA.Submit(ownerEnv(fenceItem(), f1.Generation+1), f1); !errors.Is(err, ErrFenced) {
		t.Fatalf("mismatched envelope generation accepted: %v", err)
	}
	if err := coord.RecordCheckpoint("head-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := coord.StopAndFence("owner-a"); err != nil {
		t.Fatal(err)
	}
	ownerA.Deactivate()
	ownerA2, err := ActivateCoordinatorReplacement(&coord, ownerA, "owner-a", "head-1", inner)
	if err != nil {
		t.Fatal(err)
	}
	f2 := ownerA2.Fence
	// Even if the same owner ID is reactivated in generation 2, the retired
	// generation-1 Owner struct cannot submit using generation 2's fence.
	if _, err := ownerA.Submit(ownerEnv(fenceItem(), f2.Generation), f2); !errors.Is(err, ErrFenced) {
		t.Fatalf("retired owner accepted newer fence: %v", err)
	}
	if _, err := ownerA2.Submit(ownerEnv(fenceItem(), f2.Generation), f2); err != nil || inner.calls != 1 {
		t.Fatalf("replacement owner submit failed: %v calls=%d", err, inner.calls)
	}
}
