package adapter

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/WillBeebe/nexum/nex"
)

func TestFencedHandoffRejectsOldOwnerAndStaleSnapshot(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	coord := &Coordinator{}
	srcFence, err := coord.Issue("owner-a")
	if err != nil {
		t.Fatal(err)
	}
	src := BindOwner("owner-a", srcFence, w.inner)
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
	src := BindOwner("owner-a", srcFence, w.inner)
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
	src := BindOwner("owner-a", mustFence(t, coord), w.inner)
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
