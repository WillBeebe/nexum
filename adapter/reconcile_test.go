package adapter

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

func TestLostResponseExactRetryStore(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-1")
	w.inner.DropNext = true
	_, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if !errors.Is(err, ErrLostResponse) {
		t.Fatalf("lost: %v", err)
	}
	got, err := o.Get(tenant, item.OperationID)
	if err != nil || got.Status != StatusUnknown {
		t.Fatalf("status %+v %v", got, err)
	}
	first, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil || first.Result == nil {
		t.Fatal(first, err)
	}
	recordOK(t, o, w, item.OperationID, first)
	again, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil || again.Result == nil || again.Result.Head != first.Result.Head {
		t.Fatal(again, err)
	}
	view, err := w.inner.View(tenant, w.contract.ID())
	if err != nil || view.Status != nex.StatusLocked {
		t.Fatal(view, err)
	}
}

func TestLostResponseExactRetryProtocol(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	w.enqueue(t, o, w.owner, "", "admit", "owner-admit", 1, nil)
	w.inner.DropNext = true
	_, err := o.Reconcile(tenant, "owner-admit", w.inner)
	if !errors.Is(err, ErrLostResponse) {
		t.Fatal(err)
	}
	resp, err := o.Reconcile(tenant, "owner-admit", w.inner)
	if err != nil || resp.ReceiptHead == "" {
		t.Fatal(resp, err)
	}
	retry, err := o.Reconcile(tenant, "owner-admit", w.inner)
	if err != nil || retry.ReceiptHead != resp.ReceiptHead {
		t.Fatal(retry, err)
	}
	v, err := w.store.View(w.id)
	if err != nil || len(v.Admitted) != 1 {
		t.Fatal(v, err)
	}
}

func TestProtocolV2AuthorityUsesReceiverHeight(t *testing.T) {
	w := newProtocolWorld(t)
	w.spec.Version = nex.ProtocolVersionV2
	var err error
	w.id, err = w.store.Create(w.spec)
	if err != nil {
		t.Fatal(err)
	}
	item := w.enqueue(t, testOutbox(t), w.owner, "", "admit", "owner-admit", 1, nil)
	if _, err := w.inner.Apply(item); !errors.Is(err, nex.ErrProtocolAuthority) {
		t.Fatalf("accepted v2 with no receiver height: %v", err)
	}
	height := w.spec.WorkByHeight
	w.inner.Height = func() uint64 { return height }
	if _, err := w.inner.Apply(item); !errors.Is(err, nex.ErrProtocolStale) {
		t.Fatalf("accepted sender's earlier height: %v", err)
	}
	height = 1
	first, err := w.inner.Apply(item)
	if err != nil || first.ReceiptHead == "" {
		t.Fatal(first, err)
	}
	height = w.spec.ReturnByHeight
	if retry, err := w.inner.Apply(item); err != nil || retry.ReceiptHead != first.ReceiptHead {
		t.Fatal(retry, err)
	}
}

func TestCrashBeforeSubmitAndAfterResult(t *testing.T) {
	w := newStoreWorld(t)
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "outbox")
	o, err := OpenOutbox(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	item := w.enqueueLock(t, o, "lock-crash")
	reopened, err := OpenOutbox(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopened.Get(tenant, item.OperationID)
	if err != nil || pending.Status != StatusPending || !bytes.Equal(pending.Item.SignedObject, item.SignedObject) {
		t.Fatal(pending, err)
	}
	resp, err := reopened.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	// Crash after result, before RecordVerified.
	again, err := OpenOutbox(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := again.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil || retry.Result == nil || retry.Result.Head != resp.Result.Head {
		t.Fatal(retry, err)
	}
	recordOK(t, again, w, item.OperationID, retry)
	resolved, err := again.Get(tenant, item.OperationID)
	if err != nil || resolved.Status != StatusResolved || resolved.Original == nil {
		t.Fatal(resolved, err)
	}
	view, err := w.inner.View(tenant, w.contract.ID())
	if err != nil || view.Head != resolved.Original.ReceiptHead {
		t.Fatal("original result must remain distinct from later views only after more ops", view, resolved.Original)
	}
}

func TestOperationConflictPreserved(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-conflict")
	resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	recordOK(t, o, w, item.OperationID, resp)
	payload, err := DecodePayload(item.SignedObject)
	if err != nil {
		t.Fatal(err)
	}
	changed := *payload.Operation
	changed.Command.Evidence = "different"
	raw, err := EncodeOperation(changed, nex.Sign(w.buyer, "operation", changed), w.now)
	if err != nil {
		t.Fatal(err)
	}
	foreign := item
	foreign.SignedObject = raw
	got, err := w.inner.Apply(foreign)
	if !errors.Is(err, nex.ErrOperationConflict) || got.Kind != ResultConflict {
		t.Fatalf("conflict: %+v %v", got, err)
	}
}

func TestRefuseForeignTenantCommandAgreement(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-foreign")
	resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	other := resp
	other.Tenant = "other-tenant"
	if err = o.RecordVerified(tenant, item.OperationID, other, w.authPub, SignResponse(w.authority, other)); !errors.Is(err, ErrTenant) {
		t.Fatal(err)
	}
	other = resp
	other.AgreementID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err = o.RecordVerified(tenant, item.OperationID, other, w.authPub, SignResponse(w.authority, other)); !errors.Is(err, ErrForeign) {
		t.Fatal(err)
	}
	other = resp
	other.CommandHash = nex.Hash("not-this-command")
	if err = o.RecordVerified(tenant, item.OperationID, other, w.authPub, SignResponse(w.authority, other)); !errors.Is(err, ErrForeign) {
		t.Fatal(err)
	}
	w.inner.Tenant = tenant
	cross := item
	cross.Tenant = "other-tenant"
	if _, err = w.inner.Apply(cross); !errors.Is(err, ErrTenant) {
		t.Fatal(err)
	}
}

func TestFailureReturnIsNotWorkSuccess(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	w.apply(t, o, w.owner, "", "admit", "admit-owner", 1, nil)
	w.apply(t, o, w.worker, "", "admit", "admit-worker", 2, nil)
	w.apply(t, o, w.witness, "", "admit", "admit-witness", 3, nil)
	w.apply(t, o, w.owner, "owner", "commit", "commit-1", 4, nil)
	w.apply(t, o, w.worker, "worker", "report", "report-1", 5, func(c *nex.ProtocolCommand) {
		c.Report = &nex.WorkReport{Outcome: nex.WorkSpecDefect, Stage: "inputs", ReasonHash: nex.Hash("missing dataset"), Evidence: []string{nex.Hash("gap")}}
	})
	w.apply(t, o, w.witness, "witness", "review", "review-1", 6, func(c *nex.ProtocolCommand) {
		c.Review = &nex.WitnessReview{ReportHash: nex.Hash(mustView(t, w).Report), AssessmentHash: nex.Hash("dissent"), Dissent: true}
	})
	w.apply(t, o, w.owner, "owner", "resolve", "resolve-1", 7, func(c *nex.ProtocolCommand) {
		c.Resolution = &nex.Resolution{ReportHash: nex.Hash(mustView(t, w).Report), Outcome: "reject", ReasonHash: nex.Hash("no answer")}
	})
	w.apply(t, o, w.worker, "worker", "return", "return-1", 8, func(c *nex.ProtocolCommand) {
		m := failManifest(mustView(t, w))
		c.Return = &m
	})
	v := mustView(t, w)
	if v.Phase != "complete" || !v.Reviews[0].Review.Dissent {
		t.Fatalf("%+v", v)
	}
	if WorkSucceeded(v) {
		t.Fatal("complete failure return reported as success")
	}
}

func TestLostEffectDoesNotReexecute(t *testing.T) {
	key := testKey(t)
	effects, err := OpenEffects(filepath.Join(t.TempDir(), "effects"), key)
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "effect-1", AgreementID: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", Evidence: "tool"}
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	dest := NewMemoryDestination()
	dest.Fence = Fence{Version: Version, Generation: 1, Owner: "a", Token: bytes.Repeat([]byte{1}, 32)}
	dest.LoseNext = true
	if err = effects.Apply(tenant, intent.EffectID, dest, dest.Fence); !errors.Is(err, ErrEffectUnknown) {
		t.Fatal(err)
	}
	if dest.Executions(intent.EffectID) != 1 {
		t.Fatal(dest.Executions(intent.EffectID))
	}
	if err = effects.Apply(tenant, intent.EffectID, dest, dest.Fence); !errors.Is(err, ErrEffectReexecute) {
		t.Fatal(err)
	}
	if dest.Executions(intent.EffectID) != 1 {
		t.Fatal("reexecuted", dest.Executions(intent.EffectID))
	}
	rec, err := effects.Get(tenant, intent.EffectID)
	if err != nil || rec.Phase != EffectPhaseUnknown || rec.Confirmed {
		t.Fatal(rec, err)
	}
}

func TestOriginalResultDistinctFromLaterView(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-then-later")
	lock, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	recordOK(t, o, w, item.OperationID, lock)
	for _, step := range []struct{ action, id string }{{"agree", "agree-1"}, {"settle", "settle-1"}} {
		signer := w.seller
		if step.action == "settle" {
			signer = w.buyer
		}
		op, err := w.store.Prepare(w.contract.ID(), step.id, step.action, "checked artifact")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := EncodeOperation(op, nex.Sign(signer, "operation", op), w.now)
		if err != nil {
			t.Fatal(err)
		}
		next := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.contract.ID(), OperationID: step.id, Kind: KindAgreement, SignedObject: raw, Destination: "authority-1", CreatedAt: w.now}
		if err = o.Enqueue(next); err != nil {
			t.Fatal(err)
		}
		resp, err := o.Reconcile(tenant, step.id, w.inner)
		if err != nil {
			t.Fatal(step.action, err)
		}
		recordOK(t, o, w, step.id, resp)
	}
	held, err := o.Get(tenant, item.OperationID)
	if err != nil || held.Original == nil || held.Original.Result == nil {
		t.Fatal(held, err)
	}
	view, err := w.inner.View(tenant, w.contract.ID())
	if err != nil || view.Status != nex.StatusAccepted {
		t.Fatal(view, err)
	}
	if held.Original.Result.Head == view.Head || held.Original.Result.Status != nex.StatusLocked {
		t.Fatal("original lock result overwritten by current state", held.Original.Result, view)
	}
	retry, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil || retry.Result == nil || retry.Result.Head != held.Original.Result.Head {
		t.Fatal(retry, err)
	}
}

func TestBackoffDueAndStopAdmission(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	now := w.now
	o.SetNow(func() time.Time { return now })
	item := w.enqueueLock(t, o, "lock-backoff")
	w.inner.DropNext = true
	if _, err := o.Reconcile(tenant, item.OperationID, w.inner); !errors.Is(err, ErrLostResponse) {
		t.Fatal(err)
	}
	due, err := o.Due(tenant)
	if err != nil || len(due) != 0 {
		t.Fatal("backoff not applied", due, err)
	}
	if _, err = o.ReconcileDue(tenant, item.OperationID, w.inner); !errors.Is(err, ErrNotDue) {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Second)
	due, err = o.Due(tenant)
	if err != nil || len(due) != 1 {
		t.Fatal(due, err)
	}
	if _, err = o.ReconcileDue(tenant, item.OperationID, w.inner); err != nil {
		t.Fatal(err)
	}
	o.StopAdmission()
	op, err := w.store.Prepare(w.contract.ID(), "lock-late", "lock", "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
	if err != nil {
		t.Fatal(err)
	}
	late := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.contract.ID(), OperationID: "lock-late", Kind: KindAgreement, SignedObject: raw, Destination: "authority-1", CreatedAt: w.now}
	if err = o.Enqueue(late); !errors.Is(err, ErrAdmissionStopped) {
		t.Fatal(err)
	}
	if unresolved, err := o.Unresolved(tenant); err != nil || len(unresolved) != 1 {
		t.Fatal("stopped admission evicted work")
	}
}

func TestOutboxDurableAdmissionGateAcrossReopenAndCopy(t *testing.T) {
	w := newStoreWorld(t)
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "outbox")
	o, err := OpenOutbox(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if sealed, gen, err := o.AdmissionSealed(); err != nil || sealed || gen != 0 {
		t.Fatalf("initial gate: sealed=%v gen=%d err=%v", sealed, gen, err)
	}
	item := w.enqueueLock(t, o, "lock-before-seal")
	if err := o.SealAdmission(1); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenOutbox(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if sealed, gen, err := reopened.AdmissionSealed(); err != nil || !sealed || gen != 1 {
		t.Fatalf("reopened gate: sealed=%v gen=%d err=%v", sealed, gen, err)
	}
	op2, err := w.store.Prepare(w.contract.ID(), "lock-blocked", "lock", "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := EncodeOperation(op2, nex.Sign(w.buyer, "operation", op2), w.now)
	if err != nil {
		t.Fatal(err)
	}
	blocked := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.contract.ID(), OperationID: "lock-blocked", Kind: KindAgreement, SignedObject: raw2, Destination: "authority-1", CreatedAt: w.now}
	if err := reopened.Enqueue(blocked); !errors.Is(err, ErrAdmissionStopped) {
		t.Fatalf("expected ErrAdmissionStopped on reopened outbox, got %v", err)
	}
	if _, err := reopened.Reconcile(tenant, item.OperationID, w.inner); err != nil {
		t.Fatalf("reconcile existing item while sealed failed: %v", err)
	}

	copiedDir := filepath.Join(t.TempDir(), "outbox-copy")
	if err := CopyPrivateDir(dir, copiedDir); err != nil {
		t.Fatal(err)
	}
	copied, err := OpenOutbox(copiedDir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := copied.Enqueue(blocked); !errors.Is(err, ErrAdmissionStopped) {
		t.Fatalf("expected copied outbox to preserve sealed gate, got %v", err)
	}
	if err := copied.ResumeAdmission(0); !errors.Is(err, ErrActivation) {
		t.Fatalf("expected stale generation resume refusal, got %v", err)
	}
	if err := copied.ResumeAdmission(2); err != nil {
		t.Fatal(err)
	}
	if sealed, gen, err := copied.AdmissionSealed(); err != nil || sealed || gen != 2 {
		t.Fatalf("resumed gate: sealed=%v gen=%d err=%v", sealed, gen, err)
	}
	if err := copied.Enqueue(blocked); err != nil {
		t.Fatalf("enqueue after ResumeAdmission failed: %v", err)
	}
}

func TestIdempotentEffectReconcilesWithoutReexecute(t *testing.T) {
	effects, err := OpenEffects(filepath.Join(t.TempDir(), "effects"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "effect-ok", AgreementID: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", Evidence: "tool"}
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	dest := NewMemoryDestination()
	dest.Fence = Fence{Version: Version, Generation: 1, Owner: "a", Token: bytes.Repeat([]byte{2}, 32)}
	dest.Idempotent = true
	dest.LoseNext = true
	if err = effects.Apply(tenant, intent.EffectID, dest, dest.Fence); !errors.Is(err, ErrEffectUnknown) {
		t.Fatal(err)
	}
	if err = effects.Apply(tenant, intent.EffectID, dest, dest.Fence); err != nil {
		t.Fatal(err)
	}
	rec, err := effects.Get(tenant, intent.EffectID)
	if err != nil || rec.Phase != EffectPhaseConfirmed || !rec.Confirmed || dest.Executions(intent.EffectID) != 1 {
		t.Fatal(rec, dest.Executions(intent.EffectID), err)
	}
}

func TestQuotaRefusesWithoutEvicting(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	o.Quota = 1
	item := w.enqueueLock(t, o, "lock-quota")
	op, err := w.store.Prepare(w.contract.ID(), "lock-quota-2", "lock", "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
	if err != nil {
		t.Fatal(err)
	}
	second := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.contract.ID(), OperationID: "lock-quota-2", Kind: KindAgreement, SignedObject: raw, Destination: "authority-1", CreatedAt: w.now}
	if err = o.Enqueue(second); !errors.Is(err, ErrQuota) {
		t.Fatal(err)
	}
	unresolved, err := o.Unresolved(tenant)
	if err != nil || len(unresolved) != 1 || unresolved[0].Item.OperationID != item.OperationID {
		t.Fatal(unresolved, err)
	}
}

func mustView(t *testing.T, w protocolWorld) nex.ProtocolView {
	t.Helper()
	v, err := w.store.View(w.id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
