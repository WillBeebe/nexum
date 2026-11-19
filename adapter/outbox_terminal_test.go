package adapter

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

func TestReceiverClockIgnoresBackdatedApplyAt(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-clock")
	resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	w.inner.Now = func() time.Time { return w.now.Add(2 * time.Hour) }
	retry, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil || retry.ReceiptHead != resp.ReceiptHead {
		t.Fatalf("historical retry: %+v %v", retry, err)
	}
	late := w.enqueueLock(t, o, "lock-late")
	if _, err = o.Reconcile(tenant, late.OperationID, w.inner); err == nil {
		t.Fatal("payload apply time overrode the receiver clock")
	}
}

func TestRecordVerifiedIsIdempotentForTheSameTerminal(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-terminal")
	resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	recordOK(t, o, w, item.OperationID, resp)
	recordOK(t, o, w, item.OperationID, resp)
	other := resp
	copied := *resp.Result
	copied.Head = nex.Hash("different-head")
	other.Result = &copied
	other.ReceiptHead = copied.Head
	if err = o.RecordVerified(tenant, item.OperationID, other, w.authPub, SignResponse(w.authority, other)); !errors.Is(err, ErrConflict) {
		t.Fatalf("different terminal: %v", err)
	}
}

func TestAwaitingVerificationIsNotATerminal(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-await")
	resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.Get(tenant, item.OperationID)
	if err != nil || got.Status != StatusAwaiting || got.Original != nil {
		t.Fatalf("candidate must stay unverified: %+v %v", got, err)
	}
	recordOK(t, o, w, item.OperationID, resp)
	got, err = o.Get(tenant, item.OperationID)
	if err != nil || got.Status != StatusResolved || got.Original == nil || got.Original.ReceiptHead != resp.ReceiptHead {
		t.Fatalf("verified: %+v %v", got, err)
	}
}

func TestStaleCommandIsDefinitiveRefusal(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	first := w.enqueueLock(t, o, "lock-first")
	stale := w.enqueueLock(t, o, "lock-stale")
	if _, err := o.Reconcile(tenant, first.OperationID, w.inner); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Reconcile(tenant, stale.OperationID, w.inner); err == nil {
		t.Fatal("stale command succeeded")
	}
	got, err := o.Get(tenant, stale.OperationID)
	if err != nil || got.Status != StatusRefused {
		t.Fatalf("status %+v %v", got, err)
	}
	if _, err = o.Reconcile(tenant, stale.OperationID, w.inner); !errors.Is(err, ErrDefinitive) {
		t.Fatalf("retry reapplied a definitive refusal: %v", err)
	}
	due, err := o.Due(tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range due {
		if item.Item.OperationID == stale.OperationID {
			t.Fatal("definitive refusal remained due")
		}
	}
	unresolved, err := o.Unresolved(tenant)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, item := range unresolved {
		if item.Item.OperationID == stale.OperationID {
			seen = true
		}
	}
	if !seen {
		t.Fatal("definitive refusal disappeared from unresolved")
	}
}

func TestCommitUncertainIsNotDefinitiveRefusal(t *testing.T) {
	resp, err := classifyStore(AuthenticatedResponse{}, nex.Result{}, fmt.Errorf("%w: sync", nex.ErrCommitUncertain))
	if resp.Kind != ResultUncertain || resp.Definitive || !errors.Is(err, nex.ErrCommitUncertain) {
		t.Fatalf("classified %+v %v", resp, err)
	}
	if status := statusFor(resp, err); status != StatusUnknown || terminalOutbox(status) {
		t.Fatalf("durability uncertainty became terminal: %s", status)
	}
}

func TestLegacyResolvedSignatureIsNotFabricated(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	item := w.enqueueLock(t, o, "lock-legacy")
	resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil {
		t.Fatal(err)
	}
	recordOK(t, o, w, item.OperationID, resp)
	id := recordID(tenant, item.OperationID)
	if err = o.vault.withLock(func() error {
		var stored itemRecord
		if err := o.vault.read(id, &stored); err != nil {
			return err
		}
		if len(stored.VerifiedSignature) == 0 || len(stored.Authority.Signing) == 0 {
			return errors.New("new record missing proof")
		}
		stored.VerifiedSignature = nil
		stored.Authority = nex.Public{}
		return o.vault.write(id, stored)
	}); err != nil {
		t.Fatal(err)
	}
	got, err := o.Get(tenant, item.OperationID)
	if err != nil || got.Status != StatusResolved {
		t.Fatalf("legacy local provenance rejected: %+v %v", got, err)
	}
	if err = o.vault.withLock(func() error {
		var stored itemRecord
		if err := o.vault.read(id, &stored); err != nil {
			return err
		}
		stored.VerifiedSignature = []byte("not-a-signature")
		return o.vault.write(id, stored)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = o.Get(tenant, item.OperationID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("partial proof accepted: %v", err)
	}
}

func TestHistoryBoundDoesNotEvict(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)
	o.HistoryLimit = 1
	item := w.enqueueLock(t, o, "lock-history")
	op, err := w.store.Prepare(w.contract.ID(), "lock-history-2", "lock", "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
	if err != nil {
		t.Fatal(err)
	}
	second := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.contract.ID(), OperationID: "lock-history-2", Kind: KindAgreement, SignedObject: raw, Destination: "authority-1", CreatedAt: w.now}
	if err = o.Enqueue(second); !errors.Is(err, ErrQuota) {
		t.Fatal(err)
	}
	got, err := o.Get(tenant, item.OperationID)
	if err != nil || got.Status != StatusPending {
		t.Fatalf("history bound evicted or dropped the first row: %+v %v", got, err)
	}
}

func TestDecodePayloadRejectsMixedBodies(t *testing.T) {
	raw := []byte(`{"version":1,"kind":"agreement","operation":{"id":"op"},"command":{"protocol_id":"p","request_id":"op"},"signature":"YQ=="}`)
	if _, err := DecodePayload(raw); err == nil {
		t.Fatal("accepted agreement and protocol payloads together")
	}
}
