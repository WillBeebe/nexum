package adapter

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

// Regression test for BUG-07: Outbox and EffectAdapter sharing one vault
// directory must remain completely isolated (even for colliding tenant+id).
func TestV202OutboxSharedVaultWithEffectsIsolated(t *testing.T) {
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

	first := w.enqueueLock(t, outbox, "shared-op-1")

	if err := effects.Intend(EffectIntent{
		Tenant:      "other-tenant",
		EffectID:    "eff-1",
		AgreementID: w.contract.ID(),
		Evidence:    "ev",
	}); err != nil {
		t.Fatal(err)
	}

	due, err := outbox.Due(tenant)
	if err != nil || len(due) != 1 {
		t.Fatalf("outbox.Due failed in shared vault: due=%v err=%v", due, err)
	}
	unres, err := outbox.Unresolved(tenant)
	if err != nil || len(unres) != 1 {
		t.Fatalf("outbox.Unresolved failed in shared vault: unres=%v err=%v", unres, err)
	}
	op2, err := w.store.Prepare(w.contract.ID(), "shared-op-2", "lock", "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := EncodeOperation(op2, nex.Sign(w.buyer, "operation", op2), w.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := outbox.Enqueue(OutboundItem{
		Version: Version, Tenant: tenant, AgreementID: w.contract.ID(),
		OperationID: "shared-op-2", Kind: KindAgreement, SignedObject: raw2,
		Destination: "authority-1", CreatedAt: w.now,
	}); err != nil {
		t.Fatalf("outbox.Enqueue failed in shared vault: %v", err)
	}

	// effects.Get on colliding (tenant, id) MUST return ErrNotFound and MUST NOT
	// overwrite or corrupt the Outbox .box record on disk.
	if _, err := effects.Get(first.Tenant, first.OperationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for effects.Get on outbox ID, got %v", err)
	}
	gotOutbox, err := outbox.Get(first.Tenant, first.OperationID)
	if err != nil || !bytes.Equal(gotOutbox.Item.SignedObject, first.SignedObject) {
		t.Fatalf("outbox item damaged after effects.Get: got=%+v err=%v", gotOutbox, err)
	}

	// Intending an Effect with the EXACT SAME (tenant, id) as the Outbox item
	// MUST coexist cleanly with both records intact.
	collidingIntent := EffectIntent{
		Tenant:      first.Tenant,
		EffectID:    first.OperationID,
		AgreementID: w.contract.ID(),
		Evidence:    "colliding-effect",
	}
	if err := effects.Intend(collidingIntent); err != nil {
		t.Fatalf("effects.Intend with colliding (tenant, id) failed: %v", err)
	}
	sink := NewMemoryDestination()
	sink.Guard = coord
	if err := effects.Apply(collidingIntent.Tenant, collidingIntent.EffectID, sink, f1); err != nil {
		t.Fatalf("effects.Apply in shared vault failed: %v", err)
	}
	gotEff, err := effects.Get(collidingIntent.Tenant, collidingIntent.EffectID)
	if err != nil || gotEff.Phase != EffectPhaseConfirmed {
		t.Fatalf("expected confirmed effect, got %+v %v", gotEff, err)
	}
	gotOutbox, err = outbox.Get(first.Tenant, first.OperationID)
	if err != nil || !bytes.Equal(gotOutbox.Item.SignedObject, first.SignedObject) {
		t.Fatalf("outbox item damaged after colliding effect Apply: got=%+v err=%v", gotOutbox, err)
	}
	if due, err := outbox.Due(tenant); err != nil || len(due) != 2 {
		t.Fatalf("outbox.Due after colliding effect failed: len=%d err=%v", len(due), err)
	}
}

// Regression test for BUG-08: Stale SealAdmission must not latch o.stopped, and
// cross-handle ResumeAdmission must immediately unblock prior handles.
func TestV202OutboxSealAdmissionStaleGenAndCrossHandleResume(t *testing.T) {
	t.Run("StaleSealDoesNotLatchStopped", func(t *testing.T) {
		w := newStoreWorld(t)
		key := testKey(t)
		dir := filepath.Join(t.TempDir(), "outbox-seal-a")

		o1, err := OpenOutbox(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := o1.SealAdmission(2); err != nil {
			t.Fatal(err)
		}
		if err := o1.ResumeAdmission(3); err != nil {
			t.Fatal(err)
		}
		if sealed, gen, err := o1.AdmissionSealed(); err != nil || sealed || gen != 3 {
			t.Fatalf("expected open at gen 3, got sealed=%v gen=%d err=%v", sealed, gen, err)
		}

		if err := o1.SealAdmission(1); !errors.Is(err, ErrActivation) {
			t.Fatalf("expected ErrActivation for stale SealAdmission(1), got %v", err)
		}

		sealed, gen, err := o1.AdmissionSealed()
		if err != nil || sealed || gen != 3 {
			t.Fatalf("stale SealAdmission corrupted handle state: sealed=%v gen=%d err=%v", sealed, gen, err)
		}
		op, err := w.store.Prepare(w.contract.ID(), "op-after-stale-seal", "lock", "checked")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
		if err != nil {
			t.Fatal(err)
		}
		item := OutboundItem{
			Version: Version, Tenant: tenant, AgreementID: w.contract.ID(),
			OperationID: "op-after-stale-seal", Kind: KindAgreement, SignedObject: raw,
			Destination: "authority-1", CreatedAt: w.now,
		}
		if err := o1.Enqueue(item); err != nil {
			t.Fatalf("Enqueue after rejected stale SealAdmission failed: %v", err)
		}
	})

	t.Run("CrossHandleResumeUnblocksFirstHandle", func(t *testing.T) {
		w := newStoreWorld(t)
		key := testKey(t)
		dir := filepath.Join(t.TempDir(), "outbox-seal-b")

		o1, err := OpenOutbox(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		o2, err := OpenOutbox(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := o1.SealAdmission(1); err != nil {
			t.Fatal(err)
		}
		if err := o2.ResumeAdmission(2); err != nil {
			t.Fatal(err)
		}
		s1, g1, err := o1.AdmissionSealed()
		if err != nil || s1 || g1 != 2 {
			t.Fatalf("o1 did not sync cross-handle ResumeAdmission: sealed=%v gen=%d err=%v", s1, g1, err)
		}
		op, err := w.store.Prepare(w.contract.ID(), "op-after-cross-resume", "lock", "checked")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
		if err != nil {
			t.Fatal(err)
		}
		if err := o1.Enqueue(OutboundItem{
			Version: Version, Tenant: tenant, AgreementID: w.contract.ID(),
			OperationID: "op-after-cross-resume", Kind: KindAgreement, SignedObject: raw,
			Destination: "authority-1", CreatedAt: w.now,
		}); err != nil {
			t.Fatalf("o1.Enqueue after o2.ResumeAdmission failed: %v", err)
		}
	})
}

// Regression test for BUG-09: validateID rejects NUL bytes and both recordID
// and EffectRef.slot() are length-framed to prevent cross-tenant collisions.
func TestV202ValidateIDRejectsNulBytesAndLengthFramesKeys(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)

	opA, err := w.store.Prepare(w.contract.ID(), "beta\x00gamma", "lock", "checked")
	if err != nil {
		t.Fatal(err)
	}
	rawA, err := EncodeOperation(opA, nex.Sign(w.buyer, "operation", opA), w.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(OutboundItem{
		Version: Version, Tenant: "alpha", AgreementID: w.contract.ID(),
		OperationID: "beta\x00gamma", Kind: KindAgreement, SignedObject: rawA,
		Destination: "authority-1", CreatedAt: w.now,
	}); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for NUL byte in OperationID, got %v", err)
	}

	opB, err := w.store.Prepare(w.contract.ID(), "gamma", "lock", "checked")
	if err != nil {
		t.Fatal(err)
	}
	rawB, err := EncodeOperation(opB, nex.Sign(w.buyer, "operation", opB), w.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Enqueue(OutboundItem{
		Version: Version, Tenant: "alpha\x00beta", AgreementID: w.contract.ID(),
		OperationID: "gamma", Kind: KindAgreement, SignedObject: rawB,
		Destination: "authority-1", CreatedAt: w.now,
	}); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for NUL byte in Tenant, got %v", err)
	}

	effects, err := OpenEffects(filepath.Join(t.TempDir(), "effects-nul"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := effects.Intend(EffectIntent{Tenant: "alpha", EffectID: "beta\x00gamma", AgreementID: "ag1", Evidence: "a"}); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for NUL byte in EffectID, got %v", err)
	}
	if err := effects.Intend(EffectIntent{Tenant: "alpha\x00beta", EffectID: "gamma", AgreementID: "ag2", Evidence: "b"}); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for NUL byte in Effect Tenant, got %v", err)
	}

	// Length-framing guarantees injectivity even if internal helpers are called directly.
	if recordID("alpha", "beta\x00gamma") == recordID("alpha\x00beta", "gamma") {
		t.Fatal("recordID collided across NUL-delimited boundary")
	}

	dest := NewMemoryDestination()
	dest.Space = "ns"
	dest.Fence = Fence{Version: Version, Generation: 1, Owner: "a", Token: bytes.Repeat([]byte{3}, 32)}
	ref1 := EffectRef{Tenant: "t1", Namespace: "ns", EffectID: "x\x00y", AgreementID: "ag1", Digest: "d1"}
	ref2 := EffectRef{Tenant: "t1\x00ns", Namespace: "x", EffectID: "y", AgreementID: "ag2", Digest: "d2"}
	if ref1.slot() == ref2.slot() {
		t.Fatalf("EffectRef.slot collided: %q", ref1.slot())
	}
	if _, err := dest.Execute(EffectIntent{Tenant: "t1", EffectID: "x\x00y", AgreementID: "ag1"}, ref1, dest.Fence); err != nil {
		t.Fatal(err)
	}
	if _, err := dest.Execute(EffectIntent{Tenant: "t1\x00ns", EffectID: "y", AgreementID: "ag2"}, ref2, dest.Fence); err != nil {
		t.Fatalf("MemoryDestination collided distinct EffectRefs: %v", err)
	}
}

type scriptedAuthority struct {
	apply func(OutboundItem) (AuthenticatedResponse, error)
}

func (a *scriptedAuthority) Apply(item OutboundItem) (AuthenticatedResponse, error) {
	return a.apply(item)
}
func (a *scriptedAuthority) View(string, string) (ViewSnapshot, error) { return ViewSnapshot{}, nil }

// Regression test for BUG-11: Reconcile rejects invalid (got, nil) candidates
// without bricking the vault, and clears stale unverified candidates when
// transitioning to StatusUnknown so genuine RecordVerified succeeds.
func TestV202OutboxRejectsInvalidCandidateAndClearsStaleOnUnknown(t *testing.T) {
	t.Run("ErrorFieldRejectedWithoutBrickingVault", func(t *testing.T) {
		w := newStoreWorld(t)
		o := testOutbox(t)
		item := w.enqueueLock(t, o, "op-bad-cand")

		badAuth := &scriptedAuthority{
			apply: func(it OutboundItem) (AuthenticatedResponse, error) {
				return AuthenticatedResponse{
					Version:     Version,
					Tenant:      it.Tenant,
					AgreementID: it.AgreementID,
					RequestID:   it.OperationID,
					CommandHash: CommandHash(it.SignedObject),
					Kind:        ResultAgreement,
					Result:      &nex.Result{Head: "some-head"},
					ReceiptHead: "some-head",
					Error:       "non-empty error alongside nil Go error",
				}, nil
			},
		}
		if _, err := o.Reconcile(tenant, item.OperationID, badAuth); !errors.Is(err, ErrResponse) {
			t.Fatalf("expected ErrResponse for invalid candidate with Error!=empty, got %v", err)
		}

		rec, err := o.Get(tenant, item.OperationID)
		if err != nil || rec.Status != StatusUnknown {
			t.Fatalf("expected healthy StatusUnknown after bad candidate, got %+v %v", rec, err)
		}
		if _, err := o.Due("completely-other-tenant"); err != nil {
			t.Fatalf("Due for other tenant failed: %v", err)
		}
		opOther, err := w.store.Prepare(w.contract.ID(), "op-other", "lock", "checked")
		if err != nil {
			t.Fatal(err)
		}
		rawOther, err := EncodeOperation(opOther, nex.Sign(w.buyer, "operation", opOther), w.now)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Enqueue(OutboundItem{
			Version: Version, Tenant: "completely-other-tenant", AgreementID: w.contract.ID(),
			OperationID: "op-other", Kind: KindAgreement, SignedObject: rawOther,
			Destination: "authority-1", CreatedAt: w.now,
		}); err != nil {
			t.Fatalf("Enqueue for other tenant failed: %v", err)
		}

		// Also reject invalid shape (nil Result for KindAgreement).
		missingResultAuth := &scriptedAuthority{
			apply: func(it OutboundItem) (AuthenticatedResponse, error) {
				return AuthenticatedResponse{
					Version:     Version,
					Tenant:      it.Tenant,
					AgreementID: it.AgreementID,
					RequestID:   it.OperationID,
					CommandHash: CommandHash(it.SignedObject),
					Kind:        ResultAgreement,
					ReceiptHead: "head-without-result",
				}, nil
			},
		}
		if _, err := o.Reconcile(tenant, item.OperationID, missingResultAuth); !errors.Is(err, ErrResponse) {
			t.Fatalf("expected ErrResponse for KindAgreement response missing Result, got %v", err)
		}
	})

	t.Run("UnverifiedCandidateClearedOnUnknownAllowsRealRecordVerified", func(t *testing.T) {
		w := newStoreWorld(t)
		o := testOutbox(t)
		item := w.enqueueLock(t, o, "op-spoof-cand")

		realResp, err := w.inner.Apply(item)
		if err != nil {
			t.Fatal(err)
		}
		realSig := SignResponse(w.authority, realResp)

		attempt := 0
		untrusted := &scriptedAuthority{
			apply: func(it OutboundItem) (AuthenticatedResponse, error) {
				attempt++
				if attempt == 1 {
					// Structurally valid spoofed unsigned candidate -> enters StatusAwaiting.
					return AuthenticatedResponse{
						Version:     Version,
						Tenant:      it.Tenant,
						AgreementID: it.AgreementID,
						RequestID:   it.OperationID,
						CommandHash: CommandHash(it.SignedObject),
						Kind:        ResultAgreement,
						Result:      &nex.Result{Head: "spoofed-unsigned-head"},
						ReceiptHead: "spoofed-unsigned-head",
					}, nil
				}
				return AuthenticatedResponse{Version: Version, Kind: ResultUncertain}, ErrLostResponse
			},
		}
		if _, err := o.Reconcile(tenant, item.OperationID, untrusted); err != nil {
			t.Fatal(err)
		}
		recAwait, err := o.Get(tenant, item.OperationID)
		if err != nil || recAwait.Status != StatusAwaiting {
			t.Fatalf("expected StatusAwaiting on attempt 1, got %+v %v", recAwait, err)
		}
		if _, err := o.Reconcile(tenant, item.OperationID, untrusted); !errors.Is(err, ErrLostResponse) {
			t.Fatalf("expected ErrLostResponse on attempt 2, got %v", err)
		}
		rec, err := o.Get(tenant, item.OperationID)
		if err != nil || rec.Status != StatusUnknown {
			t.Fatalf("expected StatusUnknown, got %+v %v", rec, err)
		}

		// Stale unverified candidate was cleared on StatusUnknown, so genuine
		// signed authority response MUST be accepted.
		if err := o.RecordVerified(tenant, item.OperationID, realResp, w.authPub, realSig); err != nil {
			t.Fatalf("RecordVerified blocked by stale unverified candidate: %v", err)
		}
	})
}

// Regression test for BUG-25: validateItem and Authorities must enforce
// payload.Kind == item.Kind and matching operation/agreement IDs, and
// duplicate Enqueue must reject conflicting metadata with ErrConflict.
func TestV202OutboxValidatesPayloadKindMetadataAndDuplicateConflicts(t *testing.T) {
	t.Run("KindAndMetadataMismatchRejected", func(t *testing.T) {
		w := newStoreWorld(t)
		pw := newProtocolWorld(t)
		o := testOutbox(t)

		op, err := w.store.Prepare(w.contract.ID(), "op-kind-mismatch", "lock", "checked")
		if err != nil {
			t.Fatal(err)
		}
		rawOp, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
		if err != nil {
			t.Fatal(err)
		}

		mismatched := OutboundItem{
			Version:      Version,
			Tenant:       tenant,
			AgreementID:  w.contract.ID(),
			OperationID:  "op-kind-mismatch",
			Kind:         KindProtocol, // Mismatched with KindAgreement payload.
			SignedObject: rawOp,
			Destination:  "authority-1",
			CreatedAt:    w.now,
		}
		if err := o.Enqueue(mismatched); !errors.Is(err, ErrItem) {
			t.Fatalf("expected Outbox.Enqueue ErrItem for kind mismatch, got %v", err)
		}
		if _, err := w.inner.Apply(mismatched); !errors.Is(err, ErrItem) {
			t.Fatalf("expected StoreAuthority.Apply ErrItem for kind mismatch, got %v", err)
		}
		if view, err := w.inner.View(tenant, w.contract.ID()); err != nil || view.Status != nex.StatusOpen {
			t.Fatalf("StoreAuthority mutated store on kind mismatch: view=%+v err=%v", view, err)
		}

		// Mismatched AgreementID / OperationID in Outbox.Enqueue.
		badAg := mismatched
		badAg.Kind = KindAgreement
		badAg.AgreementID = "other-agreement"
		if err := o.Enqueue(badAg); !errors.Is(err, ErrItem) {
			t.Fatalf("expected ErrItem for AgreementID mismatch, got %v", err)
		}
		badOp := mismatched
		badOp.Kind = KindAgreement
		badOp.OperationID = "other-op"
		if err := o.Enqueue(badOp); !errors.Is(err, ErrItem) {
			t.Fatalf("expected ErrItem for OperationID mismatch, got %v", err)
		}

		// ProtocolAuthority must also reject item.Kind != KindProtocol.
		cmd, err := pw.store.Prepare(pw.id, mustPublic(t, pw.owner).ID(), "", pw.spec.Scope, "admit", "proto-kind-mismatch", 1)
		if err != nil {
			t.Fatal(err)
		}
		cmd.GrantID = ""
		cmd.Scope = ""
		rawCmd, err := EncodeProtocol(cmd, nex.Sign(pw.owner, "protocol", cmd))
		if err != nil {
			t.Fatal(err)
		}
		badProto := OutboundItem{
			Version:      Version,
			Tenant:       tenant,
			AgreementID:  pw.id,
			OperationID:  "proto-kind-mismatch",
			Kind:         KindAgreement, // Mismatched with KindProtocol payload.
			SignedObject: rawCmd,
			Destination:  "authority-1",
			CreatedAt:    w.now,
		}
		if err := o.Enqueue(badProto); !errors.Is(err, ErrItem) {
			t.Fatalf("expected Outbox.Enqueue ErrItem for protocol kind mismatch, got %v", err)
		}
		if _, err := pw.inner.Apply(badProto); !errors.Is(err, ErrItem) {
			t.Fatalf("expected ProtocolAuthority.Apply ErrItem for kind mismatch, got %v", err)
		}
	})

	t.Run("DuplicateEnqueueMetadataConflictRejected", func(t *testing.T) {
		w := newStoreWorld(t)
		o := testOutbox(t)

		op, err := w.store.Prepare(w.contract.ID(), "op-dup-meta", "lock", "checked")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
		if err != nil {
			t.Fatal(err)
		}
		valid := OutboundItem{
			Version: Version, Tenant: tenant, AgreementID: w.contract.ID(),
			OperationID: "op-dup-meta", Kind: KindAgreement, SignedObject: raw,
			Destination: "dest-A", CreatedAt: w.now,
		}
		if err := o.Enqueue(valid); err != nil {
			t.Fatal(err)
		}
		// Identical replay is idempotent.
		if err := o.Enqueue(valid); err != nil {
			t.Fatalf("identical duplicate Enqueue failed: %v", err)
		}
		// Different Destination with same SignedObject MUST return ErrConflict.
		diffDest := valid
		diffDest.Destination = "dest-B"
		if err := o.Enqueue(diffDest); !errors.Is(err, ErrConflict) {
			t.Fatalf("expected ErrConflict for duplicate Enqueue with different Destination, got %v", err)
		}
		// Conflicting AgreementID/Kind MUST be rejected.
		conflictingMeta := valid
		conflictingMeta.AgreementID = "completely-different-agreement"
		conflictingMeta.Destination = "completely-different-dest"
		conflictingMeta.Kind = KindProtocol
		if err := o.Enqueue(conflictingMeta); err == nil {
			t.Fatal("expected duplicate Enqueue with conflicting AgreementID/Destination/Kind to be rejected")
		}
	})
}

// Regression test for BUG-26: ReconcileDue must enforce NextTry atomically
// inside the vault lock so concurrent callers cannot bypass retry backoff.
func TestV202OutboxReconcileDueAtomicBackoffUnderConcurrency(t *testing.T) {
	w := newStoreWorld(t)
	o := testOutbox(t)

	var currentTime atomic.Int64
	currentTime.Store(w.now.UnixNano())
	o.SetNow(func() time.Time { return time.Unix(0, currentTime.Load()).UTC() })

	op, err := w.store.Prepare(w.contract.ID(), "op-due-race", "lock", "checked")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
	if err != nil {
		t.Fatal(err)
	}
	item := OutboundItem{
		Version: Version, Tenant: tenant, AgreementID: w.contract.ID(),
		OperationID: "op-due-race", Kind: KindAgreement, SignedObject: raw,
		Destination: "authority-1", CreatedAt: w.now,
		Retry: RetryPolicy{InitialBackoff: time.Hour, MaxBackoff: time.Hour},
	}
	if err := o.Enqueue(item); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	var holdSecond atomic.Bool
	inApply := make(chan struct{})
	releaseApply := make(chan struct{})
	dropAuth := &scriptedAuthority{
		apply: func(OutboundItem) (AuthenticatedResponse, error) {
			n := calls.Add(1)
			if n == 2 && holdSecond.Load() {
				close(inApply)
				<-releaseApply
			}
			return AuthenticatedResponse{Version: Version, Kind: ResultUncertain}, ErrLostResponse
		},
	}

	// First attempt fails -> sets NextTry = baseNow + 1h.
	if _, err := o.Reconcile(tenant, item.OperationID, dropAuth); !errors.Is(err, ErrLostResponse) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}

	// Advance clock past NextTry (+2h) and race 6 concurrent ReconcileDue calls.
	currentTime.Store(w.now.Add(2 * time.Hour).UnixNano())
	holdSecond.Store(true)

	const workers = 6
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = o.ReconcileDue(tenant, item.OperationID, dropAuth)
		}(i)
	}
	<-inApply
	time.Sleep(30 * time.Millisecond)
	close(releaseApply)
	wg.Wait()

	if calls.Load() != 2 {
		t.Fatalf("concurrent ReconcileDue bypassed backoff: total Apply calls=%d (want 2), errs=%v", calls.Load(), errs)
	}
	lostCount, notDueCount := 0, 0
	for _, err := range errs {
		switch {
		case errors.Is(err, ErrLostResponse):
			lostCount++
		case errors.Is(err, ErrNotDue):
			notDueCount++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if lostCount != 1 || notDueCount != workers-1 {
		t.Fatalf("expected 1 ErrLostResponse and %d ErrNotDue, got lost=%d notDue=%d errs=%v", workers-1, lostCount, notDueCount, errs)
	}
}

// Regression test for BUG-27: sameTerminal must compare Phase, WorkOutcome,
// and Definitive so conflicting verified terminals return ErrConflict.
func TestV202OutboxSameTerminalChecksPhaseWorkOutcomeAndDefinitive(t *testing.T) {
	w := newProtocolWorld(t)
	o := testOutbox(t)
	item := w.enqueue(t, o, w.owner, "", "admit", "admit-term", 1, nil)

	respA := AuthenticatedResponse{
		Version:     Version,
		Tenant:      tenant,
		AgreementID: w.id,
		RequestID:   item.OperationID,
		CommandHash: CommandHash(item.SignedObject),
		Kind:        ResultAgreement,
		ReceiptHead: nex.Hash("head-1"),
		Phase:       "complete",
		WorkOutcome: "success",
		Definitive:  false,
	}
	if err := o.RecordVerified(tenant, item.OperationID, respA, w.authPub, SignResponse(w.authority, respA)); err != nil {
		t.Fatal(err)
	}
	// Identical terminal stays idempotent.
	if err := o.RecordVerified(tenant, item.OperationID, respA, w.authPub, SignResponse(w.authority, respA)); err != nil {
		t.Fatalf("identical terminal replay failed: %v", err)
	}

	diffPhase := respA
	diffPhase.Phase = "failed"
	if err := o.RecordVerified(tenant, item.OperationID, diffPhase, w.authPub, SignResponse(w.authority, diffPhase)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for differing Phase, got %v", err)
	}

	diffOutcome := respA
	diffOutcome.WorkOutcome = "defect"
	if err := o.RecordVerified(tenant, item.OperationID, diffOutcome, w.authPub, SignResponse(w.authority, diffOutcome)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for differing WorkOutcome, got %v", err)
	}

	diffDefinitive := respA
	diffDefinitive.Definitive = true
	if err := o.RecordVerified(tenant, item.OperationID, diffDefinitive, w.authPub, SignResponse(w.authority, diffDefinitive)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for differing Definitive, got %v", err)
	}
}

// Regression test for BUG-13: CopyPrivateDir must reject non-empty dst before
// mutating or deleting anything and must reject aliased/nested src/dst paths
// through symlinked parents without touching src files.
func TestV202CopyPrivateDirProtectsPreexistingDstAndAliasedSrc(t *testing.T) {
	t.Run("RejectsNonEmptyDstWithoutMutation", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src")
		dst := filepath.Join(t.TempDir(), "dst")
		if err := os.Mkdir(src, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dst, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "shared.box"), []byte("new-data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "shared.box"), []byte("precious-old-data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "other.box"), []byte("other-data"), 0600); err != nil {
			t.Fatal(err)
		}

		if err := CopyPrivateDir(src, dst); !errors.Is(err, ErrStorageDir) {
			t.Fatalf("expected ErrStorageDir on non-empty dst, got %v", err)
		}
		got, err := os.ReadFile(filepath.Join(dst, "shared.box"))
		if err != nil || string(got) != "precious-old-data" {
			t.Fatalf("pre-existing dst/shared.box modified or deleted: got=%q err=%v", string(got), err)
		}
		gotOther, err := os.ReadFile(filepath.Join(dst, "other.box"))
		if err != nil || string(gotOther) != "other-data" {
			t.Fatalf("pre-existing dst/other.box modified or deleted: got=%q err=%v", string(gotOther), err)
		}
	})

	t.Run("RejectsAliasedSrcViaSymlinkedParent", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		linkParent := filepath.Join(root, "link")
		if err := os.Mkdir(realParent, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(realParent, "vault")
		dstAlias := filepath.Join(linkParent, "vault")
		if err := os.Mkdir(src, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "a.box"), []byte("source-vault-data"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(src, "z-subdir"), 0700); err != nil {
			t.Fatal(err)
		}

		if err := CopyPrivateDir(src, dstAlias); !errors.Is(err, ErrStorageDir) {
			t.Fatalf("expected ErrStorageDir on aliased src/dst, got %v", err)
		}
		got, err := os.ReadFile(filepath.Join(src, "a.box"))
		if err != nil || string(got) != "source-vault-data" {
			t.Fatalf("source file src/a.box damaged or deleted: got=%q err=%v", string(got), err)
		}
	})

	t.Run("RejectsNestedDstInsideSrc", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "src")
		if err := os.Mkdir(src, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, "a.box"), []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
		nested := filepath.Join(src, "nested")
		if err := CopyPrivateDir(src, nested); !errors.Is(err, ErrStorageDir) {
			t.Fatalf("expected ErrStorageDir for nested dst, got %v", err)
		}
		if _, err := os.Stat(nested); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("nested directory should not have been created: %v", err)
		}
	})
}
