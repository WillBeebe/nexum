package adapter

import (
	"errors"
	"path/filepath"
	"testing"
)

// Regression test for BUG-12: OutcomeNotDispatched on a retry of a previously
// uncertain effect must preserve EffectPhaseUnknown / Reconcile=true so later
// attempts always reconcile via dest.Query and never duplicate execution.
func TestV202EffectNotDispatchedOnRetryPreservesUnknownAndReconciles(t *testing.T) {
	runCase := func(t *testing.T, idemOnAttempt3 bool) {
		dir := filepath.Join(t.TempDir(), "effects-retry-reset")
		effects, err := OpenEffects(dir, testKey(t))
		if err != nil {
			t.Fatal(err)
		}
		intent := EffectIntent{
			Tenant:      tenant,
			EffectID:    "eff-preserve-unknown",
			AgreementID: "agreement-1",
			Evidence:    "transfer-100",
		}
		if err := effects.Intend(intent); err != nil {
			t.Fatal(err)
		}

		var execCalls, queryCalls int
		attempt := 0
		dest := &scriptDest{space: "bank", idem: true}
		dest.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
			attempt++
			switch attempt {
			case 1:
				// Attempt 1 executes on destination, then transport drops the response.
				execCalls++
				return OutcomeUnknown, ErrLostResponse
			case 2:
				// Attempt 2 is rejected pre-dispatch; Attempt 1's outcome is still unknown.
				return OutcomeNotDispatched, ErrEffectRejected
			default:
				// Attempt 3 must never reach Execute because Query confirms Attempt 1.
				execCalls++
				return OutcomeConfirmed, nil
			}
		}
		dest.query = func(EffectRef, Fence) (DestinationOutcome, error) {
			queryCalls++
			if queryCalls == 1 {
				return OutcomeUnknown, nil
			}
			return OutcomeConfirmed, nil
		}

		// Attempt 1 -> Phase=unknown, Reconcile=true.
		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); !errors.Is(err, ErrEffectUnknown) {
			t.Fatalf("attempt 1: expected ErrEffectUnknown, got %v", err)
		}
		rec1, err := effects.Get(tenant, intent.EffectID)
		if err != nil || rec1.Phase != EffectPhaseUnknown || !rec1.Reconcile {
			t.Fatalf("after attempt 1: expected unknown/reconcile=true, got %+v %v", rec1, err)
		}

		// Attempt 2 -> Query returns unknown, Execute returns (OutcomeNotDispatched, ErrEffectRejected).
		// Must stay Phase=unknown and Reconcile=true!
		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); !errors.Is(err, ErrEffectRejected) {
			t.Fatalf("attempt 2: expected ErrEffectRejected, got %v", err)
		}
		rec2, err := effects.Get(tenant, intent.EffectID)
		if err != nil {
			t.Fatal(err)
		}
		if rec2.Phase != EffectPhaseUnknown || !rec2.Reconcile || rec2.Attempts != 2 {
			t.Fatalf("after attempt 2: expected Phase=unknown Reconcile=true Attempts=2, got %+v", rec2)
		}

		// Attempt 3 -> must reconcile via Query (OutcomeConfirmed) without re-executing.
		dest.idem = idemOnAttempt3
		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); err != nil {
			t.Fatalf("attempt 3 unexpected err: %v", err)
		}
		rec3, err := effects.Get(tenant, intent.EffectID)
		if err != nil || rec3.Phase != EffectPhaseConfirmed || !rec3.Confirmed {
			t.Fatalf("after attempt 3: expected confirmed, got %+v %v", rec3, err)
		}
		if queryCalls != 2 || execCalls != 1 {
			t.Fatalf("idemOnAttempt3=%v: expected queryCalls=2 execCalls=1, got queryCalls=%d execCalls=%d",
				idemOnAttempt3, queryCalls, execCalls)
		}
	}

	t.Run("QueriesAndConfirmsWhenStillIdempotent", func(t *testing.T) { runCase(t, true) })
	t.Run("QueriesAndConfirmsWhenIdempotencyUnavailable", func(t *testing.T) { runCase(t, false) })

	t.Run("RefusesReexecuteWhenNonIdempotentAndQueryStillUnknown", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "effects-retry-refuse")
		effects, err := OpenEffects(dir, testKey(t))
		if err != nil {
			t.Fatal(err)
		}
		intent := EffectIntent{Tenant: tenant, EffectID: "eff-refuse", AgreementID: "agreement-2", Evidence: "transfer-200"}
		if err := effects.Intend(intent); err != nil {
			t.Fatal(err)
		}
		execCalls := 0
		attempt := 0
		dest := &scriptDest{space: "bank", idem: true}
		dest.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
			attempt++
			if attempt == 1 {
				execCalls++
				return OutcomeUnknown, ErrLostResponse
			}
			return OutcomeNotDispatched, ErrEffectRejected
		}
		dest.query = func(EffectRef, Fence) (DestinationOutcome, error) {
			return OutcomeUnknown, nil
		}

		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); !errors.Is(err, ErrEffectUnknown) {
			t.Fatal(err)
		}
		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); !errors.Is(err, ErrEffectRejected) {
			t.Fatal(err)
		}
		dest.idem = false
		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); !errors.Is(err, ErrEffectReexecute) {
			t.Fatalf("expected ErrEffectReexecute, got %v", err)
		}
		if execCalls != 1 {
			t.Fatalf("expected 1 execution, got %d", execCalls)
		}
	})

	t.Run("FirstAttemptNotDispatchedStillReturnsToIntended", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "effects-first-not-dispatched")
		effects, err := OpenEffects(dir, testKey(t))
		if err != nil {
			t.Fatal(err)
		}
		intent := EffectIntent{Tenant: tenant, EffectID: "eff-fresh", AgreementID: "agreement-3", Evidence: "transfer-300"}
		if err := effects.Intend(intent); err != nil {
			t.Fatal(err)
		}
		calls := 0
		dest := &scriptDest{space: "bank", idem: false}
		dest.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
			calls++
			if calls == 1 {
				return OutcomeNotDispatched, ErrEffectRejected
			}
			return OutcomeConfirmed, nil
		}
		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); !errors.Is(err, ErrEffectRejected) {
			t.Fatalf("attempt 1: expected ErrEffectRejected, got %v", err)
		}
		rec, err := effects.Get(tenant, intent.EffectID)
		if err != nil || rec.Phase != EffectPhaseIntended || rec.Reconcile {
			t.Fatalf("fresh OutcomeNotDispatched should return to intended: %+v %v", rec, err)
		}
		if err := effects.Apply(tenant, intent.EffectID, dest, crashFence()); err != nil {
			t.Fatalf("attempt 2: expected success, got %v", err)
		}
	})
}
