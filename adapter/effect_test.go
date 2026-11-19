package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

const crashEffect = "effect-crash"

func crashIntent() EffectIntent {
	return EffectIntent{Tenant: tenant, EffectID: crashEffect, AgreementID: "agreement-crash", Evidence: "tool"}
}

func crashFence() Fence {
	return Fence{Version: Version, Generation: 1, Owner: "a", Token: bytes.Repeat([]byte{9}, 32)}
}

func TestEffectDurablePhasesAndNoDuplicate(t *testing.T) {
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "effects")
	effects, err := OpenEffects(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "effect-phase", AgreementID: "agreement-phase", Evidence: "tool"}
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	other := intent
	other.Evidence = "different"
	if err = effects.Intend(other); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	destDir := filepath.Join(t.TempDir(), "dest")
	dest := newDurableDest(destDir, false)
	effects.vault.onWrite = func(stage string) error {
		if stage == "before-sync" {
			return errors.New("sync failed")
		}
		return nil
	}
	if err = effects.Apply(tenant, intent.EffectID, dest, crashFence()); err == nil {
		t.Fatal("dispatch write failure returned success")
	}
	if dest.total() != 0 {
		t.Fatal(dest.total())
	}
	rec, err := effects.Get(tenant, intent.EffectID)
	if err != nil || rec.Phase != EffectPhaseIntended || rec.Attempts != 0 {
		t.Fatal(rec, err)
	}
	effects.vault.onWrite = func(stage string) error {
		if stage == "after-rename" {
			return errors.New("directory sync uncertain")
		}
		return nil
	}
	if err = effects.Apply(tenant, intent.EffectID, dest, crashFence()); err == nil {
		t.Fatal("uncertain dispatch returned success")
	}
	if dest.total() != 0 {
		t.Fatal("executed without a durable dispatch record", dest.total())
	}
	effects.vault.onWrite = nil
	reopened, err := OpenEffects(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	rec, err = reopened.Get(tenant, intent.EffectID)
	if err != nil || rec.Phase != EffectPhaseDispatching {
		t.Fatal(rec, err)
	}
	if err = reopened.Apply(tenant, intent.EffectID, dest, crashFence()); !errors.Is(err, ErrEffectReexecute) {
		t.Fatal(err)
	}
	if dest.total() != 0 || recPhase(t, reopened, intent) != EffectPhaseUnknown {
		t.Fatal(dest.total(), recPhase(t, reopened, intent))
	}
}

func TestEffectConfirmWriteFailureReopensWithoutDuplicate(t *testing.T) {
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "effects")
	destDir := filepath.Join(t.TempDir(), "dest")
	effects, err := OpenEffects(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "effect-confirm", AgreementID: "agreement-confirm", Evidence: "tool"}
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	dest := newDurableDest(destDir, false)
	var writes int
	effects.vault.onWrite = func(stage string) error {
		if stage == "before-sync" {
			writes++
			if writes == 2 {
				return errors.New("confirmation sync failed")
			}
		}
		return nil
	}
	if err = effects.Apply(tenant, intent.EffectID, dest, crashFence()); err == nil {
		t.Fatal("confirmation failure reported success")
	}
	if dest.total() != 1 {
		t.Fatal(dest.total())
	}
	effects.vault.onWrite = nil
	reopened, err := OpenEffects(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	again := newDurableDest(destDir, false)
	if again.total() != 1 {
		t.Fatal(again.total())
	}
	if err = reopened.Apply(tenant, intent.EffectID, again, crashFence()); err != nil {
		t.Fatal(err)
	}
	if again.total() != 1 || recPhase(t, reopened, intent) != EffectPhaseConfirmed {
		t.Fatal(again.total(), recPhase(t, reopened, intent))
	}
	rec, err := reopened.Get(tenant, intent.EffectID)
	if err != nil || !rec.Confirmed || rec.ConfirmEvidence == "" {
		t.Fatal(rec, err)
	}
}

func TestEffectCrashChild(t *testing.T) {
	mode := os.Getenv("NEX_EFFECT_CHILD")
	if mode == "" {
		t.Skip()
	}
	key, err := hex.DecodeString(os.Getenv("NEX_EFFECT_KEY"))
	if err != nil || len(key) != 32 {
		t.Fatal(err)
	}
	effects, err := OpenEffects(os.Getenv("NEX_EFFECT_VAULT"), key)
	if err != nil {
		t.Fatal(err)
	}
	intent := crashIntent()
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	dest := newDurableDest(os.Getenv("NEX_EFFECT_DEST"), false)
	switch mode {
	case "before-execute":
		effects.beforeExecute = func() error {
			os.Exit(99)
			return nil
		}
	case "after-execute":
		var writes int
		effects.vault.onWrite = func(stage string) error {
			if stage == "before-sync" {
				writes++
				if writes == 2 {
					os.Exit(99)
					return nil
				}
			}
			return nil
		}
	default:
		t.Fatal(mode)
	}
	if err = effects.Apply(tenant, intent.EffectID, dest, crashFence()); err != nil {
		t.Fatal(err)
	}
	t.Fatal("child reached the end of Apply")
}

func TestEffectSubprocessCrashDoesNotDuplicate(t *testing.T) {
	key := testKey(t)
	vaultDir := filepath.Join(t.TempDir(), "effects")
	destDir := filepath.Join(t.TempDir(), "dest")
	if err := os.MkdirAll(destDir, 0700); err != nil {
		t.Fatal(err)
	}
	runEffectChild(t, "before-execute", vaultDir, destDir, key)
	effects, err := OpenEffects(vaultDir, key)
	if err != nil {
		t.Fatal(err)
	}
	dest := newDurableDest(destDir, false)
	if dest.total() != 0 {
		t.Fatal(dest.total())
	}
	rec, err := effects.Get(tenant, crashEffect)
	if err != nil || rec.Phase != EffectPhaseDispatching || rec.Attempts != 1 {
		t.Fatal(rec, err)
	}
	if err = effects.Apply(tenant, crashEffect, dest, crashFence()); !errors.Is(err, ErrEffectReexecute) {
		t.Fatal(err)
	}
	if dest.total() != 0 || recPhase(t, effects, crashIntent()) != EffectPhaseUnknown {
		t.Fatal(dest.total(), recPhase(t, effects, crashIntent()))
	}

	vaultDir = filepath.Join(t.TempDir(), "effects-2")
	destDir = filepath.Join(t.TempDir(), "dest-2")
	if err = os.MkdirAll(destDir, 0700); err != nil {
		t.Fatal(err)
	}
	runEffectChild(t, "after-execute", vaultDir, destDir, key)
	effects, err = OpenEffects(vaultDir, key)
	if err != nil {
		t.Fatal(err)
	}
	dest = newDurableDest(destDir, false)
	if dest.total() != 1 {
		t.Fatal(dest.total())
	}
	if err = effects.Apply(tenant, crashEffect, dest, crashFence()); err != nil {
		t.Fatal(err)
	}
	if dest.total() != 1 || recPhase(t, effects, crashIntent()) != EffectPhaseConfirmed {
		t.Fatal(dest.total(), recPhase(t, effects, crashIntent()))
	}
	if err = effects.Apply(tenant, crashEffect, dest, crashFence()); err != nil || dest.total() != 1 {
		t.Fatal(err, dest.total())
	}
}

func TestEffectIdempotentReplayQueryAndRejection(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "effects")
	effects, err := OpenEffects(dir, testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "effect-replay", AgreementID: "agreement-replay", Evidence: "tool"}
	if err = effects.Intend(intent); err != nil {
		t.Fatal(err)
	}
	dest := &scriptDest{space: "script", idem: true}
	dest.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
		dest.execs++
		return OutcomeConfirmed, nil
	}
	effects.beforeExecute = func() error { return errors.New("crash before execute") }
	if err = effects.Apply(tenant, intent.EffectID, dest, crashFence()); err == nil || dest.execs != 0 {
		t.Fatal(err, dest.execs)
	}
	effects.beforeExecute = nil
	if err = effects.Apply(tenant, intent.EffectID, dest, crashFence()); err != nil || dest.execs != 1 {
		t.Fatal(err, dest.execs)
	}
	if recPhase(t, effects, intent) != EffectPhaseConfirmed {
		t.Fatal(recPhase(t, effects, intent))
	}

	unknown := EffectIntent{Tenant: tenant, EffectID: "effect-unknown-query", AgreementID: "agreement-replay", Evidence: "tool"}
	if err = effects.Intend(unknown); err != nil {
		t.Fatal(err)
	}
	blind := &scriptDest{space: "blind"}
	blind.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
		blind.execs++
		return OutcomeConfirmed, nil
	}
	effects.beforeExecute = func() error { return errors.New("crash before execute") }
	if err = effects.Apply(tenant, unknown.EffectID, blind, crashFence()); err == nil {
		t.Fatal(err)
	}
	effects.beforeExecute = nil
	blind.query = func(EffectRef, Fence) (DestinationOutcome, error) {
		return OutcomeUnknown, errors.New("query unavailable")
	}
	if err = effects.Apply(tenant, unknown.EffectID, blind, crashFence()); err == nil || blind.execs != 0 {
		t.Fatal(err, blind.execs)
	}
	if recPhase(t, effects, unknown) != EffectPhaseUnknown {
		t.Fatal(recPhase(t, effects, unknown))
	}

	rejected := EffectIntent{Tenant: tenant, EffectID: "effect-reject", AgreementID: "agreement-replay", Evidence: "tool"}
	if err = effects.Intend(rejected); err != nil {
		t.Fatal(err)
	}
	bad := &scriptDest{space: "reject"}
	bad.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
		bad.execs++
		return OutcomeUnknown, ErrEffectRejected
	}
	bad.query = func(EffectRef, Fence) (DestinationOutcome, error) { return OutcomeUnknown, nil }
	if err = effects.Apply(tenant, rejected.EffectID, bad, crashFence()); !errors.Is(err, ErrEffectRejected) || bad.execs != 1 {
		t.Fatal(err, bad.execs)
	}
	if err = effects.Apply(tenant, rejected.EffectID, bad, crashFence()); !errors.Is(err, ErrEffectReexecute) || bad.execs != 1 {
		t.Fatal(err, bad.execs)
	}

	proven := EffectIntent{Tenant: tenant, EffectID: "effect-proven", AgreementID: "agreement-replay", Evidence: "tool"}
	if err = effects.Intend(proven); err != nil {
		t.Fatal(err)
	}
	clean := &scriptDest{space: "clean"}
	var calls int
	clean.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
		calls++
		if calls == 1 {
			return OutcomeNotDispatched, ErrEffectRejected
		}
		return OutcomeConfirmed, nil
	}
	if err = effects.Apply(tenant, proven.EffectID, clean, crashFence()); !errors.Is(err, ErrEffectRejected) || calls != 1 {
		t.Fatal(err, calls)
	}
	if recPhase(t, effects, proven) != EffectPhaseIntended {
		t.Fatal(recPhase(t, effects, proven))
	}
	if err = effects.Apply(tenant, proven.EffectID, clean, crashFence()); err != nil || calls != 2 {
		t.Fatal(err, calls)
	}

	fenced := EffectIntent{Tenant: tenant, EffectID: "effect-fenced", AgreementID: "agreement-replay", Evidence: "tool"}
	if err = effects.Intend(fenced); err != nil {
		t.Fatal(err)
	}
	fate := &scriptDest{space: "fate"}
	fate.execute = func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error) {
		fate.execs++
		return OutcomeNotDispatched, ErrFenced
	}
	fate.query = func(EffectRef, Fence) (DestinationOutcome, error) { return OutcomeUnknown, nil }
	if err = effects.Apply(tenant, fenced.EffectID, fate, crashFence()); !errors.Is(err, ErrFenced) || fate.execs != 1 {
		t.Fatal(err, fate.execs)
	}
	if recPhase(t, effects, fenced) != EffectPhaseUnknown {
		t.Fatal("ErrFenced was treated as not dispatched", recPhase(t, effects, fenced))
	}
	if err = effects.Apply(tenant, fenced.EffectID, fate, crashFence()); !errors.Is(err, ErrEffectReexecute) || fate.execs != 1 {
		t.Fatal(err, fate.execs)
	}
}

func TestEffectLegacyMigrationAndTenantIdentity(t *testing.T) {
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "effects")
	effects, err := OpenEffects(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	fresh := EffectIntent{Tenant: tenant, EffectID: "legacy-zero", AgreementID: "agreement-legacy", Evidence: "tool"}
	if err = effects.vault.write(recordID(fresh.Tenant, fresh.EffectID), EffectRecord{Intent: fresh, Status: EffectPending, Attempts: 0}); err != nil {
		t.Fatal(err)
	}
	dest := NewMemoryDestination()
	dest.Fence = crashFence()
	dest.Idempotent = true
	if err = effects.Apply(tenant, fresh.EffectID, dest, dest.Fence); !errors.Is(err, ErrEffectReexecute) || dest.Executions(fresh.EffectID) != 0 {
		t.Fatal(err, dest.Executions(fresh.EffectID))
	}
	rec, err := effects.Get(tenant, fresh.EffectID)
	if err != nil || rec.Phase != EffectPhaseUnknown || !rec.Legacy || rec.Version != EffectRecordVersion {
		t.Fatal(rec, err)
	}
	if err = effects.Apply(tenant, fresh.EffectID, dest, dest.Fence); !errors.Is(err, ErrEffectReexecute) || dest.Executions(fresh.EffectID) != 0 {
		t.Fatal("legacy pending reexecuted", err, dest.Executions(fresh.EffectID))
	}

	bad := EffectIntent{Tenant: tenant, EffectID: "legacy-bad", AgreementID: "agreement-legacy", Evidence: "tool"}
	if err = effects.vault.write(recordID(bad.Tenant, bad.EffectID), EffectRecord{Intent: bad, Status: EffectConfirmed, Confirmed: false, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if err = effects.Apply(tenant, bad.EffectID, dest, dest.Fence); !errors.Is(err, ErrCorrupt) || dest.Executions(bad.EffectID) != 0 {
		t.Fatal(err, dest.Executions(bad.EffectID))
	}
	rec, err = effects.Get(tenant, bad.EffectID)
	if err != nil || rec.Phase != EffectPhaseQuarantined || rec.Confirmed {
		t.Fatal(rec, err)
	}
	flipped := EffectIntent{Tenant: tenant, EffectID: "legacy-flip", AgreementID: "agreement-legacy", Evidence: "tool"}
	if err = effects.vault.write(recordID(flipped.Tenant, flipped.EffectID), EffectRecord{Intent: flipped, Status: EffectPending, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	if err = effects.Apply(tenant, flipped.EffectID, dest, dest.Fence); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}

	ok := EffectIntent{Tenant: tenant, EffectID: "legacy-ok", AgreementID: "agreement-legacy", Evidence: "tool"}
	if err = effects.vault.write(recordID(ok.Tenant, ok.EffectID), EffectRecord{Intent: ok, Status: EffectConfirmed, Confirmed: true, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if err = effects.Apply(tenant, ok.EffectID, dest, dest.Fence); err != nil || dest.Executions(ok.EffectID) != 0 {
		t.Fatal(err, dest.Executions(ok.EffectID))
	}
	rec, err = effects.Get(tenant, ok.EffectID)
	if err != nil || rec.Phase != EffectPhaseConfirmed || !rec.Confirmed || rec.ConfirmEvidence == "" {
		t.Fatal(rec, err)
	}

	future := EffectIntent{Tenant: tenant, EffectID: "future", AgreementID: "agreement-legacy", Evidence: "tool"}
	next := newIntentRecord(future)
	next.Version = EffectRecordVersion + 1
	if err = effects.vault.write(recordID(future.Tenant, future.EffectID), next); err != nil {
		t.Fatal(err)
	}
	if _, err = effects.Get(tenant, future.EffectID); !errors.Is(err, ErrVersion) {
		t.Fatal(err)
	}
	if err = effects.Apply(tenant, future.EffectID, dest, dest.Fence); !errors.Is(err, ErrVersion) || dest.Executions(future.EffectID) != 0 {
		t.Fatal(err)
	}

	shared := NewMemoryDestination()
	shared.Fence = crashFence()
	left := EffectIntent{Tenant: tenant, EffectID: "same", AgreementID: "agreement-left", Evidence: "left"}
	right := EffectIntent{Tenant: "other", EffectID: "same", AgreementID: "agreement-right", Evidence: "right"}
	if err = effects.Intend(left); err != nil {
		t.Fatal(err)
	}
	if err = effects.Intend(right); err != nil {
		t.Fatal(err)
	}
	if err = effects.Apply(left.Tenant, left.EffectID, shared, shared.Fence); err != nil {
		t.Fatal(err)
	}
	if err = effects.Apply(right.Tenant, right.EffectID, shared, shared.Fence); err != nil {
		t.Fatal(err)
	}
	leftRef := EffectRef{Tenant: left.Tenant, EffectID: left.EffectID, AgreementID: left.AgreementID, Digest: effectDigest(left), Namespace: shared.Namespace()}
	rightRef := EffectRef{Tenant: right.Tenant, EffectID: right.EffectID, AgreementID: right.AgreementID, Digest: effectDigest(right), Namespace: shared.Namespace()}
	if shared.Count(leftRef) != 1 || shared.Count(rightRef) != 1 || shared.Executions("same") != 2 {
		t.Fatal(shared.Count(leftRef), shared.Count(rightRef), shared.Executions("same"))
	}
	clash := leftRef
	clash.Digest = effectDigest(right)
	if _, err = shared.Execute(left, clash, shared.Fence); !errors.Is(err, ErrConflict) || shared.Count(leftRef) != 1 {
		t.Fatal(err, shared.Count(leftRef))
	}
}

func TestEffectConcurrentHandles(t *testing.T) {
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "effects")
	first, err := OpenEffects(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenEffects(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	intent := EffectIntent{Tenant: tenant, EffectID: "effect-race", AgreementID: "agreement-race", Evidence: "tool"}
	if err = first.Intend(intent); err != nil {
		t.Fatal(err)
	}
	dest := NewMemoryDestination()
	dest.Fence = crashFence()
	hold := make(chan struct{})
	entered := make(chan struct{})
	dest.entered = entered
	dest.hold = hold
	done1 := make(chan error, 1)
	go func() { done1 <- first.Apply(tenant, intent.EffectID, dest, dest.Fence) }()
	<-entered
	done2 := make(chan error, 1)
	go func() { done2 <- second.Apply(tenant, intent.EffectID, dest, dest.Fence) }()
	select {
	case err = <-done2:
		t.Fatal("second handle ran beside the first", err)
	default:
	}
	close(hold)
	if err = <-done1; err != nil {
		t.Fatal(err)
	}
	if err = <-done2; err != nil {
		t.Fatal(err)
	}
	if dest.Executions(intent.EffectID) != 1 {
		t.Fatal(dest.Executions(intent.EffectID))
	}
}

func runEffectChild(t *testing.T, mode, vaultDir, destDir string, key []byte) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestEffectCrashChild$", "-test.count=1", "-test.timeout=60s")
	cmd.Env = append(os.Environ(),
		"NEX_EFFECT_CHILD="+mode,
		"NEX_EFFECT_VAULT="+vaultDir,
		"NEX_EFFECT_DEST="+destDir,
		"NEX_EFFECT_KEY="+hex.EncodeToString(key),
	)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 99 {
		t.Fatalf("child %s: %v\n%s", mode, err, out)
	}
}

func recPhase(t *testing.T, effects *EffectAdapter, intent EffectIntent) string {
	t.Helper()
	rec, err := effects.Get(intent.Tenant, intent.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	return rec.Phase
}

type scriptDest struct {
	space   string
	idem    bool
	execs   int
	execute func(EffectIntent, EffectRef, Fence) (DestinationOutcome, error)
	query   func(EffectRef, Fence) (DestinationOutcome, error)
}

func (d *scriptDest) Namespace() string {
	if d.space != "" {
		return d.space
	}
	return "script"
}
func (d *scriptDest) DurableIdempotent() bool { return d.idem }
func (d *scriptDest) Execute(intent EffectIntent, ref EffectRef, fence Fence) (DestinationOutcome, error) {
	if d.execute == nil {
		d.execs++
		return OutcomeConfirmed, nil
	}
	return d.execute(intent, ref, fence)
}
func (d *scriptDest) Query(ref EffectRef, fence Fence) (DestinationOutcome, error) {
	if d.query == nil {
		return OutcomeUnknown, nil
	}
	return d.query(ref, fence)
}

type durableDest struct {
	dir        string
	idempotent bool
	fence      Fence
	mu         sync.Mutex
}

type durableState struct {
	Count     int
	Confirmed bool
	Ref       EffectRef
}

func newDurableDest(dir string, idempotent bool) *durableDest {
	if err := os.MkdirAll(dir, 0700); err != nil {
		panic(err)
	}
	return &durableDest{dir: dir, idempotent: idempotent, fence: crashFence()}
}

func (d *durableDest) Namespace() string       { return "durable" }
func (d *durableDest) DurableIdempotent() bool { return d.idempotent }
func (d *durableDest) path(ref EffectRef) string {
	sum := sha256.Sum256([]byte(ref.slot()))
	return filepath.Join(d.dir, hex.EncodeToString(sum[:])+".fx")
}

func (d *durableDest) Execute(intent EffectIntent, ref EffectRef, fence Fence) (DestinationOutcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if fence.Generation != d.fence.Generation || !bytes.Equal(fence.Token, d.fence.Token) {
		return OutcomeNotDispatched, nil
	}
	cur, ok, err := d.read(ref)
	if err != nil {
		return OutcomeUnknown, err
	}
	if ok && !sameEffect(cur.Ref, ref) {
		return OutcomeUnknown, ErrConflict
	}
	if d.idempotent && ok && cur.Confirmed {
		return OutcomeConfirmed, nil
	}
	if !d.idempotent && ok && cur.Count > 0 {
		return OutcomeUnknown, ErrEffectReexecute
	}
	cur.Count++
	cur.Confirmed = true
	cur.Ref = ref
	_ = intent
	if err = d.write(ref, cur); err != nil {
		return OutcomeUnknown, err
	}
	return OutcomeConfirmed, nil
}

func (d *durableDest) Query(ref EffectRef, fence Fence) (DestinationOutcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if fence.Generation != d.fence.Generation || !bytes.Equal(fence.Token, d.fence.Token) {
		return OutcomeUnknown, ErrFenced
	}
	cur, ok, err := d.read(ref)
	if err != nil {
		return OutcomeUnknown, err
	}
	if !ok {
		return OutcomeUnknown, nil
	}
	if !sameEffect(cur.Ref, ref) {
		return OutcomeUnknown, ErrConflict
	}
	if cur.Confirmed {
		return OutcomeConfirmed, nil
	}
	return OutcomeUnknown, nil
}

func (d *durableDest) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !bytes.HasSuffix([]byte(e.Name()), []byte(".fx")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(d.dir, e.Name()))
		if err != nil {
			continue
		}
		var st durableState
		if json.Unmarshal(raw, &st) == nil {
			n += st.Count
		}
	}
	return n
}

func (d *durableDest) read(ref EffectRef) (durableState, bool, error) {
	raw, err := os.ReadFile(d.path(ref))
	if errors.Is(err, os.ErrNotExist) {
		return durableState{}, false, nil
	}
	if err != nil {
		return durableState{}, false, err
	}
	var st durableState
	if json.Unmarshal(raw, &st) != nil {
		return durableState{}, false, ErrCorrupt
	}
	return st, true, nil
}

func (d *durableDest) write(ref EffectRef, st durableState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d.dir, ".pending-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err = tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err = tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err = os.Chmod(name, 0600); err != nil {
		os.Remove(name)
		return err
	}
	if err = os.Rename(name, d.path(ref)); err != nil {
		os.Remove(name)
		return err
	}
	return syncDir(d.dir)
}
