package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

const (
	// Legacy effect statuses. Version 0 records use these strings.
	// Attempts is audit metadata and never selects a phase.
	EffectPending   = "pending"
	EffectConfirmed = "confirmed"
	EffectUnknown   = "effect_unknown"
)

const (
	EffectPhaseIntended    = "intended"
	EffectPhaseDispatching = "dispatching"
	EffectPhaseUnknown     = "unknown"
	EffectPhaseConfirmed   = "confirmed"
	EffectPhaseQuarantined = "quarantined"
)

// EffectRecordVersion is the effect-vault format written by this package.
// Version 0 is the legacy pending / confirmed / effect_unknown shape and is
// only accepted through migration. A version 0 writer must not share a vault
// with a version 1 writer: it can treat a dispatching record as fresh work.
// Higher versions fail closed and are not rewritten.
const EffectRecordVersion = 1

type DestinationOutcome string

const (
	OutcomeConfirmed     DestinationOutcome = "confirmed"
	OutcomeNotDispatched DestinationOutcome = "not_dispatched"
	OutcomeUnknown       DestinationOutcome = "unknown"
)

// ErrEffectRejected is a typed destination refusal. It does not by itself
// prove the effect never ran. Pair it with OutcomeNotDispatched only when
// the destination contract guarantees that.
var ErrEffectRejected = errors.New("adapter: effect rejected")

type EffectIntent struct {
	Tenant      string
	EffectID    string
	AgreementID string
	Evidence    string
}

// EffectRef is the tenant-scoped identity presented to a destination.
// The digest covers the immutable intent. Namespace is the destination's,
// not a second effect id. The same EffectID in two tenants must not collide.
type EffectRef struct {
	Tenant      string
	EffectID    string
	AgreementID string
	Digest      string
	Namespace   string
}

func (r EffectRef) slot() string {
	return fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(r.Tenant), r.Tenant, len(r.Namespace), r.Namespace, len(r.EffectID), r.EffectID)
}

type EffectRecord struct {
	Version   int
	Intent    EffectIntent
	Digest    string
	Namespace string
	Phase     string
	// Status mirrors Phase on version 1 records. Version 0 load still reads
	// the legacy status strings above; it is not a second source of truth.
	Status   string
	Attempts int
	// Confirmed is a compatibility projection: true if and only if Phase is
	// confirmed. A contradictory legacy boolean is quarantined, not executed.
	Confirmed bool
	// ConfirmEvidence is required when Phase is confirmed. Phase alone is
	// not confirmation.
	ConfirmEvidence string
	// Legacy is set when the record was migrated from a pre-phase vault.
	// Those rows are not fresh: Attempts==0 does not prove no dispatch.
	Legacy bool
	// Reconcile is operator-visible. Dispatching, unknown, and quarantined
	// records must be reconciled; they are not automatically fresh work.
	Reconcile bool
}

type EffectDestination interface {
	Namespace() string
	// DurableIdempotent reports whether the destination durably dedupes the
	// full stable intent key (tenant, namespace, effect, agreement, digest).
	DurableIdempotent() bool
	Execute(intent EffectIntent, ref EffectRef, fence Fence) (DestinationOutcome, error)
	Query(ref EffectRef, fence Fence) (DestinationOutcome, error)
}

type EffectAdapter struct {
	vault *vault
	// beforeExecute, if set, runs after the dispatching record is durable and
	// before Execute. Tests use it as a crash seam. Production leaves it nil.
	beforeExecute func() error
}

func OpenEffects(dir string, key []byte) (*EffectAdapter, error) {
	v, err := openVault(dir, key)
	if err != nil {
		return nil, err
	}
	return &EffectAdapter{vault: v}, nil
}

const effectLockFile = "effect.lock"

func effectFilename(id string) string { return id + ".effect" }
func effectAAD(id string) string      { return vaultHeader + "/effect/" + id }

func (e *EffectAdapter) withLock(fn func() error) error {
	if e == nil || e.vault == nil {
		return ErrItem
	}
	return e.vault.withNamedLock(effectLockFile, fn)
}

func (e *EffectAdapter) writeEffect(id string, rec EffectRecord) error {
	return e.vault.writeNamed(effectFilename(id), effectAAD(id), rec)
}

// Intend records an effect intent in this vault. It does not apply an agreement.
// Store.Apply and Intend are separate calls and are not atomic. A host that
// needs both to commit together must use its own durable transaction, or a
// durable idempotent dispatcher that rebuilds intents only from committed
// operations. There is no lost-intent window inside this method; there is
// one between it and any separate Store.Apply the caller also makes.
func (e *EffectAdapter) Intend(intent EffectIntent) error {
	if err := validateEffectIntent(intent); err != nil {
		return err
	}
	id := recordID(intent.Tenant, intent.EffectID)
	return e.withLock(func() error {
		existing, err := e.readEffect(id, intent.Tenant, intent.EffectID)
		if errors.Is(err, ErrNotFound) {
			return e.writeEffect(id, newIntentRecord(intent))
		}
		if err != nil {
			return err
		}
		if existing.Phase == EffectPhaseQuarantined {
			return ErrCorrupt
		}
		if existing.Intent != intent || existing.Digest != effectDigest(intent) {
			return ErrConflict
		}
		return nil
	})
}

func (e *EffectAdapter) Get(tenant, effectID string) (EffectRecord, error) {
	var rec EffectRecord
	if err := validateID(tenant); err != nil {
		return rec, err
	}
	if err := validateID(effectID); err != nil {
		return rec, err
	}
	err := e.withLock(func() error {
		loaded, err := e.readEffect(recordID(tenant, effectID), tenant, effectID)
		if err != nil {
			return err
		}
		rec = loaded
		return nil
	})
	return rec, err
}

// Apply delivers one intended effect or reconciles an uncertain one.
// Store.Apply and Apply are not atomic; see Intend.
//
// The vault lock is held across the durable dispatching write and Execute so
// two handles cannot both dispatch. Lock order: this vault lock, then
// Coordinator.mu if the destination's guard takes it. Callbacks must not call
// back into EffectAdapter or Coordinator.
//
// A storage error after Execute is returned as a storage failure. Execute
// returning confirmed is not success until the confirmation record is durable.
// ErrFenced is an unknown outcome, not proof the destination did not run.
// Query "not found" is OutcomeUnknown unless the destination itself returns
// OutcomeNotDispatched under its contract.
func (e *EffectAdapter) Apply(tenant, effectID string, dest EffectDestination, fence Fence) error {
	if dest == nil || dest.Namespace() == "" {
		return ErrItem
	}
	if err := validateID(tenant); err != nil {
		return err
	}
	if err := validateID(effectID); err != nil {
		return err
	}
	id := recordID(tenant, effectID)
	return e.withLock(func() error {
		rec, err := e.readEffect(id, tenant, effectID)
		if err != nil {
			return err
		}
		if rec.Phase == EffectPhaseQuarantined {
			return ErrCorrupt
		}
		if rec.Phase == EffectPhaseConfirmed {
			return nil
		}
		if rec.Namespace != "" && rec.Namespace != dest.Namespace() {
			return ErrConflict
		}
		ref := EffectRef{
			Tenant:      rec.Intent.Tenant,
			EffectID:    rec.Intent.EffectID,
			AgreementID: rec.Intent.AgreementID,
			Digest:      rec.Digest,
			Namespace:   dest.Namespace(),
		}
		dispatch := rec.Phase == EffectPhaseIntended && !rec.Legacy
		if rec.Phase == EffectPhaseDispatching || rec.Phase == EffectPhaseUnknown || rec.Legacy {
			again, err := e.reconcile(&rec, id, ref, dest, fence)
			if err != nil {
				return err
			}
			if rec.Phase == EffectPhaseConfirmed {
				return nil
			}
			dispatch = again
		}
		if !dispatch {
			return ErrEffectReexecute
		}
		if rec.Phase != EffectPhaseIntended && rec.Phase != EffectPhaseDispatching && rec.Phase != EffectPhaseUnknown {
			return ErrCorrupt
		}
		// If an earlier attempt reached dispatching/unknown and Query did not
		// prove OutcomeNotDispatched (moving rec back to intended), a subsequent
		// OutcomeNotDispatched only proves this retry did not dispatch, NOT that
		// the earlier attempt did not execute.
		priorUncertain := rec.Phase != EffectPhaseIntended
		// Idempotent replay may dispatch again from unknown. Proven
		// not-dispatched has already been returned to intended. Either way
		// the dispatching record is durable before Execute.
		rec.Phase = EffectPhaseDispatching
		rec.Attempts++
		rec.Namespace = dest.Namespace()
		rec.ConfirmEvidence = ""
		rec.Legacy = false
		sealEffect(&rec)
		if err = e.writeEffect(id, rec); err != nil {
			return err
		}
		if e.beforeExecute != nil {
			if err = e.beforeExecute(); err != nil {
				return err
			}
		}
		outcome, execErr := dest.Execute(rec.Intent, ref, fence)
		return e.persistOutcome(&rec, id, outcome, execErr, priorUncertain)
	})
}

func (e *EffectAdapter) reconcile(rec *EffectRecord, id string, ref EffectRef, dest EffectDestination, fence Fence) (bool, error) {
	outcome, qerr := dest.Query(ref, fence)
	// ErrFenced and admission refusal do not prove the effect never ran,
	// even if a destination also claims OutcomeNotDispatched.
	if qerr != nil && (outcome != OutcomeNotDispatched || errors.Is(qerr, ErrFenced) || errors.Is(qerr, ErrAdmissionStopped)) {
		if err := e.markUnknown(rec, id); err != nil {
			return false, err
		}
		return false, qerr
	}
	switch outcome {
	case OutcomeConfirmed:
		if qerr != nil {
			if err := e.markUnknown(rec, id); err != nil {
				return false, err
			}
			return false, qerr
		}
		if err := e.markConfirmed(rec, id, "query:"+rec.Digest); err != nil {
			return false, err
		}
		return false, nil
	case OutcomeNotDispatched:
		if err := e.markIntended(rec, id); err != nil {
			return false, err
		}
		return true, nil
	default:
		if rec.Legacy || !dest.DurableIdempotent() {
			if err := e.markUnknown(rec, id); err != nil {
				return false, err
			}
			return false, ErrEffectReexecute
		}
		return true, nil
	}
}

func (e *EffectAdapter) persistOutcome(rec *EffectRecord, id string, outcome DestinationOutcome, execErr error, priorUncertain bool) error {
	fenceErr := errors.Is(execErr, ErrFenced) || errors.Is(execErr, ErrAdmissionStopped)
	ambiguous := fenceErr || (outcome == OutcomeConfirmed && execErr != nil) || (outcome != OutcomeConfirmed && outcome != OutcomeNotDispatched)
	if ambiguous {
		if err := e.markUnknown(rec, id); err != nil {
			return err
		}
		if errors.Is(execErr, ErrLostResponse) || execErr == nil {
			return ErrEffectUnknown
		}
		return execErr
	}
	if outcome == OutcomeNotDispatched {
		if priorUncertain {
			if err := e.markUnknown(rec, id); err != nil {
				return err
			}
		} else {
			if err := e.markIntended(rec, id); err != nil {
				return err
			}
		}
		if execErr != nil {
			return execErr
		}
		return ErrEffectUnknown
	}
	if err := e.markConfirmed(rec, id, "execute:"+rec.Digest); err != nil {
		return err
	}
	return nil
}

func (e *EffectAdapter) markUnknown(rec *EffectRecord, id string) error {
	if rec.Phase == EffectPhaseUnknown && !rec.Confirmed && rec.ConfirmEvidence == "" && rec.Reconcile {
		return nil
	}
	rec.Phase = EffectPhaseUnknown
	rec.ConfirmEvidence = ""
	sealEffect(rec)
	return e.writeEffect(id, *rec)
}

func (e *EffectAdapter) markIntended(rec *EffectRecord, id string) error {
	rec.Phase = EffectPhaseIntended
	rec.ConfirmEvidence = ""
	rec.Legacy = false
	sealEffect(rec)
	return e.writeEffect(id, *rec)
}

func (e *EffectAdapter) markConfirmed(rec *EffectRecord, id string, evidence string) error {
	if evidence == "" {
		return ErrCorrupt
	}
	rec.Phase = EffectPhaseConfirmed
	rec.ConfirmEvidence = evidence
	sealEffect(rec)
	return e.writeEffect(id, *rec)
}

func newIntentRecord(intent EffectIntent) EffectRecord {
	rec := EffectRecord{
		Version: EffectRecordVersion,
		Intent:  intent,
		Digest:  effectDigest(intent),
		Phase:   EffectPhaseIntended,
	}
	sealEffect(&rec)
	return rec
}

func sealEffect(rec *EffectRecord) {
	rec.Version = EffectRecordVersion
	rec.Confirmed = rec.Phase == EffectPhaseConfirmed
	rec.Status = rec.Phase
	rec.Reconcile = rec.Phase == EffectPhaseDispatching || rec.Phase == EffectPhaseUnknown || rec.Phase == EffectPhaseQuarantined
	if rec.Phase != EffectPhaseConfirmed {
		rec.ConfirmEvidence = ""
		rec.Confirmed = false
	}
}

func isOutboxRecordJSON(plain []byte) bool {
	var probe struct {
		Item   json.RawMessage `json:"Item"`
		Intent json.RawMessage `json:"Intent"`
	}
	if json.Unmarshal(plain, &probe) != nil {
		return false
	}
	hasItem := len(probe.Item) > 0 && string(probe.Item) != "null"
	hasIntent := len(probe.Intent) > 0 && string(probe.Intent) != "null"
	return hasItem && !hasIntent
}

func (e *EffectAdapter) readEffect(id, tenant, effectID string) (EffectRecord, error) {
	var stored EffectRecord
	fromLegacyBox := false
	err := e.vault.readNamed(effectFilename(id), effectAAD(id), &stored)
	if errors.Is(err, ErrNotFound) {
		plain, lerr := e.vault.readNamedBytes(id+".box", vaultHeader+"/"+id)
		if lerr != nil {
			return EffectRecord{}, lerr
		}
		defer clear(plain)
		if isOutboxRecordJSON(plain) {
			return EffectRecord{}, ErrNotFound
		}
		if json.Unmarshal(plain, &stored) != nil {
			return EffectRecord{}, ErrCorrupt
		}
		fromLegacyBox = true
	} else if err != nil {
		return EffectRecord{}, err
	}
	rec, rewrite, err := normalizeEffect(stored, tenant, effectID)
	if err != nil {
		return EffectRecord{}, err
	}
	if rewrite || fromLegacyBox {
		if err = e.writeEffect(id, rec); err != nil {
			return EffectRecord{}, err
		}
	}
	return rec, nil
}

func normalizeEffect(stored EffectRecord, tenant, effectID string) (EffectRecord, bool, error) {
	if stored.Version > EffectRecordVersion || stored.Version < 0 {
		return EffectRecord{}, false, ErrVersion
	}
	if err := validateEffectIntent(stored.Intent); err != nil {
		rec := quarantineEffect(stored)
		return rec, !effectProjectionEqual(stored, rec), nil
	}
	if stored.Intent.Tenant != tenant {
		return EffectRecord{}, false, ErrTenant
	}
	if stored.Intent.EffectID != effectID {
		rec := quarantineEffect(stored)
		return rec, !effectProjectionEqual(stored, rec), nil
	}
	if stored.Version == 0 {
		return migrateLegacyEffect(stored), true, nil
	}
	if stored.Version != EffectRecordVersion {
		return EffectRecord{}, false, ErrVersion
	}
	digest := effectDigest(stored.Intent)
	contradiction := stored.Digest != digest || stored.Attempts < 0 || !validPhase(stored.Phase)
	contradiction = contradiction || stored.Confirmed != (stored.Phase == EffectPhaseConfirmed)
	contradiction = contradiction || (stored.Phase == EffectPhaseConfirmed && stored.ConfirmEvidence == "")
	contradiction = contradiction || (stored.Phase == EffectPhaseIntended && stored.Legacy)
	contradiction = contradiction || (stored.Phase != EffectPhaseConfirmed && stored.ConfirmEvidence != "")
	if contradiction {
		rec := quarantineEffect(stored)
		rec.Digest = digest
		return rec, !effectProjectionEqual(stored, rec), nil
	}
	sealed := stored
	sealEffect(&sealed)
	return sealed, !effectProjectionEqual(stored, sealed), nil
}

func effectProjectionEqual(before, after EffectRecord) bool {
	return before.Version == after.Version && before.Phase == after.Phase && before.Status == after.Status && before.Confirmed == after.Confirmed && before.ConfirmEvidence == after.ConfirmEvidence && before.Reconcile == after.Reconcile && before.Legacy == after.Legacy && before.Digest == after.Digest && before.Namespace == after.Namespace && before.Attempts == after.Attempts
}

func migrateLegacyEffect(stored EffectRecord) EffectRecord {
	rec := stored
	rec.Digest = effectDigest(stored.Intent)
	rec.Legacy = true
	rec.ConfirmEvidence = ""
	switch {
	case stored.Status == EffectConfirmed && stored.Confirmed && stored.Phase == "":
		rec.Phase = EffectPhaseConfirmed
		rec.ConfirmEvidence = "legacy-confirmed"
		rec.Legacy = true
	case stored.Status == EffectPending && !stored.Confirmed && stored.Phase == "":
		// The old writer incremented attempts only in memory and stored them
		// after Execute. Attempts==0 does not prove the effect never ran.
		rec.Phase = EffectPhaseUnknown
	case stored.Status == EffectUnknown && !stored.Confirmed && stored.Phase == "":
		rec.Phase = EffectPhaseUnknown
	default:
		rec.Phase = EffectPhaseQuarantined
		rec.ConfirmEvidence = ""
	}
	sealEffect(&rec)
	if rec.Phase == EffectPhaseConfirmed {
		rec.ConfirmEvidence = "legacy-confirmed"
		rec.Confirmed = true
	}
	return rec
}

func quarantineEffect(stored EffectRecord) EffectRecord {
	rec := stored
	if rec.Digest == "" && rec.Intent.EffectID != "" {
		rec.Digest = effectDigest(rec.Intent)
	}
	rec.Phase = EffectPhaseQuarantined
	rec.ConfirmEvidence = ""
	rec.Legacy = rec.Legacy || rec.Version == 0
	sealEffect(&rec)
	return rec
}

func validPhase(phase string) bool {
	switch phase {
	case EffectPhaseIntended, EffectPhaseDispatching, EffectPhaseUnknown, EffectPhaseConfirmed, EffectPhaseQuarantined:
		return true
	default:
		return false
	}
}

func validateEffectIntent(intent EffectIntent) error {
	if err := validateID(intent.Tenant); err != nil {
		return err
	}
	if err := validateID(intent.EffectID); err != nil {
		return err
	}
	if err := validateID(intent.AgreementID); err != nil {
		return err
	}
	return nil
}

func effectDigest(intent EffectIntent) string {
	mac := sha256.New()
	for _, part := range []string{intent.Tenant, intent.EffectID, intent.AgreementID, intent.Evidence} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		mac.Write(n[:])
		mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// MemoryDestination is a synthetic effect sink for tests and the local example.
// It is not a remote system. When Guard is set, the fence is checked at the
// mutation under the coordinator lock. A refusal before that callback runs is
// OutcomeNotDispatched for this process only. EffectAdapter still treats a
// returned ErrFenced as unknown and will not infer not-dispatched from it.
type MemoryDestination struct {
	mu         sync.Mutex
	Guard      AuthorityGuard
	Fence      Fence
	Idempotent bool
	LoseNext   bool
	Restarted  bool
	Space      string
	exec       map[string]memEffect
	// entered and hold are test seams. hold is received while the mutation
	// lock is held. Production leaves both nil.
	entered chan struct{}
	hold    <-chan struct{}
}

type memEffect struct {
	count     int
	confirmed bool
	known     bool
	ref       EffectRef
}

func NewMemoryDestination() *MemoryDestination {
	return &MemoryDestination{exec: map[string]memEffect{}}
}

func (d *MemoryDestination) Namespace() string {
	if d != nil && d.Space != "" {
		return d.Space
	}
	return "memory"
}

func (d *MemoryDestination) DurableIdempotent() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Idempotent
}

func (d *MemoryDestination) check(fence Fence) error {
	if d.Fence.Generation == 0 || len(d.Fence.Token) == 0 {
		return ErrFenced
	}
	if fence.Generation != d.Fence.Generation || !bytes.Equal(fence.Token, d.Fence.Token) {
		return ErrFenced
	}
	return nil
}

func (d *MemoryDestination) Execute(intent EffectIntent, ref EffectRef, fence Fence) (DestinationOutcome, error) {
	if d.Guard != nil {
		var outcome DestinationOutcome
		var merr error
		err := d.Guard.Authorize(fence, func() error {
			d.mu.Lock()
			defer d.mu.Unlock()
			outcome, merr = d.mutate(intent, ref)
			return nil
		})
		if err != nil {
			// Authorize did not enter the callback, so this process did not
			// mutate. That is this sink's contract, not an adapter guess from ErrFenced.
			if errors.Is(err, ErrFenced) || errors.Is(err, ErrAdmissionStopped) {
				return OutcomeNotDispatched, nil
			}
			return OutcomeUnknown, err
		}
		return outcome, merr
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.check(fence); err != nil {
		return OutcomeNotDispatched, nil
	}
	return d.mutate(intent, ref)
}

func (d *MemoryDestination) Query(ref EffectRef, fence Fence) (DestinationOutcome, error) {
	if d.Guard != nil {
		var outcome DestinationOutcome
		var qerr error
		err := d.Guard.Authorize(fence, func() error {
			d.mu.Lock()
			defer d.mu.Unlock()
			outcome, qerr = d.queryLocked(ref)
			return nil
		})
		if err != nil {
			return OutcomeUnknown, err
		}
		return outcome, qerr
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.check(fence); err != nil {
		return OutcomeUnknown, err
	}
	return d.queryLocked(ref)
}

func (d *MemoryDestination) mutate(_ EffectIntent, ref EffectRef) (DestinationOutcome, error) {
	if d.exec == nil {
		d.exec = map[string]memEffect{}
	}
	cur, ok := d.exec[ref.slot()]
	if ok && !sameEffect(cur.ref, ref) {
		return OutcomeUnknown, ErrConflict
	}
	if d.Idempotent && ok && cur.confirmed {
		return OutcomeConfirmed, nil
	}
	if !d.Idempotent && ok && cur.count > 0 && !cur.known {
		return OutcomeUnknown, ErrEffectReexecute
	}
	d.arm()
	cur.count++
	cur.ref = ref
	if d.LoseNext {
		d.LoseNext = false
		if d.Idempotent {
			cur.confirmed = true
			cur.known = true
		}
		d.exec[ref.slot()] = cur
		return OutcomeUnknown, ErrLostResponse
	}
	cur.confirmed = true
	cur.known = true
	d.exec[ref.slot()] = cur
	return OutcomeConfirmed, nil
}

func (d *MemoryDestination) arm() {
	if d.entered != nil {
		ch := d.entered
		d.entered = nil
		close(ch)
	}
	if d.hold != nil {
		<-d.hold
	}
}

func (d *MemoryDestination) queryLocked(ref EffectRef) (DestinationOutcome, error) {
	if d.Restarted && !d.Idempotent {
		return OutcomeUnknown, nil
	}
	if d.exec == nil {
		return OutcomeUnknown, nil
	}
	cur, ok := d.exec[ref.slot()]
	if !ok {
		return OutcomeUnknown, nil
	}
	if !sameEffect(cur.ref, ref) {
		return OutcomeUnknown, ErrConflict
	}
	if cur.confirmed && cur.known {
		return OutcomeConfirmed, nil
	}
	return OutcomeUnknown, nil
}

func sameEffect(a, b EffectRef) bool {
	return a.Tenant == b.Tenant && a.Namespace == b.Namespace && a.EffectID == b.EffectID && a.AgreementID == b.AgreementID && a.Digest == b.Digest
}

func (d *MemoryDestination) Executions(effectID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, cur := range d.exec {
		if cur.ref.EffectID == effectID {
			n += cur.count
		}
	}
	return n
}

func (d *MemoryDestination) Count(ref EffectRef) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.exec == nil {
		return 0
	}
	return d.exec[ref.slot()].count
}
