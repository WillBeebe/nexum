package adapter

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

// DefaultHistory is the retained-row bound per tenant. Admission fails when
// it is reached. Rows are not deleted to free a pending slot.
const DefaultHistory = 1024

type itemRecord struct {
	Version   int
	Item      OutboundItem
	Status    string
	Original  *AuthenticatedResponse
	Candidate *AuthenticatedResponse
	NextTry   time.Time
	Attempts  int
	// VerifiedSignature and Authority are written by RecordVerified.
	// Both empty means the row has local vault provenance only.
	VerifiedSignature []byte
	Authority         nex.Public
}

const (
	admissionGateFile = "admission.gate"
	admissionGateAAD  = vaultHeader + "/admission.gate/v1"
)

type admissionGateRecord struct {
	Version    int    `json:"version"`
	Stopped    bool   `json:"stopped"`
	Generation uint64 `json:"generation"`
}

// Outbox retains exact signed commands until a verified result is recorded.
type Outbox struct {
	vault        *vault
	Quota        int
	HistoryLimit int
	now          func() time.Time
	// mu guards the in-process stopped latch; admission.gate persists the
	// admission gate across processes sharing or copying the vault directory.
	mu      sync.Mutex
	stopped bool
}

func OpenOutbox(dir string, key []byte) (*Outbox, error) {
	v, err := openVault(dir, key)
	if err != nil {
		return nil, err
	}
	return &Outbox{vault: v, Quota: DefaultQuota, now: time.Now}, nil
}

func (o *Outbox) SetNow(now func() time.Time) {
	if now == nil {
		return
	}
	o.mu.Lock()
	o.now = now
	o.mu.Unlock()
}

func (o *Outbox) clock() time.Time {
	o.mu.Lock()
	fn := o.now
	o.mu.Unlock()
	if fn == nil {
		return time.Now()
	}
	return fn()
}

func (o *Outbox) setStopped(stopped bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stopped = stopped
}

func (o *Outbox) StopAdmission() {
	if o == nil {
		return
	}
	if o.vault == nil {
		o.setStopped(true)
		return
	}
	_ = o.vault.withLock(func() error {
		o.setStopped(true)
		gate, _, err := o.readAdmissionGateLocked()
		if err != nil {
			return err
		}
		gate.Stopped = true
		return o.writeAdmissionGateLocked(gate)
	})
}

// SealAdmission durably stops new Enqueue calls at the given fence generation.
// Any process opening or copying this vault observes ErrAdmissionStopped on
// Enqueue until ResumeAdmission succeeds at or above generation.
func (o *Outbox) SealAdmission(generation uint64) error {
	if o == nil || o.vault == nil {
		return ErrItem
	}
	return o.vault.withLock(func() error {
		gate, exists, err := o.readAdmissionGateLocked()
		if err != nil {
			return err
		}
		if generation < gate.Generation {
			if exists {
				o.setStopped(gate.Stopped)
			}
			return ErrActivation
		}
		gate.Stopped = true
		gate.Generation = generation
		if err := o.writeAdmissionGateLocked(gate); err != nil {
			return err
		}
		o.setStopped(true)
		return nil
	})
}

// ResumeAdmission reopens admission at generation, refusing any generation
// older than the durable gate generation.
func (o *Outbox) ResumeAdmission(generation uint64) error {
	if o == nil || o.vault == nil {
		return ErrItem
	}
	return o.vault.withLock(func() error {
		gate, exists, err := o.readAdmissionGateLocked()
		if err != nil {
			return err
		}
		if generation < gate.Generation {
			if exists {
				o.setStopped(gate.Stopped)
			}
			return ErrActivation
		}
		gate.Stopped = false
		gate.Generation = generation
		if err := o.writeAdmissionGateLocked(gate); err != nil {
			return err
		}
		o.setStopped(false)
		return nil
	})
}

// AdmissionSealed reports whether admission is stopped and the persisted gate
// generation recorded in admission.gate.
func (o *Outbox) AdmissionSealed() (bool, uint64, error) {
	if o == nil || o.vault == nil {
		return true, 0, ErrItem
	}
	var (
		sealed bool
		gen    uint64
	)
	err := o.vault.withLock(func() error {
		gate, exists, err := o.readAdmissionGateLocked()
		if err != nil {
			return err
		}
		if exists {
			o.setStopped(gate.Stopped)
			sealed = gate.Stopped
		} else {
			sealed = o.admissionStopped()
		}
		gen = gate.Generation
		return nil
	})
	if err != nil {
		return false, 0, err
	}
	return sealed, gen, nil
}

func (o *Outbox) readAdmissionGateLocked() (admissionGateRecord, bool, error) {
	var gate admissionGateRecord
	err := o.vault.readNamed(admissionGateFile, admissionGateAAD, &gate)
	if errors.Is(err, ErrNotFound) {
		return admissionGateRecord{Version: Version}, false, nil
	}
	if err != nil {
		return admissionGateRecord{}, false, err
	}
	if gate.Version != Version {
		return admissionGateRecord{}, false, ErrVersion
	}
	return gate, true, nil
}

func (o *Outbox) writeAdmissionGateLocked(gate admissionGateRecord) error {
	gate.Version = Version
	return o.vault.writeNamed(admissionGateFile, admissionGateAAD, gate)
}

func (o *Outbox) admissionStopped() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.stopped
}

func (o *Outbox) Enqueue(item OutboundItem) error {
	if o == nil || o.vault == nil {
		return ErrItem
	}
	if err := validateItem(item); err != nil {
		return err
	}
	item.Retry = item.Retry.normalized()
	id := recordID(item.Tenant, item.OperationID)
	return o.vault.withLock(func() error {
		gate, exists, err := o.readAdmissionGateLocked()
		if err != nil {
			return err
		}
		if exists {
			o.setStopped(gate.Stopped)
			if gate.Stopped {
				return ErrAdmissionStopped
			}
		} else if o.admissionStopped() {
			return ErrAdmissionStopped
		}
		var existing itemRecord
		err = o.vault.read(id, &existing)
		if err == nil {
			if existing.Item.Tenant != item.Tenant {
				return ErrTenant
			}
			if !bytes.Equal(existing.Item.SignedObject, item.SignedObject) ||
				existing.Item.AgreementID != item.AgreementID ||
				existing.Item.Destination != item.Destination ||
				existing.Item.Kind != item.Kind {
				return ErrConflict
			}
			return nil
		}
		if err != ErrNotFound {
			return err
		}
		if err = o.enforceBounds(item.Tenant); err != nil {
			return err
		}
		return o.vault.write(id, itemRecord{Version: Version, Item: item, Status: StatusPending})
	})
}

func (o *Outbox) Get(tenant, operationID string) (RecordedItem, error) {
	var rec RecordedItem
	if err := validateID(tenant); err != nil {
		return rec, err
	}
	if err := validateID(operationID); err != nil {
		return rec, err
	}
	err := o.vault.withLock(func() error {
		var stored itemRecord
		if err := o.vault.read(recordID(tenant, operationID), &stored); err != nil {
			return err
		}
		if err := validateStored(stored); err != nil {
			return err
		}
		if stored.Item.Tenant != tenant {
			return ErrTenant
		}
		rec = recorded(stored)
		return nil
	})
	return rec, err
}

func (o *Outbox) Due(tenant string) ([]RecordedItem, error) {
	if err := validateID(tenant); err != nil {
		return nil, err
	}
	now := o.clock()
	var out []RecordedItem
	err := o.vault.withLock(func() error {
		ids, err := o.vault.listIDs()
		if err != nil {
			return err
		}
		for _, id := range ids {
			var stored itemRecord
			if err = o.vault.read(id, &stored); err != nil {
				return err
			}
			if err = validateStored(stored); err != nil {
				return err
			}
			if stored.Item.Tenant != tenant || terminalOutbox(stored.Status) {
				continue
			}
			if !stored.NextTry.IsZero() && now.Before(stored.NextTry) {
				continue
			}
			out = append(out, recorded(stored))
		}
		return nil
	})
	return out, err
}

func (o *Outbox) Unresolved(tenant string) ([]RecordedItem, error) {
	if err := validateID(tenant); err != nil {
		return nil, err
	}
	var out []RecordedItem
	err := o.vault.withLock(func() error {
		ids, err := o.vault.listIDs()
		if err != nil {
			return err
		}
		for _, id := range ids {
			var stored itemRecord
			if err = o.vault.read(id, &stored); err != nil {
				return err
			}
			if err = validateStored(stored); err != nil {
				return err
			}
			if stored.Item.Tenant != tenant || stored.Status == StatusResolved {
				continue
			}
			out = append(out, recorded(stored))
		}
		return nil
	})
	return out, err
}

// ReconcileDue resubmits only when backoff has elapsed. Explicit Reconcile
// still retries immediately so an operator can force reconciliation.
func (o *Outbox) ReconcileDue(tenant, operationID string, auth Authority) (AuthenticatedResponse, error) {
	return o.reconcile(tenant, operationID, auth, true)
}

// Reconcile resubmits the identical signed bytes. It never calls Prepare.
func (o *Outbox) Reconcile(tenant, operationID string, auth Authority) (AuthenticatedResponse, error) {
	return o.reconcile(tenant, operationID, auth, false)
}

func (o *Outbox) reconcile(tenant, operationID string, auth Authority, enforceDue bool) (AuthenticatedResponse, error) {
	var resp AuthenticatedResponse
	if o == nil || o.vault == nil || auth == nil {
		return resp, ErrItem
	}
	if err := validateID(tenant); err != nil {
		return resp, err
	}
	if err := validateID(operationID); err != nil {
		return resp, err
	}
	err := o.vault.withLock(func() error {
		id := recordID(tenant, operationID)
		var stored itemRecord
		if err := o.vault.read(id, &stored); err != nil {
			return err
		}
		if err := validateStored(stored); err != nil {
			return err
		}
		if stored.Item.Tenant != tenant {
			return ErrTenant
		}
		if stored.Status == StatusResolved && stored.Original != nil {
			resp = *stored.Original
			return nil
		}
		if stored.Status == StatusConflict {
			return ErrConflict
		}
		if stored.Status == StatusRefused {
			if stored.Original != nil {
				resp = *stored.Original
			}
			return ErrDefinitive
		}
		if enforceDue && !stored.NextTry.IsZero() && o.clock().Before(stored.NextTry) {
			return ErrNotDue
		}
		got, err := auth.Apply(stored.Item)
		stored.Attempts++
		stored.NextTry = o.clock().Add(backoff(stored.Item.Retry, stored.Attempts))
		if err != nil {
			stored.Status = statusFor(got, err)
			stored.Candidate = nil
			if terminalOutbox(stored.Status) {
				copy := got
				stored.Original = &copy
				stored.NextTry = time.Time{}
			}
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return err
		}
		if got.Kind == ResultUncertain || got.Kind == ResultRefused {
			stored.Status = StatusUnknown
			stored.Candidate = nil
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return ErrUnresolved
		}
		if got.Kind == ResultConflict {
			copy := got
			stored.Original = &copy
			stored.Candidate = nil
			stored.Status = StatusConflict
			stored.NextTry = time.Time{}
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return ErrConflict
		}
		if !validCandidate(stored.Item, got) {
			stored.Status = StatusUnknown
			stored.Candidate = nil
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return ErrResponse
		}
		copy := got
		stored.Candidate = &copy
		stored.Status = StatusAwaiting
		if writeErr := o.vault.write(id, stored); writeErr != nil {
			return writeErr
		}
		resp = got
		return nil
	})
	return resp, err
}

// RecordVerified persists a verified result before marking the item resolved.
func (o *Outbox) RecordVerified(tenant, operationID string, resp AuthenticatedResponse, authority nex.Public, signature []byte) error {
	if err := validateID(tenant); err != nil {
		return err
	}
	if err := validateID(operationID); err != nil {
		return err
	}
	return o.vault.withLock(func() error {
		id := recordID(tenant, operationID)
		var stored itemRecord
		if err := o.vault.read(id, &stored); err != nil {
			return err
		}
		if err := validateStored(stored); err != nil {
			return err
		}
		if stored.Item.Tenant != tenant || resp.Tenant != tenant {
			return ErrTenant
		}
		if resp.AgreementID != stored.Item.AgreementID || resp.RequestID != stored.Item.OperationID {
			return ErrForeign
		}
		if resp.CommandHash != CommandHash(stored.Item.SignedObject) {
			return ErrForeign
		}
		if resp.Error != "" || resp.Version != Version || resp.Kind != ResultAgreement {
			return ErrResponse
		}
		if !responseMatchesKind(stored.Item.Kind, resp) {
			return ErrResponse
		}
		if err := VerifyResponse(authority, resp, signature); err != nil {
			return ErrResponse
		}
		if stored.Candidate != nil && !sameTerminal(*stored.Candidate, resp) {
			return ErrConflict
		}
		if stored.Status == StatusResolved && stored.Original != nil {
			if sameTerminal(*stored.Original, resp) {
				return nil
			}
			return ErrConflict
		}
		if stored.Status == StatusConflict || stored.Status == StatusRefused {
			return ErrConflict
		}
		copy := resp
		stored.Original = &copy
		stored.Candidate = nil
		stored.Status = StatusResolved
		stored.NextTry = time.Time{}
		stored.VerifiedSignature = append([]byte(nil), signature...)
		stored.Authority = authority
		return o.vault.write(id, stored)
	})
}

func (o *Outbox) enforceBounds(tenant string) error {
	quotaLimit := o.Quota
	if quotaLimit <= 0 {
		quotaLimit = DefaultQuota
	}
	historyLimit := o.HistoryLimit
	if historyLimit <= 0 {
		historyLimit = DefaultHistory
	}
	ids, err := o.vault.listIDs()
	if err != nil {
		return err
	}
	pending, total := 0, 0
	for _, id := range ids {
		var stored itemRecord
		if err = o.vault.read(id, &stored); err != nil {
			return err
		}
		if err = validateStored(stored); err != nil {
			return err
		}
		if stored.Item.Tenant == tenant {
			total++
			if !terminalOutbox(stored.Status) {
				pending++
			}
		}
	}
	if pending >= quotaLimit || total >= historyLimit {
		return ErrQuota
	}
	return nil
}

func validKind(kind Kind) bool {
	switch kind {
	case KindAgreement, KindProtocol, KindAccord:
		return true
	default:
		return false
	}
}

func maxSignedObjectBytes(kind Kind) int {
	if kind == KindAccord {
		// nex.Accord permits 512 KiB commands for attest (and sealed votes);
		// allow envelope overhead on top of the inner command cap.
		return 512<<10 + 4096
	}
	return 64 << 10
}

func validateItem(item OutboundItem) error {
	if item.Version != Version || !validKind(item.Kind) {
		return ErrItem
	}
	if err := validateID(item.Tenant); err != nil {
		return err
	}
	if err := validateID(item.AgreementID); err != nil {
		return err
	}
	if err := validateID(item.OperationID); err != nil {
		return err
	}
	if err := validateID(item.Destination); err != nil {
		return err
	}
	if len(item.SignedObject) == 0 || len(item.SignedObject) > maxSignedObjectBytes(item.Kind) {
		return ErrItem
	}
	payload, err := DecodePayload(item.SignedObject)
	if err != nil {
		return err
	}
	if payload.Kind != item.Kind {
		return ErrItem
	}
	switch item.Kind {
	case KindAgreement:
		if payload.Operation == nil || payload.Operation.ID != item.OperationID || payload.Operation.Command.Terms != item.AgreementID {
			return ErrItem
		}
	case KindProtocol:
		if payload.Command == nil || payload.Command.RequestID != item.OperationID || payload.Command.ProtocolID != item.AgreementID {
			return ErrItem
		}
	case KindAccord:
		if payload.Accord == nil || payload.Accord.RequestID != item.OperationID || payload.Accord.AccordID != item.AgreementID || payload.Accord.Height == 0 {
			return ErrItem
		}
	default:
		return ErrItem
	}
	return nil
}

func validCandidate(item OutboundItem, resp AuthenticatedResponse) bool {
	if resp.Version != Version || resp.Kind != ResultAgreement || resp.Error != "" {
		return false
	}
	if resp.Tenant != item.Tenant || resp.AgreementID != item.AgreementID || resp.RequestID != item.OperationID {
		return false
	}
	if resp.CommandHash != CommandHash(item.SignedObject) {
		return false
	}
	return responseMatchesKind(item.Kind, resp)
}

func terminalOutbox(status string) bool {
	return status == StatusResolved || status == StatusConflict || status == StatusRefused
}

func validateStored(stored itemRecord) error {
	if stored.Version != Version {
		return ErrVersion
	}
	if err := validateItem(stored.Item); err != nil {
		return err
	}
	switch stored.Status {
	case StatusPending, StatusUnknown, StatusAwaiting, StatusResolved, StatusConflict, StatusRefused:
	default:
		return ErrCorrupt
	}
	if stored.Status == StatusResolved && (stored.Original == nil || stored.Original.Error != "") {
		return ErrCorrupt
	}
	if stored.Status == StatusResolved {
		signed := len(stored.VerifiedSignature) > 0
		identified := len(stored.Authority.Signing) > 0
		if signed != identified {
			return ErrCorrupt
		}
		if signed {
			if err := VerifyResponse(stored.Authority, *stored.Original, stored.VerifiedSignature); err != nil {
				return ErrCorrupt
			}
		}
	}
	if stored.Status == StatusAwaiting && (stored.Candidate == nil || !validCandidate(stored.Item, *stored.Candidate)) {
		return ErrCorrupt
	}
	return nil
}

func responseMatchesKind(kind Kind, resp AuthenticatedResponse) bool {
	switch kind {
	case KindAgreement:
		return resp.Result != nil && resp.Result.Head != "" && resp.Result.Head == resp.ReceiptHead
	case KindProtocol, KindAccord:
		return resp.Result == nil && resp.ReceiptHead != ""
	default:
		return false
	}
}

func sameTerminal(a, b AuthenticatedResponse) bool {
	if a.Version != b.Version ||
		a.Tenant != b.Tenant ||
		a.AgreementID != b.AgreementID ||
		a.RequestID != b.RequestID ||
		a.CommandHash != b.CommandHash ||
		a.Kind != b.Kind ||
		a.ReceiptHead != b.ReceiptHead ||
		a.Phase != b.Phase ||
		a.WorkOutcome != b.WorkOutcome ||
		a.Error != b.Error ||
		a.Definitive != b.Definitive {
		return false
	}
	if (a.Result == nil) != (b.Result == nil) {
		return false
	}
	if a.Result != nil && *a.Result != *b.Result {
		return false
	}
	return true
}

func recorded(s itemRecord) RecordedItem {
	return RecordedItem{Item: s.Item, Status: s.Status, Original: s.Original, NextTry: s.NextTry, Attempts: s.Attempts}
}

func statusFor(got AuthenticatedResponse, err error) string {
	if got.Kind == ResultConflict || err == ErrConflict || errors.Is(err, nex.ErrOperationConflict) {
		return StatusConflict
	}
	if got.Kind == ResultRefused && got.Definitive {
		return StatusRefused
	}
	return StatusUnknown
}

func backoff(p RetryPolicy, attempts int) time.Duration {
	p = p.normalized()
	d := p.InitialBackoff
	for i := 1; i < attempts; i++ {
		if d >= p.MaxBackoff/2 {
			return p.MaxBackoff
		}
		d *= 2
	}
	if d > p.MaxBackoff {
		return p.MaxBackoff
	}
	return d
}
