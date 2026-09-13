package adapter

import (
	"bytes"
	"time"

	"github.com/WillBeebe/nexum/nex"
)

type itemRecord struct {
	Version  int
	Item     OutboundItem
	Status   string
	Original *AuthenticatedResponse
	NextTry  time.Time
	Attempts int
}

// Outbox retains exact signed commands until a verified result is recorded.
type Outbox struct {
	vault   *vault
	Quota   int
	now     func() time.Time
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
	if now != nil {
		o.now = now
	}
}

func (o *Outbox) StopAdmission() { o.stopped = true }

func (o *Outbox) Enqueue(item OutboundItem) error {
	if err := validateItem(item); err != nil {
		return err
	}
	item.Retry = item.Retry.normalized()
	id := recordID(item.Tenant, item.OperationID)
	return o.vault.withLock(func() error {
		if o.stopped {
			return ErrAdmissionStopped
		}
		var existing itemRecord
		err := o.vault.read(id, &existing)
		if err == nil {
			if existing.Item.Tenant != item.Tenant {
				return ErrTenant
			}
			if !bytes.Equal(existing.Item.SignedObject, item.SignedObject) {
				return ErrConflict
			}
			return nil
		}
		if err != ErrNotFound {
			return err
		}
		if err = o.enforceQuota(item.Tenant); err != nil {
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
	now := o.now()
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
			if stored.Item.Tenant != tenant || stored.Status == StatusResolved {
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
	rec, err := o.Get(tenant, operationID)
	if err != nil {
		return AuthenticatedResponse{}, err
	}
	if rec.Status != StatusResolved && !rec.NextTry.IsZero() && o.now().Before(rec.NextTry) {
		return AuthenticatedResponse{}, ErrNotDue
	}
	return o.Reconcile(tenant, operationID, auth)
}

// Reconcile resubmits the identical signed bytes. It never calls Prepare.
func (o *Outbox) Reconcile(tenant, operationID string, auth Authority) (AuthenticatedResponse, error) {
	var resp AuthenticatedResponse
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
		if stored.Item.Tenant != tenant {
			return ErrTenant
		}
		if stored.Status == StatusResolved && stored.Original != nil {
			resp = *stored.Original
			return nil
		}
		got, err := auth.Apply(stored.Item)
		stored.Attempts++
		stored.NextTry = o.now().Add(backoff(stored.Item.Retry, stored.Attempts))
		if err != nil {
			stored.Status = statusFor(got, err)
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return err
		}
		if got.Kind == ResultUncertain {
			stored.Status = StatusUnknown
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return ErrUnresolved
		}
		if got.Kind == ResultConflict {
			stored.Status = StatusConflict
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return ErrConflict
		}
		if got.Kind == ResultRefused {
			stored.Status = StatusUnknown
			if writeErr := o.vault.write(id, stored); writeErr != nil {
				return writeErr
			}
			resp = got
			return ErrUnresolved
		}
		stored.Status = StatusUnknown
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
		if stored.Item.Tenant != tenant || resp.Tenant != tenant {
			return ErrTenant
		}
		if resp.AgreementID != stored.Item.AgreementID || resp.RequestID != stored.Item.OperationID {
			return ErrForeign
		}
		if resp.CommandHash != CommandHash(stored.Item.SignedObject) {
			return ErrForeign
		}
		if resp.Version != Version || resp.Kind != ResultAgreement {
			return ErrResponse
		}
		if err := VerifyResponse(authority, resp, signature); err != nil {
			return ErrResponse
		}
		copy := resp
		stored.Original = &copy
		stored.Status = StatusResolved
		return o.vault.write(id, stored)
	})
}

func (o *Outbox) enforceQuota(tenant string) error {
	limit := o.Quota
	if limit <= 0 {
		limit = DefaultQuota
	}
	ids, err := o.vault.listIDs()
	if err != nil {
		return err
	}
	n := 0
	for _, id := range ids {
		var stored itemRecord
		if err = o.vault.read(id, &stored); err != nil {
			return err
		}
		if stored.Item.Tenant == tenant && stored.Status != StatusResolved {
			n++
		}
	}
	if n >= limit {
		return ErrQuota
	}
	return nil
}

func validateItem(item OutboundItem) error {
	if item.Version != Version || (item.Kind != KindAgreement && item.Kind != KindProtocol) {
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
	if len(item.SignedObject) == 0 || len(item.SignedObject) > 64<<10 {
		return ErrItem
	}
	if _, err := DecodePayload(item.SignedObject); err != nil {
		return err
	}
	return nil
}

func recorded(s itemRecord) RecordedItem {
	return RecordedItem{Item: s.Item, Status: s.Status, Original: s.Original, NextTry: s.NextTry, Attempts: s.Attempts}
}

func statusFor(got AuthenticatedResponse, err error) string {
	if got.Kind == ResultConflict || err == ErrConflict {
		return StatusConflict
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
