package adapter

import (
	"bytes"
)

const (
	EffectPending   = "pending"
	EffectConfirmed = "confirmed"
	EffectUnknown   = "effect_unknown"
)

type EffectIntent struct {
	Tenant      string
	EffectID    string
	AgreementID string
	Evidence    string
}

type EffectRecord struct {
	Intent    EffectIntent
	Status    string
	Attempts  int
	Confirmed bool
}

type EffectDestination interface {
	Execute(intent EffectIntent, fence Fence) (confirmed bool, err error)
	Query(effectID string, fence Fence) (found bool, confirmed bool, err error)
}

type EffectAdapter struct {
	vault *vault
}

func OpenEffects(dir string, key []byte) (*EffectAdapter, error) {
	v, err := openVault(dir, key)
	if err != nil {
		return nil, err
	}
	return &EffectAdapter{v}, nil
}

func (e *EffectAdapter) Intend(intent EffectIntent) error {
	if err := validateID(intent.Tenant); err != nil {
		return err
	}
	if err := validateID(intent.EffectID); err != nil {
		return err
	}
	if err := validateID(intent.AgreementID); err != nil {
		return err
	}
	id := recordID(intent.Tenant, intent.EffectID)
	return e.vault.withLock(func() error {
		var existing EffectRecord
		err := e.vault.read(id, &existing)
		if err == nil {
			if existing.Intent.Tenant != intent.Tenant {
				return ErrTenant
			}
			if existing.Intent != intent {
				return ErrConflict
			}
			return nil
		}
		if err != ErrNotFound {
			return err
		}
		return e.vault.write(id, EffectRecord{Intent: intent, Status: EffectPending})
	})
}

func (e *EffectAdapter) Get(tenant, effectID string) (EffectRecord, error) {
	var rec EffectRecord
	err := e.vault.withLock(func() error {
		var stored EffectRecord
		if err := e.vault.read(recordID(tenant, effectID), &stored); err != nil {
			return err
		}
		if stored.Intent.Tenant != tenant {
			return ErrTenant
		}
		rec = stored
		return nil
	})
	return rec, err
}

// Apply queries the destination before another attempt. Lost responses without
// an idempotent query remain effect_unknown; they are never auto-reexecuted.
func (e *EffectAdapter) Apply(tenant, effectID string, dest EffectDestination, fence Fence) error {
	if dest == nil {
		return ErrItem
	}
	return e.vault.withLock(func() error {
		id := recordID(tenant, effectID)
		var stored EffectRecord
		if err := e.vault.read(id, &stored); err != nil {
			return err
		}
		if stored.Intent.Tenant != tenant {
			return ErrTenant
		}
		if stored.Status == EffectConfirmed {
			return nil
		}
		if stored.Attempts > 0 {
			found, confirmed, err := dest.Query(effectID, fence)
			if err != nil {
				stored.Status = EffectUnknown
				_ = e.vault.write(id, stored)
				return err
			}
			if found && confirmed {
				stored.Status = EffectConfirmed
				stored.Confirmed = true
				return e.vault.write(id, stored)
			}
			if !found {
				stored.Status = EffectUnknown
				_ = e.vault.write(id, stored)
				return ErrEffectReexecute
			}
			stored.Status = EffectUnknown
			_ = e.vault.write(id, stored)
			return ErrEffectUnknown
		}
		stored.Attempts++
		confirmed, err := dest.Execute(stored.Intent, fence)
		if err != nil {
			if err == ErrLostResponse {
				stored.Status = EffectUnknown
				_ = e.vault.write(id, stored)
				return ErrEffectUnknown
			}
			stored.Status = EffectUnknown
			_ = e.vault.write(id, stored)
			return err
		}
		if !confirmed {
			stored.Status = EffectUnknown
			_ = e.vault.write(id, stored)
			return ErrEffectUnknown
		}
		stored.Status = EffectConfirmed
		stored.Confirmed = true
		return e.vault.write(id, stored)
	})
}

// MemoryDestination is a synthetic effect sink for tests and the local example.
type MemoryDestination struct {
	Fence      Fence
	Idempotent bool
	LoseNext   bool
	Restarted  bool
	executions map[string]int
	confirmed  map[string]bool
	queryKnown map[string]bool
}

func NewMemoryDestination() *MemoryDestination {
	return &MemoryDestination{executions: map[string]int{}, confirmed: map[string]bool{}, queryKnown: map[string]bool{}}
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

func (d *MemoryDestination) Execute(intent EffectIntent, fence Fence) (bool, error) {
	if err := d.check(fence); err != nil {
		return false, err
	}
	if d.executions == nil {
		d.executions = map[string]int{}
		d.confirmed = map[string]bool{}
		d.queryKnown = map[string]bool{}
	}
	if d.Idempotent {
		if d.confirmed[intent.EffectID] {
			return true, nil
		}
	} else if d.executions[intent.EffectID] > 0 && !d.queryKnown[intent.EffectID] {
		return false, ErrEffectReexecute
	}
	d.executions[intent.EffectID]++
	if d.LoseNext {
		d.LoseNext = false
		if d.Idempotent {
			d.confirmed[intent.EffectID] = true
			d.queryKnown[intent.EffectID] = true
		}
		return false, ErrLostResponse
	}
	d.confirmed[intent.EffectID] = true
	d.queryKnown[intent.EffectID] = true
	return true, nil
}

func (d *MemoryDestination) Query(effectID string, fence Fence) (bool, bool, error) {
	if err := d.check(fence); err != nil {
		return false, false, err
	}
	if d.Restarted && !d.Idempotent {
		return false, false, nil
	}
	if !d.queryKnown[effectID] {
		return false, false, nil
	}
	return true, d.confirmed[effectID], nil
}

func (d *MemoryDestination) Executions(effectID string) int { return d.executions[effectID] }
