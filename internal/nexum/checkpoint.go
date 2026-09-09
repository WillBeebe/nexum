package nexum

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/WillBeebe/nexum/internal/settle"
)

// PrivateCheckpoint includes local custody secrets. It must only be persisted
// in authenticated encrypted storage, never exposed as a public receipt bundle.
type PrivateCheckpoint struct {
	Version   int
	Agreement *Agreement
	Steps     int
	Ledger    *settle.PrivateState
}

func (a *Agreement) PrivateCheckpoint() PrivateCheckpoint {
	s := PrivateCheckpoint{Version: 1, Agreement: a, Steps: a.steps}
	if a.Sealed != nil {
		l := a.Sealed.PrivateState()
		s.Ledger = &l
	}
	return s
}

// RestorePrivate reconstructs the exact ciphertext, receipt head and step meter.
// It must receive authenticated local data, not a peer-supplied snapshot.
func RestorePrivate(s PrivateCheckpoint) (*Agreement, error) {
	bad := errors.New("nexum: invalid private checkpoint")
	if s.Version != 1 || s.Agreement == nil {
		return nil, bad
	}
	// Own all slices and timestamps rather than aliasing the checkpoint.
	data, err := json.Marshal(s.Agreement)
	if err != nil {
		return nil, err
	}
	var a Agreement
	if err = json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	if a.ID == "" || a.Kind == "" || a.Buyer == "" || a.Seller == "" || a.Buyer == a.Seller || a.Amount <= 0 ||
		s.Steps != len(a.Receipts) || s.Steps < 1 || s.Steps > a.Meter.MaxSteps || a.Meter.MaxSteps > 128 {
		return nil, bad
	}
	if err = a.VerifyReceipts(); err != nil {
		return nil, bad
	}
	a.steps = s.Steps
	switch a.Status {
	case StatusOpen:
		if a.LockedAt != nil || a.ClosedAt != nil || a.ReleasedTo != "" {
			return nil, bad
		}
	case StatusLocked:
		if a.LockedAt == nil || a.ClosedAt != nil || a.ReleasedTo != "" {
			return nil, bad
		}
	case StatusAccepted:
		if a.LockedAt == nil || a.ClosedAt == nil || a.ReleasedTo != a.Seller {
			return nil, bad
		}
	case StatusRejected:
		if a.LockedAt == nil || a.ClosedAt == nil || a.ReleasedTo != a.Buyer {
			return nil, bad
		}
	case StatusExpired:
		if a.ClosedAt == nil || a.ReleasedTo != a.Buyer {
			return nil, bad
		}
	default:
		return nil, bad
	}
	if s.Ledger != nil {
		if len(s.Ledger.Randomness) != len(a.SealedLocks) {
			return nil, bad
		}
		a.Sealed, err = settle.RestorePrivate(*s.Ledger)
		if err != nil {
			return nil, bad
		}
		if len(a.SealedLocks) > 0 {
			sum, e := a.Sealed.Aggregate(a.SealedLocks)
			if e != nil {
				return nil, bad
			}
			if a.Status == StatusAccepted {
				if len(a.SealedSum) != 0 {
					return nil, bad
				}
			} else if !bytes.Equal(sum, a.SealedSum) {
				return nil, bad
			}
		} else if len(a.SealedSum) != 0 {
			return nil, bad
		}
	} else if len(a.SealedLocks) > 0 || len(a.SealedSum) > 0 {
		return nil, bad
	}
	return &a, nil
}
