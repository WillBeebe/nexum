package nexum

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/WillBeebe/nexum/v2/internal/settle"
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
	if a.Format != 0 && a.Format != 1 && a.Format != FormatV2 {
		return nil, bad
	}
	if a.Format >= FormatV2 && a.Mode != ModePlaintext && a.Mode != ModeSealed {
		return nil, bad
	}
	seals := 0
	for _, r := range a.Receipts {
		if r.Action == "seal" {
			seals++
		}
	}
	if seals > 0 || len(a.SealedLocks) > 0 || len(a.SealedSum) > 0 || a.Mode == ModeSealed {
		if err = a.sealsMatchReceipts(); err != nil {
			return nil, bad
		}
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
	if a.Mode == ModePlaintext && (s.Ledger != nil || seals > 0 || len(a.SealedLocks) > 0 || len(a.SealedSum) > 0 || len(a.SealedAggregate) > 0 || a.Scheme != "" || len(a.PublicKey) > 0 || len(a.SealedEqualityProof) > 0) {
		return nil, bad
	}
	if s.Ledger != nil {
		if a.Mode == ModePlaintext || len(s.Ledger.Randomness) != len(a.SealedLocks) || seals != len(a.SealedLocks) {
			return nil, bad
		}
		a.Sealed, err = settle.RestorePrivate(*s.Ledger)
		if err != nil {
			return nil, bad
		}
		if len(a.PublicKey) == 0 {
			a.PublicKey = a.Sealed.PublicModulus()
		} else if !bytes.Equal(a.PublicKey, a.Sealed.PublicModulus()) {
			return nil, bad
		}
		if a.Scheme == "" {
			a.Scheme = SchemePaillier
		} else if a.Scheme != SchemePaillier {
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
			if len(a.SealedAggregate) > 0 && !bytes.Equal(a.SealedAggregate, sum) {
				return nil, bad
			}
			// Legacy accepted snapshots clear SealedSum. Keep the recomputed
			// aggregate for the public proof bundle.
			a.SealedAggregate = append([]byte(nil), sum...)
		} else if len(a.SealedSum) != 0 || len(a.SealedAggregate) != 0 {
			return nil, bad
		}
	} else if a.sealedPath() {
		return nil, bad
	}
	return &a, nil
}
