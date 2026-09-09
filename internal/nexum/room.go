package nexum

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/WillBeebe/nexum/internal/settle"
)

// Move is one agent step in a Room two-agent escrow. The kernel
// applies it. A takeback after lock/accept must fail.
type Move struct {
	Actor   Party  `json:"actor"`
	Action  string `json:"action"`            // lock | seal | accept | reject | takeback
	Partial int64  `json:"partial,omitempty"` // sealed path: the partial amount, encrypted at the seal boundary
}

// Apply runs one Room move. takeback is never a legal transition:
// it must return ErrTakeback or ErrBadState. A nil error on
// takeback means the kernel is broken.
func (a *Agreement) Apply(m Move, now time.Time) error {
	switch m.Action {
	case "lock":
		return a.Lock(m.Actor, now)
	case "seal":
		return a.sealLock(m.Actor, m.Partial, now)
	case "accept":
		return a.Accept(m.Actor, now)
	case "reject":
		return a.Reject(m.Actor, now)
	case "takeback":
		err := a.takeback(m.Actor, now)
		if err == nil {
			return fmt.Errorf("nexum: takeback succeeded — kernel broken")
		}
		return err
	default:
		return fmt.Errorf("nexum: unknown action %q", m.Action)
	}
}

// isSealed reports whether this escrow runs on ciphertext.
func (a *Agreement) isSealed() bool {
	return a.Sealed != nil
}

// sealLock is the sealed-path lock point: the buyer's partial amount
// is encrypted at this boundary and only ciphertext is stored. The
// kernel never holds a plaintext partial. After the first seal the
// escrow is locked — the buyer cannot unwind (no takeback).
func (a *Agreement) sealLock(actor Party, partial int64, now time.Time) error {
	if actor != a.Buyer {
		return ErrWrongParty
	}
	if a.terminal() {
		return ErrTakeback
	}
	if a.Sealed == nil {
		return ErrNoSeal
	}
	ledger := a.Sealed.Clone()
	ct, err := ledger.SealLock(partial)
	if err != nil {
		return err
	}
	locks := append(append([][]byte(nil), a.SealedLocks...), ct)
	sum, err := ledger.Aggregate(locks)
	if err != nil {
		return err
	}
	// Commit only after encryption, aggregation and receipt checks succeed.
	if err := a.append(actor, "seal", base64.StdEncoding.EncodeToString(ct), now); err != nil {
		return err
	}
	a.Sealed = ledger
	a.SealedLocks = locks
	a.SealedSum = sum
	a.Status = StatusLocked
	t := now.UTC()
	a.LockedAt = &t
	return nil
}

// acceptSealed releases the sealed value to the seller. The accept/reject
// branch runs on CIPHERTEXT (equality proof): the ledger builds a zero-knowledge
// equality proof that the aggregate encrypts the committed Amount, and the
// kernel verifies it with the public key only. No decrypt on this path.
// Proof failure, tamper or empty fails closed with no state change.
func (a *Agreement) acceptSealed(actor Party, now time.Time) error {
	if actor != a.Seller {
		return ErrWrongParty
	}
	if a.terminal() {
		return ErrTakeback
	}
	if a.Status != StatusLocked || len(a.SealedLocks) == 0 {
		return ErrBadState
	}
	proof, err := a.Sealed.ProveEqual(a.SealedSum, a.Amount)
	if err != nil {
		return err // fail closed: status unchanged, nothing settles
	}
	ok, err := a.Sealed.VerifyEqual(a.SealedSum, a.Amount, proof)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: equality proof rejected on ciphertext", settle.ErrSumMismatch)
	}
	// The proof is public (no plaintext inside): it rides the receipt so
	// any fleet node or auditor can re-branch the accept with the public
	// key. The committed Amount is contract terms, not a sealed value.
	note := fmt.Sprintf("sealed sum == committed %d via zk equality proof (no decrypt); proof: %s",
		a.Amount, base64.StdEncoding.EncodeToString(proof))
	if err := a.append(actor, "accept", note, now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Seller
	a.Status = StatusAccepted
	a.SealedSum = nil // branch-once: a second release must refuse
	return nil
}

// rejectSealed returns the sealed value to the buyer WITHOUT
// decrypting: the aggregate stays sealed, the buyer unwinds on
// their side. The kernel sees no plaintext on the reject path.
func (a *Agreement) rejectSealed(actor Party, now time.Time) error {
	if actor != a.Seller {
		return ErrWrongParty
	}
	if a.terminal() {
		return ErrTakeback
	}
	if a.Status != StatusLocked {
		return ErrBadState
	}
	if err := a.append(actor, "reject", "returned to buyer (sum stays sealed)", now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Buyer
	a.Status = StatusRejected
	return nil
}

// StartSealed arms this escrow for ciphertext settlement with an
// `bits`-bit Paillier ledger. Call after OpenEscrow, before any move.
func (a *Agreement) StartSealed(bits int) error {
	if a.Status != StatusOpen {
		return ErrBadState
	}
	l, err := settle.NewEncryptedLedger(bits)
	if err != nil {
		return err
	}
	a.Sealed = l
	return nil
}

func (a *Agreement) takeback(actor Party, now time.Time) error {
	// Buyer trying to unwind after lock, or anyone after terminal.
	if a.terminal() {
		return ErrTakeback
	}
	if a.Status == StatusLocked && actor == a.Buyer {
		return ErrTakeback
	}
	return ErrBadState
}
