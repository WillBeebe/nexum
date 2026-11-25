package adapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"math"
	"strings"
	"sync"
)

const (
	coordinatorGateFile = "coordinator.gate"
	coordinatorGateAAD  = vaultHeader + "/coordinator.gate/v1"
	coordinatorLockFile = "coordinator.lock"
)

const (
	coordStateUnissued       = "unissued"
	coordStateActive         = "active"
	coordStateFencedUnproven = "fenced_unproven"
	coordStateFencedProven   = "fenced_proven"
)

const (
	coordAdmissionOpen    = "open"
	coordAdmissionStopped = "stopped"
)

type coordinatorRecord struct {
	Version     int        `json:"version"`
	State       string     `json:"state"`
	Generation  uint64     `json:"generation"`
	OwnerID     string     `json:"owner_id"`
	TokenSHA256 [32]byte   `json:"token_sha256"`
	Token       []byte     `json:"token"`
	Checkpoint  Checkpoint `json:"checkpoint"`
	FenceProof  bool       `json:"fence_proof"`
	Admission   string     `json:"admission"`
}

// DurableCoordinator is a single-host, multi-process crash-safe fencing
// authority backed by an AEAD-authenticated vault file (coordinator.gate) and
// OS advisory file locking.
type DurableCoordinator struct {
	vault  *vault
	cfgMu  sync.RWMutex
	scope  string
	sealer EpochSealer
}

var _ FenceCoordinator = (*DurableCoordinator)(nil)
var _ HandoffReady = (*DurableCoordinator)(nil)

// OpenCoordinator opens or initializes a durable coordinator in dir encrypted
// under the 32-byte key. Reopening an existing directory restores its exact
// persisted generation, state, checkpoint, and admission gate.
func OpenCoordinator(dir string, key []byte) (*DurableCoordinator, error) {
	v, err := openVault(dir, key)
	if err != nil {
		return nil, err
	}
	c := &DurableCoordinator{vault: v, scope: "default"}
	err = c.withLock(func() error {
		_, err := c.readOrInitLocked()
		return err
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// SetEpochSealer configures an optional destination epoch sealer invoked by
// StopAndFence and ConfirmFenceProof.
func (c *DurableCoordinator) SetEpochSealer(scope string, sealer EpochSealer) {
	if c == nil {
		return
	}
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	if strings.TrimSpace(scope) != "" {
		c.scope = scope
	}
	c.sealer = sealer
}

func (c *DurableCoordinator) sealerConfig() (string, EpochSealer) {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.scope, c.sealer
}

func (c *DurableCoordinator) withLock(fn func() error) error {
	if c == nil || c.vault == nil {
		return ErrItem
	}
	return c.vault.withNamedLock(coordinatorLockFile, fn)
}

func (c *DurableCoordinator) readOrInitLocked() (coordinatorRecord, error) {
	var rec coordinatorRecord
	err := c.vault.readNamed(coordinatorGateFile, coordinatorGateAAD, &rec)
	if errors.Is(err, ErrNotFound) {
		initRec := coordinatorRecord{
			Version:    Version,
			State:      coordStateUnissued,
			Generation: 0,
			Admission:  coordAdmissionStopped,
		}
		if err := c.writeLocked(initRec); err != nil {
			return coordinatorRecord{}, err
		}
		return initRec, nil
	}
	if err != nil {
		return coordinatorRecord{}, err
	}
	if err := validateCoordinatorRecord(rec); err != nil {
		return coordinatorRecord{}, err
	}
	return rec, nil
}

func (c *DurableCoordinator) readLocked() (coordinatorRecord, error) {
	var rec coordinatorRecord
	if err := c.vault.readNamed(coordinatorGateFile, coordinatorGateAAD, &rec); err != nil {
		return coordinatorRecord{}, err
	}
	if err := validateCoordinatorRecord(rec); err != nil {
		return coordinatorRecord{}, err
	}
	return rec, nil
}

func (c *DurableCoordinator) writeLocked(rec coordinatorRecord) error {
	rec.Version = Version
	if err := validateCoordinatorRecord(rec); err != nil {
		return err
	}
	return c.vault.writeNamed(coordinatorGateFile, coordinatorGateAAD, rec)
}

func validateCoordinatorRecord(rec coordinatorRecord) error {
	if rec.Version != Version {
		return ErrVersion
	}
	switch rec.Admission {
	case coordAdmissionOpen, coordAdmissionStopped:
	default:
		return ErrCorrupt
	}
	switch rec.State {
	case coordStateUnissued:
		if rec.Generation != 0 || rec.OwnerID != "" || len(rec.Token) != 0 || rec.FenceProof || rec.Admission != coordAdmissionStopped || rec.Checkpoint.Set {
			return ErrCorrupt
		}
	case coordStateActive:
		if rec.Generation == 0 || validateID(rec.OwnerID) != nil || len(rec.Token) != 32 || rec.FenceProof {
			return ErrCorrupt
		}
		sum := sha256.Sum256(rec.Token)
		if subtle.ConstantTimeCompare(sum[:], rec.TokenSHA256[:]) != 1 {
			return ErrCorrupt
		}
	case coordStateFencedUnproven:
		if rec.Generation == 0 || validateID(rec.OwnerID) != nil || len(rec.Token) != 32 || rec.FenceProof || rec.Admission != coordAdmissionStopped {
			return ErrCorrupt
		}
		sum := sha256.Sum256(rec.Token)
		if subtle.ConstantTimeCompare(sum[:], rec.TokenSHA256[:]) != 1 {
			return ErrCorrupt
		}
	case coordStateFencedProven:
		if rec.Generation == 0 || validateID(rec.OwnerID) != nil || len(rec.Token) != 32 || !rec.FenceProof || rec.Admission != coordAdmissionStopped {
			return ErrCorrupt
		}
		sum := sha256.Sum256(rec.Token)
		if subtle.ConstantTimeCompare(sum[:], rec.TokenSHA256[:]) != 1 {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	if rec.Checkpoint.Set {
		if rec.Checkpoint.Head == "" || strings.TrimSpace(rec.Checkpoint.Head) == "" || rec.Checkpoint.Generation != rec.Generation {
			return ErrCorrupt
		}
	}
	return nil
}

func fenceFromRecord(rec coordinatorRecord) Fence {
	return Fence{
		Version:    Version,
		Generation: rec.Generation,
		Owner:      rec.OwnerID,
		Token:      append([]byte(nil), rec.Token...),
	}
}

func (c *DurableCoordinator) Current() (Fence, error) {
	if c == nil || c.vault == nil {
		return Fence{}, ErrFenced
	}
	var out Fence
	err := c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State != coordStateActive || rec.Generation == 0 || len(rec.Token) == 0 || rec.OwnerID == "" {
			return ErrFenced
		}
		out = fenceFromRecord(rec)
		return nil
	})
	return out, err
}

func (c *DurableCoordinator) Historical() (Fence, error) {
	if c == nil || c.vault == nil {
		return Fence{}, ErrFenced
	}
	var out Fence
	err := c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State != coordStateFencedProven && rec.State != coordStateFencedUnproven {
			return ErrFenced
		}
		if rec.Generation == 0 || len(rec.Token) == 0 {
			return ErrFenced
		}
		out = fenceFromRecord(rec)
		return nil
	})
	return out, err
}

func (c *DurableCoordinator) Admission() string {
	if c == nil || c.vault == nil {
		return coordAdmissionStopped
	}
	mode := coordAdmissionStopped
	_ = c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State == coordStateActive && rec.Admission == coordAdmissionOpen {
			mode = coordAdmissionOpen
		}
		return nil
	})
	return mode
}

func (c *DurableCoordinator) Issue(owner string) (Fence, error) {
	if err := validateID(owner); err != nil {
		return Fence{}, err
	}
	if c == nil || c.vault == nil {
		return Fence{}, ErrActivation
	}
	var out Fence
	err := c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.Generation >= 1 {
			if rec.State == coordStateActive {
				return ErrConcurrentOwner
			}
			return ErrActivation
		}
		if rec.State != coordStateUnissued {
			return ErrActivation
		}
		next, err := mintCoordinatorRecord(0, owner)
		if err != nil {
			return err
		}
		if err := c.writeLocked(next); err != nil {
			return err
		}
		out = fenceFromRecord(next)
		return nil
	})
	return out, err
}

func mintCoordinatorRecord(prevGen uint64, owner string) (coordinatorRecord, error) {
	if prevGen == math.MaxUint64 {
		return coordinatorRecord{}, ErrGenerationOverflow
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return coordinatorRecord{}, err
	}
	return coordinatorRecord{
		Version:     Version,
		State:       coordStateActive,
		Generation:  prevGen + 1,
		OwnerID:     owner,
		TokenSHA256: sha256.Sum256(token),
		Token:       token,
		Checkpoint:  Checkpoint{},
		FenceProof:  false,
		Admission:   coordAdmissionOpen,
	}, nil
}

func (c *DurableCoordinator) RecordCheckpoint(head string) error {
	if head == "" || strings.TrimSpace(head) == "" {
		return ErrActivation
	}
	if c == nil || c.vault == nil {
		return ErrFenced
	}
	return c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State != coordStateActive || rec.Generation == 0 {
			return ErrFenced
		}
		rec.Checkpoint = Checkpoint{Head: head, Generation: rec.Generation, Set: true}
		return c.writeLocked(rec)
	})
}

func (c *DurableCoordinator) StopAdmission() error {
	if c == nil || c.vault == nil {
		return ErrFenced
	}
	return c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State == coordStateUnissued || rec.Generation == 0 {
			return ErrFenced
		}
		if rec.Admission == coordAdmissionStopped {
			return nil
		}
		rec.Admission = coordAdmissionStopped
		return c.writeLocked(rec)
	})
}

func (c *DurableCoordinator) Resume() error {
	if c == nil || c.vault == nil {
		return ErrFenced
	}
	return c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State != coordStateActive || rec.Generation == 0 {
			return ErrFenced
		}
		if rec.Admission != coordAdmissionStopped {
			return ErrActivation
		}
		rec.Admission = coordAdmissionOpen
		return c.writeLocked(rec)
	})
}

func (c *DurableCoordinator) StopAndFence(owner string) (Fence, error) {
	return c.StopAndFenceContext(context.Background(), owner)
}

func (c *DurableCoordinator) StopAndFenceContext(ctx context.Context, owner string) (Fence, error) {
	if err := validateID(owner); err != nil {
		return Fence{}, err
	}
	if c == nil || c.vault == nil {
		return Fence{}, ErrFenced
	}
	if ctx == nil {
		ctx = context.Background()
	}
	scope, sealer := c.sealerConfig()
	if sealer == nil {
		var out Fence
		err := c.withLock(func() error {
			rec, err := c.readLocked()
			if err != nil {
				return err
			}
			if rec.State != coordStateActive || rec.Generation == 0 || rec.OwnerID != owner {
				return ErrFenced
			}
			rec.Admission = coordAdmissionStopped
			rec.State = coordStateFencedProven
			rec.FenceProof = true
			if err := c.writeLocked(rec); err != nil {
				return err
			}
			out = fenceFromRecord(rec)
			return nil
		})
		return out, err
	}

	var (
		fencedGen uint64
		out       Fence
	)
	err := c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State != coordStateActive || rec.Generation == 0 || rec.OwnerID != owner {
			return ErrFenced
		}
		rec.Admission = coordAdmissionStopped
		rec.State = coordStateFencedUnproven
		rec.FenceProof = false
		if err := c.writeLocked(rec); err != nil {
			return err
		}
		fencedGen = rec.Generation
		out = fenceFromRecord(rec)
		return nil
	})
	if err != nil {
		return Fence{}, err
	}
	if err := sealer.SealFenceEpoch(ctx, scope, fencedGen); err != nil {
		return Fence{}, err
	}
	err = c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.Generation != fencedGen || rec.OwnerID != owner {
			return ErrFenced
		}
		if rec.State == coordStateFencedProven && rec.FenceProof {
			return nil
		}
		if rec.State != coordStateFencedUnproven {
			return ErrFenced
		}
		rec.State = coordStateFencedProven
		rec.FenceProof = true
		return c.writeLocked(rec)
	})
	if err != nil {
		return Fence{}, err
	}
	return out, nil
}

// ConfirmFenceProof completes epoch sealing for an unproven fenced generation
// so Activate can proceed once destinations have sealed the old generation.
func (c *DurableCoordinator) ConfirmFenceProof(owner string) error {
	return c.ConfirmFenceProofContext(context.Background(), owner)
}

func (c *DurableCoordinator) ConfirmFenceProofContext(ctx context.Context, owner string) error {
	if err := validateID(owner); err != nil {
		return err
	}
	if c == nil || c.vault == nil {
		return ErrActivation
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		gen           uint64
		alreadyProven bool
	)
	err := c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.Generation == 0 || rec.OwnerID != owner || rec.Admission != coordAdmissionStopped {
			return ErrActivation
		}
		if rec.State == coordStateFencedProven && rec.FenceProof {
			alreadyProven = true
			return nil
		}
		if rec.State != coordStateFencedUnproven {
			return ErrActivation
		}
		gen = rec.Generation
		return nil
	})
	if err != nil || alreadyProven {
		return err
	}
	if scope, sealer := c.sealerConfig(); sealer != nil {
		if err := sealer.SealFenceEpoch(ctx, scope, gen); err != nil {
			return err
		}
	}
	return c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.Generation != gen || rec.OwnerID != owner || rec.Admission != coordAdmissionStopped {
			return ErrActivation
		}
		if rec.State == coordStateFencedProven && rec.FenceProof {
			return nil
		}
		if rec.State != coordStateFencedUnproven {
			return ErrActivation
		}
		rec.State = coordStateFencedProven
		rec.FenceProof = true
		return c.writeLocked(rec)
	})
}

// DisableFenceProof drops proof on a fenced generation so takeover remains
// refused until ConfirmFenceProof succeeds.
func (c *DurableCoordinator) DisableFenceProof() error {
	if c == nil || c.vault == nil {
		return ErrActivation
	}
	return c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		rec.FenceProof = false
		if rec.State == coordStateFencedProven {
			rec.State = coordStateFencedUnproven
		}
		return c.writeLocked(rec)
	})
}

func (c *DurableCoordinator) Activate(newOwner, observedHead string) (Fence, error) {
	if err := validateID(newOwner); err != nil {
		return Fence{}, err
	}
	if observedHead == "" {
		return Fence{}, ErrActivation
	}
	if c == nil || c.vault == nil {
		return Fence{}, ErrActivation
	}
	var out Fence
	err := c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.Generation == 0 || rec.State == coordStateUnissued {
			return ErrActivation
		}
		if rec.State != coordStateFencedProven || !rec.FenceProof || rec.Admission != coordAdmissionStopped {
			return ErrActivation
		}
		if !rec.Checkpoint.Set || rec.Checkpoint.Head == "" || rec.Checkpoint.Generation != rec.Generation || observedHead != rec.Checkpoint.Head {
			return ErrActivation
		}
		next, err := mintCoordinatorRecord(rec.Generation, newOwner)
		if err != nil {
			return err
		}
		if err := c.writeLocked(next); err != nil {
			return err
		}
		out = fenceFromRecord(next)
		return nil
	})
	return out, err
}

func (c *DurableCoordinator) Authorize(fence Fence, fn func() error) error {
	if c == nil || c.vault == nil || fn == nil {
		return ErrItem
	}
	return c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State != coordStateActive || rec.Generation == 0 || len(rec.Token) != 32 {
			return ErrFenced
		}
		sum := sha256.Sum256(fence.Token)
		if fence.Generation != rec.Generation || fence.Owner != rec.OwnerID || len(fence.Token) != 32 || subtle.ConstantTimeCompare(sum[:], rec.TokenSHA256[:]) != 1 {
			return ErrFenced
		}
		if rec.Admission != coordAdmissionOpen {
			return ErrAdmissionStopped
		}
		return fn()
	})
}

// ReadyForHandoff reports whether this coordinator is fenced with proof,
// stopped for admission, and holding a non-empty checkpoint head for the
// fenced generation.
func (c *DurableCoordinator) ReadyForHandoff() error {
	if c == nil || c.vault == nil {
		return ErrActivation
	}
	return c.withLock(func() error {
		rec, err := c.readLocked()
		if err != nil {
			return err
		}
		if rec.State != coordStateFencedProven || !rec.FenceProof || rec.Admission != coordAdmissionStopped {
			return ErrActivation
		}
		if !rec.Checkpoint.Set || rec.Checkpoint.Head == "" || rec.Checkpoint.Generation != rec.Generation {
			return ErrActivation
		}
		return nil
	})
}
