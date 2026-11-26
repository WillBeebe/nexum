package nex

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"unicode/utf8"
)

// AccordStep builds one command inside AccordStore.Transact from the latest
// in-batch AccordView. Returning apply=false skips the step.
type AccordStep func(view AccordView) (cmd AccordCommand, signature []byte, apply bool, err error)

type storedAccord struct {
	Version int          `json:"version"`
	Bundle  AccordBundle `json:"bundle"`
	Head    string       `json:"head"`
}

type cachedAccord struct {
	meta            checkpointMeta
	plainDigest     [32]byte
	spec            AccordSpec
	events          []AccordEvent
	view            AccordView
	evidenceByID    map[string]EvidenceSlot
	roleVoterCount  map[string]uint64
	roleVoterWeight map[string]uint64
}

// AccordStore persists Accord histories through AES-256-GCM authenticated
// local checkpoints, per-accord OS file locks, and a bounded 256-entry cache.
// Use a separate private directory from Contract, Protocol, Goal, and Coordination stores.
type AccordStore struct {
	store      *Store
	mu         sync.Mutex
	cache      map[string]cachedAccord
	cacheOrder []string
}

// OpenAccordStore opens or creates a private (0700) encrypted Accord store.
func OpenAccordStore(dir string, key []byte) (*AccordStore, error) {
	s, err := OpenStore(dir, key)
	if err != nil {
		return nil, err
	}
	return &AccordStore{store: s, cache: make(map[string]cachedAccord)}, nil
}

// Stats returns lock, encrypted checkpoint read/write, AEAD decrypt, replay
// validation, cache, and directory sync counters.
func (s *AccordStore) Stats() StoreStats {
	if s == nil || s.store == nil {
		return StoreStats{}
	}
	return s.store.Stats()
}

// loadLocked authenticates and loads accord id; callers MUST hold s.store.withLocked(id, ...).
func (s *AccordStore) loadLocked(tx checkpointTx, id string) (*Accord, error) {
	plainJSON, meta, err := s.store.readEncryptedWithMeta(tx, id)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(plainJSON) {
		return nil, ErrCorruptStore
	}
	plainDigest := sha256.Sum256(plainJSON)

	s.mu.Lock()
	entry, hit := s.cache[id]
	s.mu.Unlock()
	if hit && entry.meta.same(meta) && entry.plainDigest == plainDigest {
		s.store.cacheHits.Add(1)
		return restoreCachedAccord(entry), nil
	}

	s.store.cacheMisses.Add(1)
	s.store.replayValidationOps.Add(1)

	var rec storedAccord
	if json.Unmarshal(plainJSON, &rec) != nil || rec.Version != accordStoreVersion {
		return nil, ErrCorruptStore
	}
	a, err := replayAccordBundle(rec.Bundle, id, rec.Head)
	if err != nil {
		return nil, ErrCorruptStore
	}

	s.mu.Lock()
	if _, existed := s.cache[id]; !existed {
		if len(s.cacheOrder) >= maxCachedAccords*2 {
			compacted := s.cacheOrder[:0]
			seen := make(map[string]struct{}, len(s.cache))
			for _, k := range s.cacheOrder {
				if _, live := s.cache[k]; live {
					if _, dup := seen[k]; !dup {
						seen[k] = struct{}{}
						compacted = append(compacted, k)
					}
				}
			}
			s.cacheOrder = compacted
		}
		for len(s.cache) >= maxCachedAccords && len(s.cacheOrder) > 0 {
			evict := s.cacheOrder[0]
			s.cacheOrder = s.cacheOrder[1:]
			delete(s.cache, evict)
		}
		s.cacheOrder = append(s.cacheOrder, id)
	}
	s.cache[id] = snapshotCachedAccord(meta, plainDigest, a)
	s.mu.Unlock()
	return a, nil
}

func snapshotCachedAccord(meta checkpointMeta, plainDigest [32]byte, a *Accord) cachedAccord {
	evMap := make(map[string]EvidenceSlot, len(a.evidenceByID))
	for k, v := range a.evidenceByID {
		evMap[k] = v
	}
	rcMap := make(map[string]uint64, len(a.roleVoterCount))
	for k, v := range a.roleVoterCount {
		rcMap[k] = v
	}
	rwMap := make(map[string]uint64, len(a.roleVoterWeight))
	for k, v := range a.roleVoterWeight {
		rwMap[k] = v
	}
	return cachedAccord{
		meta:            meta,
		plainDigest:     plainDigest,
		spec:            cloneAccordSpec(a.spec),
		events:          cloneAccordEvents(a.events),
		view:            cloneAccordView(a.view),
		evidenceByID:    evMap,
		roleVoterCount:  rcMap,
		roleVoterWeight: rwMap,
	}
}

func restoreCachedAccord(entry cachedAccord) *Accord {
	evMap := make(map[string]EvidenceSlot, len(entry.evidenceByID))
	for k, v := range entry.evidenceByID {
		evMap[k] = v
	}
	rcMap := make(map[string]uint64, len(entry.roleVoterCount))
	for k, v := range entry.roleVoterCount {
		rcMap[k] = v
	}
	rwMap := make(map[string]uint64, len(entry.roleVoterWeight))
	for k, v := range entry.roleVoterWeight {
		rwMap[k] = v
	}
	return &Accord{
		spec:            cloneAccordSpec(entry.spec),
		events:          cloneAccordEvents(entry.events),
		view:            cloneAccordView(entry.view),
		evidenceByID:    evMap,
		roleVoterCount:  rcMap,
		roleVoterWeight: rwMap,
	}
}

// invalidateCacheLocked drops the cached entry for id. Callers MUST hold s.store.withLock(id, ...).
func (s *AccordStore) invalidateCacheLocked(id string) {
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
}

// Create validates and inserts a new Accord. Existing IDs are rejected with ErrExists.
func (s *AccordStore) Create(spec AccordSpec) (string, error) {
	a, err := NewAccord(spec)
	if err != nil {
		return "", err
	}
	v := a.View()
	err = s.store.withLocked(v.ID, func(tx checkpointTx) error {
		exists, err := tx.exists(v.ID)
		if err != nil {
			return err
		}
		if exists {
			return ErrExists
		}
		s.invalidateCacheLocked(v.ID)
		return s.store.writeWith(tx, v.ID, storedAccord{
			Version: accordStoreVersion,
			Bundle:  a.Bundle(),
			Head:    v.Head,
		})
	})
	return v.ID, err
}

// View returns a durable, detached AccordView after confirming durability.
func (s *AccordStore) View(id string) (AccordView, error) {
	var v AccordView
	err := s.store.withLocked(id, func(tx checkpointTx) error {
		a, err := s.loadLocked(tx, id)
		if err != nil {
			return err
		}
		if err = s.store.syncDir(); err != nil {
			return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
		}
		v = a.View()
		return nil
	})
	return v, err
}

// Prepare builds a command skeleton pinned to the stored Accord's current Head.
func (s *AccordStore) Prepare(id, actor, grant, scope, action, requestID string, height uint64) (AccordCommand, error) {
	v, err := s.View(id)
	if err != nil {
		return AccordCommand{}, err
	}
	return AccordCommand{
		RequestID: requestID,
		AccordID:  id,
		Head:      v.Head,
		Actor:     actor,
		GrantID:   grant,
		Scope:     scope,
		Action:    action,
		Height:    height,
	}, nil
}

// Apply verifies and durably commits one signed AccordCommand. Exact retries of
// already-committed signed commands confirm durability and return
// their original receipt hash without overwriting the current checkpoint.
func (s *AccordStore) Apply(id string, cmd AccordCommand, signature []byte, height uint64) (string, error) {
	var head string
	err := s.store.withLocked(id, func(tx checkpointTx) error {
		a, err := s.loadLocked(tx, id)
		if err != nil {
			return err
		}
		prior := a.View().Head
		head, err = a.Apply(cmd, signature, height)
		if err != nil {
			return err
		}
		v := a.View()
		if v.Head == prior {
			if err = s.store.syncDir(); err != nil {
				return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
			}
			return nil
		}
		s.invalidateCacheLocked(id)
		return s.store.writeWith(tx, id, storedAccord{
			Version: accordStoreVersion,
			Bundle:  a.Bundle(),
			Head:    v.Head,
		})
	})
	return head, err
}

// Export confirms durability and returns a detached offline-verifiable AccordBundle.
func (s *AccordStore) Export(id string) (AccordBundle, error) {
	var b AccordBundle
	err := s.store.withLocked(id, func(tx checkpointTx) error {
		a, err := s.loadLocked(tx, id)
		if err != nil {
			return err
		}
		if err = s.store.syncDir(); err != nil {
			return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
		}
		b = a.Bundle()
		return nil
	})
	return b, err
}

// Transact executes multiple signed steps atomically under the per-accord
// lock, persisting at most one checkpoint replacement if the head advances.
func (s *AccordStore) Transact(id string, height uint64, steps ...AccordStep) (AccordView, error) {
	var out AccordView
	err := s.store.withLocked(id, func(tx checkpointTx) error {
		a, err := s.loadLocked(tx, id)
		if err != nil {
			return err
		}
		prior := a.View().Head
		for _, step := range steps {
			if step == nil {
				continue
			}
			cmd, sig, applyStep, err := step(a.View())
			if err != nil {
				return err
			}
			if !applyStep {
				continue
			}
			if _, err := a.Apply(cmd, sig, height); err != nil {
				return err
			}
		}
		v := a.View()
		if v.Head == prior {
			if err = s.store.syncDir(); err != nil {
				return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
			}
			out = v
			return nil
		}
		s.invalidateCacheLocked(id)
		if err := s.store.writeWith(tx, id, storedAccord{
			Version: accordStoreVersion,
			Bundle:  a.Bundle(),
			Head:    v.Head,
		}); err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}
