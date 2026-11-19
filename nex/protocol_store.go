package nex

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ProtocolStore persists agreement/delegation histories through the existing
// authenticated local storage and OS-lock implementation. Use a directory
// separate from legacy Contract storage. No resource budget or currency is
// required to enter, execute, or complete a Protocol.
const maxCachedProtocols = 256

type ProtocolStore struct {
	store      *Store
	mu         sync.Mutex
	cache      map[string]cachedProtocol
	cacheOrder []string
}

type cachedProtocol struct {
	info        os.FileInfo
	plainDigest [32]byte // SHA-256 of AES-256-GCM-authenticated storedProtocol JSON plaintext read under s.store.withLock(id)
	spec        ProtocolSpec
	events      []ProtocolEvent
	view        ProtocolView
}

// ProtocolStep builds one command inside Transact from the latest in-batch ProtocolView. apply=false skips the step.
type ProtocolStep func(view ProtocolView) (cmd ProtocolCommand, signature []byte, apply bool, err error)

// The wrapper format is independent of the signed specification version.
const protocolStoreVersion = 1

type storedProtocol struct {
	Version int
	Bundle  ProtocolBundle
	Head    string
}

func OpenProtocolStore(dir string, key []byte) (*ProtocolStore, error) {
	s, err := OpenStore(dir, key)
	if err != nil {
		return nil, err
	}
	return &ProtocolStore{store: s, cache: make(map[string]cachedProtocol)}, nil
}

func (s *ProtocolStore) Stats() StoreStats {
	if s == nil || s.store == nil {
		return StoreStats{}
	}
	return s.store.Stats()
}

// loadLocked authenticates and loads protocol id; callers MUST hold s.store.withLock(id, ...) across the entire call.
func (s *ProtocolStore) loadLocked(id string) (*Protocol, error) {
	info, err := os.Lstat(s.store.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plainJSON, err := s.store.readEncrypted(id)
	if err != nil {
		return nil, err
	}
	plainDigest := sha256.Sum256(plainJSON)
	s.mu.Lock()
	entry, hit := s.cache[id]
	s.mu.Unlock()
	if hit && os.SameFile(entry.info, info) && entry.info.ModTime().Equal(info.ModTime()) && entry.info.Size() == info.Size() && entry.plainDigest == plainDigest {
		s.store.cacheHits.Add(1)
		return &Protocol{spec: cloneProtocol(entry.spec), events: cloneProtocol(entry.events), view: cloneProtocol(entry.view)}, nil
	}
	s.store.cacheMisses.Add(1)
	s.store.replayValidationOps.Add(1)
	var r storedProtocol
	if json.Unmarshal(plainJSON, &r) != nil || r.Version != protocolStoreVersion {
		return nil, ErrCorruptStore
	}
	p, err := replayProtocolBundle(r.Bundle, id, r.Head)
	if err != nil {
		return nil, ErrCorruptStore
	}
	s.mu.Lock()
	if _, existed := s.cache[id]; !existed {
		if len(s.cacheOrder) >= maxCachedProtocols*2 {
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
		for len(s.cache) >= maxCachedProtocols && len(s.cacheOrder) > 0 {
			evict := s.cacheOrder[0]
			s.cacheOrder = s.cacheOrder[1:]
			delete(s.cache, evict)
		}
		s.cacheOrder = append(s.cacheOrder, id)
	}
	s.cache[id] = cachedProtocol{info: info, plainDigest: plainDigest, spec: cloneProtocol(p.spec), events: cloneProtocol(p.events), view: cloneProtocol(p.view)}
	s.mu.Unlock()
	return p, nil
}

// invalidateCacheLocked drops the in-memory entry for id. Callers MUST hold s.store.withLock(id, ...).
func (s *ProtocolStore) invalidateCacheLocked(id string) {
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
}

func (s *ProtocolStore) Create(spec ProtocolSpec) (string, error) {
	p, err := NewProtocol(spec)
	if err != nil {
		return "", err
	}
	v := p.View()
	err = s.store.withLock(v.ID, func() error {
		if _, err := os.Lstat(s.store.path(v.ID)); err == nil {
			return ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		s.invalidateCacheLocked(v.ID)
		return s.store.write(v.ID, storedProtocol{protocolStoreVersion, p.Bundle(), v.Head})
	})
	return v.ID, err
}
func (s *ProtocolStore) View(id string) (ProtocolView, error) {
	var v ProtocolView
	err := s.store.withLock(id, func() error {
		p, err := s.loadLocked(id)
		if err != nil {
			return err
		}
		if err = s.store.syncDir(); err != nil {
			return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
		}
		v = p.View()
		return nil
	})
	return v, err
}
func (s *ProtocolStore) Prepare(id, actor, grant, scope, action, request string, height uint64) (ProtocolCommand, error) {
	v, err := s.View(id)
	if err != nil {
		return ProtocolCommand{}, err
	}
	return ProtocolCommand{ProtocolID: id, Head: v.Head, Actor: actor, GrantID: grant, Scope: scope, Action: action, RequestID: request, Height: height}, nil
}
func (s *ProtocolStore) Apply(id string, c ProtocolCommand, signature []byte, height uint64) (string, error) {
	return s.apply(id, c, signature, height, false)
}

// ApplyV1 is the compatibility path for relays that have no authoritative
// height source. It cannot advance a version 2 agreement.
func (s *ProtocolStore) ApplyV1(id string, c ProtocolCommand, signature []byte, height uint64) (string, error) {
	return s.apply(id, c, signature, height, true)
}

func (s *ProtocolStore) apply(id string, c ProtocolCommand, signature []byte, height uint64, v1Only bool) (string, error) {
	var head string
	err := s.store.withLock(id, func() error {
		p, err := s.loadLocked(id)
		if err != nil {
			return err
		}
		if v1Only && p.spec.Version != ProtocolVersion {
			return ErrProtocolAuthority
		}
		prior := p.View().Head
		head, err = p.Apply(c, signature, height)
		if err != nil {
			return err
		}
		if head == prior {
			if err = s.store.syncDir(); err != nil {
				return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
			}
			return nil
		}
		// Exact retry of an older command can return an older receipt. Persist only
		// if the actual current state advanced, never overwrite with that old head.
		v := p.View()
		if v.Head == prior {
			// An older event can still be an exact retry. A failed directory
			// sync is durability uncertainty, not a definitive refusal.
			if err = s.store.syncDir(); err != nil {
				return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
			}
			return nil
		}
		s.invalidateCacheLocked(id)
		return s.store.write(id, storedProtocol{protocolStoreVersion, p.Bundle(), v.Head})
	})
	return head, err
}
func (s *ProtocolStore) Export(id string) (ProtocolBundle, error) {
	var b ProtocolBundle
	err := s.store.withLock(id, func() error {
		p, err := s.loadLocked(id)
		if err != nil {
			return err
		}
		if err = s.store.syncDir(); err != nil {
			return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
		}
		b = p.Bundle()
		return nil
	})
	return b, err
}

func (s *ProtocolStore) Transact(id string, height uint64, steps ...ProtocolStep) (ProtocolView, error) {
	var out ProtocolView
	err := s.store.withLock(id, func() error {
		p, err := s.loadLocked(id)
		if err != nil {
			return err
		}
		prior := p.View().Head
		for _, step := range steps {
			if step == nil {
				continue
			}
			cmd, sig, applyStep, err := step(p.View())
			if err != nil {
				return err
			}
			if !applyStep {
				continue
			}
			if _, err := p.Apply(cmd, sig, height); err != nil {
				return err
			}
		}
		v := p.View()
		if v.Head == prior {
			if err = s.store.syncDir(); err != nil {
				return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
			}
			out = v
			return nil
		}
		s.invalidateCacheLocked(id)
		if err := s.store.write(id, storedProtocol{protocolStoreVersion, p.Bundle(), v.Head}); err != nil {
			return err
		}
		out = v
		return nil
	})
	return out, err
}
