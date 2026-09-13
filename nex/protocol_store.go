package nex

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// ProtocolStore persists agreement/delegation histories through the existing
// authenticated local storage and OS-lock implementation. Use a directory
// separate from legacy Contract storage. No resource budget or currency is
// required to enter, execute, or complete a Protocol.
type ProtocolStore struct{ store *Store }
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
	return &ProtocolStore{s}, nil
}
func (s *ProtocolStore) load(id string) (*Protocol, error) {
	raw, err := s.store.readEncrypted(id)
	if err != nil {
		return nil, err
	}
	var r storedProtocol
	if json.Unmarshal(raw, &r) != nil || r.Version != ProtocolVersion {
		return nil, ErrCorruptStore
	}
	if _, err = VerifyProtocolBundle(r.Bundle, id, r.Head); err != nil {
		return nil, ErrCorruptStore
	}
	p, err := NewProtocol(r.Bundle.Spec)
	if err != nil {
		return nil, err
	}
	for _, e := range r.Bundle.Events {
		if _, err = p.Apply(e.Command, e.Signature, e.Command.Height); err != nil {
			return nil, ErrCorruptStore
		}
	}
	return p, nil
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
		return s.store.write(v.ID, storedProtocol{ProtocolVersion, p.Bundle(), v.Head})
	})
	return v.ID, err
}
func (s *ProtocolStore) View(id string) (ProtocolView, error) {
	var v ProtocolView
	err := s.store.withLock(id, func() error {
		p, err := s.load(id)
		if err != nil {
			return err
		}
		if err = syncDirectory(s.store.dir); err != nil {
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
	var head string
	err := s.store.withLock(id, func() error {
		p, err := s.load(id)
		if err != nil {
			return err
		}
		prior := p.View().Head
		head, err = p.Apply(c, signature, height)
		if err != nil {
			return err
		}
		if head == prior {
			if err = syncDirectory(s.store.dir); err != nil {
				return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
			}
			return nil
		}
		// Exact retry of an older command can return an older receipt. Persist only
		// if the actual current state advanced, never overwrite with that old head.
		v := p.View()
		if v.Head == prior {
			return syncDirectory(s.store.dir)
		}
		return s.store.write(id, storedProtocol{ProtocolVersion, p.Bundle(), v.Head})
	})
	return head, err
}
func (s *ProtocolStore) Export(id string) (ProtocolBundle, error) {
	var b ProtocolBundle
	err := s.store.withLock(id, func() error {
		p, err := s.load(id)
		if err != nil {
			return err
		}
		b = p.Bundle()
		return nil
	})
	return b, err
}
