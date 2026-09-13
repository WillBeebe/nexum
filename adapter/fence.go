package adapter

import (
	"bytes"
	"crypto/rand"
	"sync"
)

type Fence struct {
	Version    int
	Generation uint64
	Owner      string
	Token      []byte
}

type Checkpoint struct {
	Head       string
	Generation uint64
}

// Coordinator is a synthetic, independently issued fencing authority.
// A token copied from the store is not sufficient.
type Coordinator struct {
	mu          sync.Mutex
	generation  uint64
	token       []byte
	owner       string
	fenced      bool
	fenceProven bool
	checkpoint  Checkpoint
	activeOwner string
}

func (c *Coordinator) Current() (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation == 0 || len(c.token) == 0 {
		return Fence{}, ErrFenced
	}
	return Fence{Version: Version, Generation: c.generation, Owner: c.owner, Token: append([]byte(nil), c.token...)}, nil
}

func (c *Coordinator) Issue(owner string) (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.issueLocked(owner)
}

func (c *Coordinator) issueLocked(owner string) (Fence, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return Fence{}, err
	}
	c.generation++
	c.token = token
	c.owner = owner
	c.fenced = false
	c.fenceProven = true
	c.activeOwner = owner
	return Fence{Version: Version, Generation: c.generation, Owner: owner, Token: append([]byte(nil), token...)}, nil
}

func (c *Coordinator) RecordCheckpoint(head string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkpoint = Checkpoint{Head: head, Generation: c.generation}
}

func (c *Coordinator) StopAndFence(owner string) (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeOwner != owner {
		return Fence{}, ErrFenced
	}
	c.fenced = true
	c.fenceProven = true
	c.activeOwner = ""
	return Fence{Version: Version, Generation: c.generation, Owner: owner, Token: append([]byte(nil), c.token...)}, nil
}

func (c *Coordinator) DisableFenceProof() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fenceProven = false
}

func (c *Coordinator) Activate(newOwner, observedHead string) (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fenceProven {
		return Fence{}, ErrActivation
	}
	if !c.fenced {
		return Fence{}, ErrActivation
	}
	if observedHead != c.checkpoint.Head || c.checkpoint.Generation != c.generation {
		return Fence{}, ErrActivation
	}
	return c.issueLocked(newOwner)
}

// Owner is one compute host bound to a fence token at every mutation.
type Owner struct {
	ID        string
	Fence     Fence
	Active    bool
	Inner     Authority
	Admission bool
}

func (o *Owner) Submit(env RoutingEnvelope, fence Fence) (AuthenticatedResponse, error) {
	base := AuthenticatedResponse{Version: Version, Tenant: env.Item.Tenant, AgreementID: env.Item.AgreementID, RequestID: env.Item.OperationID, CommandHash: CommandHash(env.Item.SignedObject), Kind: ResultRefused}
	if o == nil || !o.Active || o.Inner == nil {
		base.Error = ErrFenced.Error()
		return base, ErrFenced
	}
	if env.Generation != o.Fence.Generation {
		base.Error = ErrFenced.Error()
		return base, ErrFenced
	}
	if fence.Generation != o.Fence.Generation || !bytes.Equal(fence.Token, o.Fence.Token) || fence.Owner != o.ID {
		base.Error = ErrFenced.Error()
		return base, ErrFenced
	}
	return o.Inner.Apply(env.Item)
}

func (o *Owner) Deactivate() { o.Active = false; o.Admission = false }

func BindOwner(id string, fence Fence, inner Authority) *Owner {
	return &Owner{ID: id, Fence: fence, Active: true, Inner: inner, Admission: true}
}

func ActivateReplacement(coord *Coordinator, src *Owner, newID, observedHead string, inner Authority) (*Owner, error) {
	if src != nil && src.Active {
		return nil, ErrConcurrentOwner
	}
	fence, err := coord.Activate(newID, observedHead)
	if err != nil {
		return nil, err
	}
	return BindOwner(newID, fence, inner), nil
}

func FencesEqual(a, b Fence) bool {
	return a.Generation == b.Generation && a.Owner == b.Owner && bytes.Equal(a.Token, b.Token)
}
