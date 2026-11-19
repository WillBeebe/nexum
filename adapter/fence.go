package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
)

// ErrGenerationOverflow is returned when a new fence generation would wrap.
var ErrGenerationOverflow = errors.New("adapter: fence generation overflow")

type Fence struct {
	Version    int
	Generation uint64
	Owner      string
	Token      []byte
}

type Checkpoint struct {
	Head       string
	Generation uint64
	// Set is true only after RecordCheckpoint stores a non-empty head for
	// the current generation. The zero Checkpoint is not a checkpoint.
	Set bool
}

type leaseState int

const (
	leaseUnissued leaseState = iota
	leaseActive
	leaseFencedUnproven
	leaseFencedProven
)

type admissionState int

const (
	admissionOpen admissionState = iota
	admissionDraining
	admissionStopped
)

// AuthorityGuard is the check a destination calls at its mutation.
// Authorize holds the coordinator lock or shared row lock for the callback.
type AuthorityGuard interface {
	Authorize(fence Fence, fn func() error) error
}

// EpochSealer seals a fenced generation at external destinations before
// StopAndFence declares fence proof.
type EpochSealer interface {
	SealFenceEpoch(ctx context.Context, scope string, generation uint64) error
}

// FenceCoordinator is the lifecycle and mutation-authorization interface
// shared by in-memory Coordinator, vault-backed DurableCoordinator, and
// database-backed SQLCoordinator.
type FenceCoordinator interface {
	AuthorityGuard
	Current() (Fence, error)
	Historical() (Fence, error)
	Admission() string
	Issue(owner string) (Fence, error)
	RecordCheckpoint(head string) error
	StopAdmission() error
	Resume() error
	StopAndFence(owner string) (Fence, error)
	Activate(newOwner, observedHead string) (Fence, error)
}

type handoffReady interface {
	readyForHandoff() error
}

var _ FenceCoordinator = (*Coordinator)(nil)

// Coordinator is a synthetic, local, in-memory fencing authority.
// It cannot prove distributed fencing, anti-rollback, or that a fence
// survives coordinator process restart. A production durable coordinator
// is a separate integration. A token copied out of a store is not authority.
//
// Lock order: Coordinator.mu is held around the synchronous callback.
// Callbacks must not call back into Coordinator. Effect dispatch holds the
// vault lock and only then calls Authorize, so a callback must not call
// EffectAdapter.Apply either.
type Coordinator struct {
	mu            sync.Mutex
	state         leaseState
	generation    uint64
	token         []byte
	ownerID       string
	checkpoint    Checkpoint
	checkpointSet bool
	fenceProof    bool
	admission     admissionState
	inflight      int
	bound         []*Owner
}

func (c *Coordinator) Current() (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != leaseActive || c.generation == 0 || len(c.token) == 0 || c.ownerID == "" {
		return Fence{}, ErrFenced
	}
	return c.fenceLocked(), nil
}

// Historical returns the fenced generation's token for evidence.
// It does not authorize a mutation. Current is the only usable token.
func (c *Coordinator) Historical() (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != leaseFencedProven && c.state != leaseFencedUnproven {
		return Fence{}, ErrFenced
	}
	if c.generation == 0 || len(c.token) == 0 {
		return Fence{}, ErrFenced
	}
	return c.fenceLocked(), nil
}

// Admission reports open, draining, or stopped. Unissued and fenced
// coordinators report stopped. Draining is the stop that finishes the
// callback already inside Authorize; because that callback holds mu,
// a stop does not return while the callback is still running, and other
// callers observe stopped only after the stop call returns.
func (c *Coordinator) Admission() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.admission {
	case admissionDraining:
		return "draining"
	case admissionStopped:
		return "stopped"
	default:
		if c.state != leaseActive {
			return "stopped"
		}
		return "open"
	}
}

func (c *Coordinator) Issue(owner string) (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := validateID(owner); err != nil {
		return Fence{}, err
	}
	switch c.state {
	case leaseUnissued:
		if c.generation != 0 {
			return Fence{}, ErrActivation
		}
		return c.mintLocked(owner)
	case leaseActive:
		return Fence{}, ErrConcurrentOwner
	default:
		// Replacement is Activate, not a second Issue.
		return Fence{}, ErrActivation
	}
}

func (c *Coordinator) RecordCheckpoint(head string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if head == "" || strings.TrimSpace(head) == "" {
		return ErrActivation
	}
	if c.state != leaseActive || c.generation == 0 {
		return ErrFenced
	}
	c.checkpoint = Checkpoint{Head: head, Generation: c.generation, Set: true}
	c.checkpointSet = true
	return nil
}

// StopAdmission refuses new callbacks. An in-flight Authorize call is
// draining: it already passed the gate and runs to completion because it
// holds mu. This does not fence the generation and does not edit Outbox.
func (c *Coordinator) StopAdmission() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == leaseUnissued || c.generation == 0 {
		return ErrFenced
	}
	return c.drainLocked()
}

// Resume reopens admission for the still-active generation.
// It does not clear a fence or revive a stopped owner.
func (c *Coordinator) Resume() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != leaseActive || c.generation == 0 {
		return ErrFenced
	}
	if c.admission != admissionStopped || c.inflight != 0 {
		return ErrActivation
	}
	c.admission = admissionOpen
	c.projectAllLocked()
	return nil
}

func (c *Coordinator) StopAndFence(owner string) (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := validateID(owner); err != nil {
		return Fence{}, err
	}
	if c.state != leaseActive || c.generation == 0 || c.ownerID != owner {
		return Fence{}, ErrFenced
	}
	if err := c.drainLocked(); err != nil {
		return Fence{}, err
	}
	c.state = leaseFencedProven
	c.fenceProof = true
	// Leave Owner.Active set. Deactivate is the local handoff signal;
	// Submit fails from the coordinator state even when that flag stays true.
	return c.fenceLocked(), nil
}

// DisableFenceProof drops proof supplied by this coordinator.
// Activation stays refused until a later StopAndFence supplies it again.
func (c *Coordinator) DisableFenceProof() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fenceProof = false
	if c.state == leaseFencedProven {
		c.state = leaseFencedUnproven
	}
}

func (c *Coordinator) Activate(newOwner, observedHead string) (Fence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := validateID(newOwner); err != nil {
		return Fence{}, err
	}
	if c.generation == 0 || c.state == leaseUnissued {
		return Fence{}, ErrActivation
	}
	if c.state != leaseFencedProven || !c.fenceProof {
		return Fence{}, ErrActivation
	}
	if c.admission != admissionStopped || c.inflight != 0 {
		return Fence{}, ErrActivation
	}
	if !c.checkpointSet || !c.checkpoint.Set || c.checkpoint.Head == "" || c.checkpoint.Generation != c.generation || observedHead == "" || observedHead != c.checkpoint.Head {
		return Fence{}, ErrActivation
	}
	return c.mintLocked(newOwner)
}

// Authorize runs fn only for the active generation, holding c.mu the whole
// time. fn must not call back into Coordinator. A stopped coordinator
// refuses the call even when some Owner.Active copy is still true.
func (c *Coordinator) Authorize(fence Fence, fn func() error) error {
	if c == nil || fn == nil {
		return ErrItem
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.admitLocked(fence); err != nil {
		return err
	}
	c.inflight++
	defer func() { c.inflight-- }()
	return fn()
}

func (c *Coordinator) admitLocked(fence Fence) error {
	if c.state != leaseActive || c.generation == 0 || len(c.token) == 0 {
		return ErrFenced
	}
	if fence.Generation != c.generation || fence.Owner != c.ownerID || subtle.ConstantTimeCompare(fence.Token, c.token) != 1 {
		return ErrFenced
	}
	if c.admission != admissionOpen {
		return ErrAdmissionStopped
	}
	return nil
}

// drainLocked moves open admission to stopped. The callback already inside
// Authorize holds mu, so inflight is zero here and that callback has finished
// before StopAdmission or StopAndFence returns. New callers then see stopped,
// not draining. Draining stays a separate state so admitted work is not
// modeled as a fresh refusal.
func (c *Coordinator) drainLocked() error {
	if c.admission == admissionStopped && c.inflight == 0 {
		return nil
	}
	c.admission = admissionDraining
	if c.inflight != 0 {
		c.admission = admissionOpen
		return ErrActivation
	}
	c.admission = admissionStopped
	c.projectAllLocked()
	return nil
}

func (c *Coordinator) mintLocked(owner string) (Fence, error) {
	if c.generation == math.MaxUint64 {
		return Fence{}, ErrGenerationOverflow
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return Fence{}, err
	}
	c.generation++
	c.token = token
	c.ownerID = owner
	c.state = leaseActive
	c.fenceProof = false
	c.admission = admissionOpen
	c.inflight = 0
	c.checkpoint = Checkpoint{}
	c.checkpointSet = false
	c.projectAllLocked()
	return c.fenceLocked(), nil
}

func (c *Coordinator) fenceLocked() Fence {
	return Fence{Version: Version, Generation: c.generation, Owner: c.ownerID, Token: append([]byte(nil), c.token...)}
}

func (c *Coordinator) register(o *Owner) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bound = append(c.bound, o)
	c.projectLocked(o)
}

func (c *Coordinator) projectAllLocked() {
	for _, o := range c.bound {
		c.projectLocked(o)
	}
}

func (c *Coordinator) projectLocked(o *Owner) {
	if o == nil {
		return
	}
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	if o.isRetired() {
		o.Active = false
		o.Admission = false
		return
	}
	match := c.state == leaseActive && c.generation > 0 && o.ID == c.ownerID && o.Fence.Generation == c.generation && subtle.ConstantTimeCompare(o.Fence.Token, c.token) == 1
	o.Active = match
	o.Admission = match && c.admission == admissionOpen
}

func (c *Coordinator) readyForHandoff() error {
	if c == nil {
		return ErrActivation
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != leaseFencedProven || !c.fenceProof {
		return ErrActivation
	}
	if c.admission != admissionStopped || c.inflight != 0 {
		return ErrActivation
	}
	if !c.checkpointSet || !c.checkpoint.Set || c.checkpoint.Head == "" || c.checkpoint.Generation != c.generation {
		return ErrActivation
	}
	return nil
}

func isNilCoordinator(coord FenceCoordinator) bool {
	if coord == nil {
		return true
	}
	v := reflect.ValueOf(coord)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// HandoffCoordinatorDir copies src to dst only after coord is fenced with
// proof, stopped for admission, and holding a non-empty checkpoint head for
// the fenced generation.
func HandoffCoordinatorDir(coord FenceCoordinator, src, dst string) error {
	if isNilCoordinator(coord) {
		return ErrActivation
	}
	if hr, ok := coord.(handoffReady); ok {
		if err := hr.readyForHandoff(); err != nil {
			return err
		}
	} else {
		if _, err := coord.Historical(); err != nil || coord.Admission() != "stopped" {
			return ErrActivation
		}
	}
	return CopyPrivateDir(src, dst)
}

// HandoffPrivateDir copies src to dst only after coord is fenced, drained,
// and holding a non-empty checkpoint head. The copy is still not activation.
// Rollback is a later generation via Activate, not a reuse of this one.
func HandoffPrivateDir(coord *Coordinator, src, dst string) error {
	if coord == nil {
		return ErrActivation
	}
	return HandoffCoordinatorDir(coord, src, dst)
}

// Owner is one local compute host. Active is a projection, not the authority.
// Submit asks the coordinator again at the mutation.
type Owner struct {
	ID        string
	Fence     Fence
	Active    bool
	Inner     Authority
	Admission bool
	coord     FenceCoordinator
	stateMu   sync.Mutex
	retired   atomic.Bool
}

func (o *Owner) isRetired() bool {
	if o == nil {
		return true
	}
	return o.retired.Load()
}

func (o *Owner) Submit(env RoutingEnvelope, fence Fence) (AuthenticatedResponse, error) {
	base := AuthenticatedResponse{
		Version: Version, Tenant: env.Item.Tenant, AgreementID: env.Item.AgreementID,
		RequestID: env.Item.OperationID, CommandHash: CommandHash(env.Item.SignedObject), Kind: ResultRefused,
	}
	if o == nil || isNilCoordinator(o.coord) || o.Inner == nil {
		base.Error = ErrFenced.Error()
		return base, ErrFenced
	}
	var (
		resp     AuthenticatedResponse
		applyErr error
		ran      bool
	)
	// Authority is the coordinator at this call, not the Active flag copied
	// when the owner was bound. A stop that never cleared Active still fences.
	err := o.coord.Authorize(fence, func() error {
		if o.isRetired() || o.ID == "" || o.ID != fence.Owner || env.Generation == 0 || env.Generation != fence.Generation || !FencesEqual(o.Fence, fence) {
			return ErrFenced
		}
		ran = true
		resp, applyErr = o.Inner.Apply(env.Item)
		return nil
	})
	if err != nil {
		base.Error = err.Error()
		return base, err
	}
	if !ran {
		base.Error = ErrFenced.Error()
		return base, ErrFenced
	}
	return resp, applyErr
}

func (o *Owner) Deactivate() {
	if o == nil {
		return
	}
	if mem, ok := o.coord.(*Coordinator); ok && mem != nil {
		mem.mu.Lock()
		defer mem.mu.Unlock()
	}
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	o.retired.Store(true)
	o.Active = false
	o.Admission = false
}

func BindCoordinatorOwner(coord FenceCoordinator, id string, fence Fence, inner Authority) *Owner {
	if isNilCoordinator(coord) {
		coord = nil
	}
	o := &Owner{ID: id, Fence: cloneFence(fence), Inner: inner, coord: coord}
	if coord == nil {
		return o
	}
	if mem, ok := coord.(*Coordinator); ok {
		mem.register(o)
		return o
	}
	cur, err := coord.Current()
	match := err == nil && cur.Generation > 0 && id == cur.Owner && FencesEqual(o.Fence, cur)
	o.stateMu.Lock()
	o.Active = match
	o.Admission = match && coord.Admission() == "open"
	o.stateMu.Unlock()
	return o
}

func BindOwner(coord *Coordinator, id string, fence Fence, inner Authority) *Owner {
	if coord == nil {
		return BindCoordinatorOwner(nil, id, fence, inner)
	}
	return BindCoordinatorOwner(coord, id, fence, inner)
}

func ActivateCoordinatorReplacement(coord FenceCoordinator, src *Owner, newID, observedHead string, inner Authority) (*Owner, error) {
	if isNilCoordinator(coord) {
		return nil, ErrActivation
	}
	if ownerStillActive(src) {
		return nil, ErrConcurrentOwner
	}
	fence, err := coord.Activate(newID, observedHead)
	if err != nil {
		return nil, err
	}
	return BindCoordinatorOwner(coord, newID, fence, inner), nil
}

func ActivateReplacement(coord *Coordinator, src *Owner, newID, observedHead string, inner Authority) (*Owner, error) {
	if coord == nil {
		return nil, ErrActivation
	}
	return ActivateCoordinatorReplacement(coord, src, newID, observedHead, inner)
}

func ownerStillActive(o *Owner) bool {
	if o == nil {
		return false
	}
	if mem, ok := o.coord.(*Coordinator); ok && mem != nil {
		mem.mu.Lock()
		defer mem.mu.Unlock()
	}
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	return o.Active && !o.retired.Load()
}

func cloneFence(f Fence) Fence {
	f.Token = append([]byte(nil), f.Token...)
	return f
}

func FencesEqual(a, b Fence) bool {
	return a.Generation == b.Generation && a.Owner == b.Owner && subtle.ConstantTimeCompare(a.Token, b.Token) == 1 && bytes.Equal(a.Token, b.Token)
}
