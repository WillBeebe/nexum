package adapter

import (
	"errors"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

const Version = 1

// DefaultQuota is the maximum unresolved outbound items per tenant.
const DefaultQuota = 64

const (
	DomainResponse = "adapter-response"
	DomainFence    = "adapter-fence"
)

type Kind string

const (
	KindAgreement Kind = "agreement"
	KindProtocol  Kind = "protocol"
)

type ResultKind string

const (
	ResultAgreement ResultKind = "agreement_result"
	ResultUncertain ResultKind = "uncertain"
	ResultConflict  ResultKind = "conflict"
	ResultRefused   ResultKind = "refused"
)

const (
	// StatusPending has not been submitted.
	StatusPending = "pending"
	// StatusUnknown is retryable: the outcome is unknown or the refusal may
	// succeed on an exact retry. It is not a verified terminal.
	StatusUnknown = "unknown"
	// StatusAwaiting holds an authority response that is not yet verified.
	StatusAwaiting = "awaiting-verification"
	// StatusResolved is a verified success. StatusConflict is a verified
	// conflict. StatusRefused is a definitive refusal of these exact bytes.
	StatusResolved = "resolved"
	StatusConflict = "conflict"
	StatusRefused  = "refused"
)

var (
	ErrQuota            = errors.New("adapter: outbound quota exhausted")
	ErrDefinitive       = errors.New("adapter: exact command definitively refused")
	ErrTenant           = errors.New("adapter: tenant mismatch")
	ErrForeign          = errors.New("adapter: foreign agreement or command")
	ErrLostResponse     = errors.New("adapter: transport response lost")
	ErrFenced           = errors.New("adapter: owner fenced or inactive")
	ErrActivation       = errors.New("adapter: activation refused")
	ErrEffectUnknown    = errors.New("adapter: effect outcome unknown")
	ErrAdmissionStopped = errors.New("adapter: admission stopped")
	ErrCorrupt          = errors.New("adapter: invalid or unauthenticated outbox record")
	ErrNotFound         = errors.New("adapter: item not found")
	ErrConflict         = errors.New("adapter: operation ID already retained with different content")
	ErrUnresolved       = errors.New("adapter: outcome unresolved")
	ErrVersion          = errors.New("adapter: unsupported version")
	ErrStorageKey       = errors.New("adapter: storage key must be 32 random bytes")
	ErrStorageDir       = errors.New("adapter: directory must be private (0700), without a symlink")
	ErrItem             = errors.New("adapter: invalid outbound item")
	ErrResponse         = errors.New("adapter: unauthenticated or mismatched response")
	ErrEffectReexecute  = errors.New("adapter: refused automatic reexecution")
	ErrConcurrentOwner  = errors.New("adapter: previous owner still active")
	ErrNotDue           = errors.New("adapter: backoff not elapsed")
)

type RetryPolicy struct {
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

func (p RetryPolicy) normalized() RetryPolicy {
	if p.InitialBackoff <= 0 {
		p.InitialBackoff = 50 * time.Millisecond
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = 2 * time.Second
	}
	return p
}

// OutboundItem is persisted before send. It never contains signing or storage keys.
type OutboundItem struct {
	Version      int
	Tenant       string
	AgreementID  string
	OperationID  string
	Kind         Kind
	SignedObject []byte
	Destination  string
	CreatedAt    time.Time
	Retry        RetryPolicy
}

// AuthenticatedResponse binds tenant, agreement, request and command commitment.
// An agreement result carries the existing Nexum receipt, not a transport status.
type AuthenticatedResponse struct {
	Version     int
	Tenant      string
	AgreementID string
	RequestID   string
	CommandHash string
	Kind        ResultKind
	Result      *nex.Result
	ReceiptHead string
	Phase       string
	WorkOutcome string
	Error       string
	// Definitive marks a refusal of this exact signed command. A zero value
	// stays retryable.
	Definitive bool
}

// WorkSucceeded reports whether declared work was accepted. Protocol completion
// alone is not success: a failure return can complete its obligations.
// WorkSucceeded is a convenience predicate over an already validated view.
// It is not authentication of caller-built JSON. Success needs a complete
// phase, an accepted resolution, a return, and no incomplete record.
func WorkSucceeded(v nex.ProtocolView) bool {
	return v.Phase == "complete" && v.Resolution != nil && v.Resolution.Outcome == "accept" && v.Return != nil && v.Incomplete == nil
}

type ViewSnapshot struct {
	AgreementID string
	Head        string
	Phase       string
	Status      nex.Status
	WorkOutcome string
}

type RecordedItem struct {
	Item     OutboundItem
	Status   string
	Original *AuthenticatedResponse
	NextTry  time.Time
	Attempts int
}

type Authority interface {
	Apply(item OutboundItem) (AuthenticatedResponse, error)
	View(tenant, agreementID string) (ViewSnapshot, error)
}

type RoutingEnvelope struct {
	Item       OutboundItem
	Generation uint64
}
