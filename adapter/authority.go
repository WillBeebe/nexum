package adapter

import (
	"errors"
	"fmt"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/nexum"
	"github.com/WillBeebe/nexum/v2/nex"
)

var (
	_ Authority = (*StoreAuthority)(nil)
	_ Authority = (*ProtocolAuthority)(nil)
	_ Authority = (*AccordAuthority)(nil)
)

func baseResponse(item OutboundItem) AuthenticatedResponse {
	return AuthenticatedResponse{
		Version:     Version,
		Tenant:      item.Tenant,
		AgreementID: item.AgreementID,
		RequestID:   item.OperationID,
		CommandHash: CommandHash(item.SignedObject),
	}
}

func refusalResponse(base AuthenticatedResponse, err error, definitive bool) (AuthenticatedResponse, error) {
	base.Kind = ResultRefused
	base.Definitive = definitive
	base.Error = err.Error()
	return base, err
}

func prepareAuthorityApply(item OutboundItem, tenant string, wantKind Kind) (AuthenticatedResponse, SignedPayload, error) {
	base := baseResponse(item)
	if item.Tenant != tenant {
		resp, err := refusalResponse(base, ErrTenant, false)
		return resp, SignedPayload{}, err
	}
	if item.Kind != wantKind {
		resp, err := refusalResponse(base, ErrItem, true)
		return resp, SignedPayload{}, err
	}
	payload, err := DecodePayload(item.SignedObject)
	if err != nil || payload.Kind != wantKind {
		resp, rerr := refusalResponse(base, ErrItem, true)
		return resp, SignedPayload{}, rerr
	}
	return base, payload, nil
}

func classifyError(base AuthenticatedResponse, err error, isDefinitive func(error) bool) (AuthenticatedResponse, error) {
	if errors.Is(err, nex.ErrCommitUncertain) {
		base.Kind = ResultUncertain
		base.Error = err.Error()
		return base, err
	}
	if errors.Is(err, nex.ErrOperationConflict) {
		base.Kind = ResultConflict
		base.Error = err.Error()
		return base, err
	}
	base.Kind = ResultRefused
	base.Error = err.Error()
	if isDefinitive != nil {
		base.Definitive = isDefinitive(err)
	}
	return base, err
}

func classifyHead(base AuthenticatedResponse, head string, err error, isDefinitive func(error) bool) (AuthenticatedResponse, error) {
	if err == nil {
		// This head belongs to the command that just committed. The latest
		// agreement phase is a different fact and is available from View.
		base.Kind = ResultAgreement
		base.ReceiptHead = head
		return base, nil
	}
	return classifyError(base, err, isDefinitive)
}

// StoreAuthority submits exact signed operations to nex.Store.
type StoreAuthority struct {
	Tenant   string
	Store    *nex.Store
	Now      func() time.Time
	DropNext bool
}

func (a *StoreAuthority) clock() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}

func (a *StoreAuthority) Apply(item OutboundItem) (AuthenticatedResponse, error) {
	base, payload, err := prepareAuthorityApply(item, a.Tenant, KindAgreement)
	if err != nil {
		return base, err
	}
	if payload.Operation == nil {
		return refusalResponse(base, ErrItem, true)
	}
	op := *payload.Operation
	if op.Command.Terms != item.AgreementID || op.ID != item.OperationID {
		return refusalResponse(base, ErrForeign, true)
	}
	// The receiver's clock is the service time. A caller-supplied ApplyAt
	// cannot backdate a first application. Exact committed retries still
	// return their historical result inside Store.Apply.
	result, err := a.Store.Apply(item.AgreementID, op, payload.Signature, a.clock())
	if a.DropNext {
		a.DropNext = false
		base.Kind = ResultUncertain
		return base, ErrLostResponse
	}
	return classifyStore(base, result, err)
}

func (a *StoreAuthority) View(tenant, agreementID string) (ViewSnapshot, error) {
	if tenant != a.Tenant {
		return ViewSnapshot{}, ErrTenant
	}
	v, err := a.Store.View(agreementID)
	if err != nil {
		return ViewSnapshot{}, err
	}
	return ViewSnapshot{AgreementID: agreementID, Head: v.Head, Status: v.Status}, nil
}

func classifyStore(base AuthenticatedResponse, result nex.Result, err error) (AuthenticatedResponse, error) {
	if err == nil {
		copy := result
		base.Kind = ResultAgreement
		base.Result = &copy
		base.ReceiptHead = result.Head
		return base, nil
	}
	return classifyError(base, err, definitiveRefusal)
}

func definitiveRefusal(err error) bool {
	if err == nil || errors.Is(err, nex.ErrCommitUncertain) {
		return false
	}
	if errors.Is(err, nexum.ErrTakeback) || errors.Is(err, nex.ErrProtocolStale) {
		return true
	}
	switch err.Error() {
	case "stale or foreign command", "nex: foreign operation", "invalid signature":
		return true
	default:
		return false
	}
}

// ProtocolAuthority submits exact signed protocol commands to nex.ProtocolStore.
type ProtocolAuthority struct {
	Tenant   string
	Store    *nex.ProtocolStore
	DropNext bool
	// Height is supplied by the receiving host. Without it only v1 commands
	// can use the legacy sender-supplied height.
	Height func() uint64
}

func (a *ProtocolAuthority) Apply(item OutboundItem) (AuthenticatedResponse, error) {
	base, payload, err := prepareAuthorityApply(item, a.Tenant, KindProtocol)
	if err != nil {
		return base, err
	}
	if payload.Command == nil {
		return refusalResponse(base, ErrItem, true)
	}
	cmd := *payload.Command
	if cmd.ProtocolID != item.AgreementID || cmd.RequestID != item.OperationID {
		return refusalResponse(base, ErrForeign, true)
	}
	var head string
	if a.Height == nil {
		head, err = a.Store.ApplyV1(item.AgreementID, cmd, payload.Signature, payload.Height)
	} else {
		head, err = a.Store.Apply(item.AgreementID, cmd, payload.Signature, a.Height())
	}
	if a.DropNext {
		a.DropNext = false
		base.Kind = ResultUncertain
		return base, ErrLostResponse
	}
	return classifyProtocol(a, base, head, err)
}

func (a *ProtocolAuthority) View(tenant, agreementID string) (ViewSnapshot, error) {
	if tenant != a.Tenant {
		return ViewSnapshot{}, ErrTenant
	}
	v, err := a.Store.View(agreementID)
	if err != nil {
		return ViewSnapshot{}, err
	}
	outcome := ""
	if v.Report != nil {
		outcome = string(v.Report.Outcome)
	}
	return ViewSnapshot{AgreementID: agreementID, Head: v.Head, Phase: v.Phase, WorkOutcome: outcome}, nil
}

func classifyProtocol(a *ProtocolAuthority, base AuthenticatedResponse, head string, err error) (AuthenticatedResponse, error) {
	return classifyHead(base, head, err, definitiveRefusal)
}

// AccordAuthority submits exact signed accord commands to nex.AccordStore.
type AccordAuthority struct {
	Tenant   string
	Store    *nex.AccordStore
	DropNext bool
	// Height is supplied by the receiving host and is required to be non-nil
	// and return > 0.
	Height func() uint64
}

func (a *AccordAuthority) Apply(item OutboundItem) (AuthenticatedResponse, error) {
	if a == nil {
		return refusalResponse(baseResponse(item), ErrItem, false)
	}
	base, payload, err := prepareAuthorityApply(item, a.Tenant, KindAccord)
	if err != nil {
		return base, err
	}
	if payload.Accord == nil {
		return refusalResponse(base, ErrItem, true)
	}
	cmd := *payload.Accord
	if cmd.AccordID != item.AgreementID || cmd.RequestID != item.OperationID {
		return refusalResponse(base, ErrForeign, true)
	}
	if a.Store == nil {
		return refusalResponse(base, fmt.Errorf("%w: accord store is nil", ErrItem), false)
	}
	if a.Height == nil {
		return refusalResponse(base, fmt.Errorf("%w: accord authority height callback is nil", ErrItem), false)
	}
	height := a.Height()
	if height == 0 {
		return refusalResponse(base, fmt.Errorf("%w: accord authority height must be > 0", ErrItem), false)
	}
	head, err := a.Store.Apply(item.AgreementID, cmd, payload.Signature, height)
	if a.DropNext {
		a.DropNext = false
		base.Kind = ResultUncertain
		return base, ErrLostResponse
	}
	return classifyAccord(base, head, err)
}

func (a *AccordAuthority) View(tenant, agreementID string) (ViewSnapshot, error) {
	if a == nil {
		return ViewSnapshot{}, ErrItem
	}
	if tenant != a.Tenant {
		return ViewSnapshot{}, ErrTenant
	}
	if a.Store == nil {
		return ViewSnapshot{}, fmt.Errorf("%w: accord store is nil", ErrItem)
	}
	v, err := a.Store.View(agreementID)
	if err != nil {
		return ViewSnapshot{}, err
	}
	outcome := ""
	if v.Outcome != nil {
		outcome = v.Outcome.WinningOptionID
	}
	return ViewSnapshot{
		AgreementID: agreementID,
		Head:        v.Head,
		Phase:       string(v.Phase),
		WorkOutcome: outcome,
	}, nil
}

func classifyAccord(base AuthenticatedResponse, head string, err error) (AuthenticatedResponse, error) {
	return classifyHead(base, head, err, definitiveAccordRefusal)
}

// definitiveAccordRefusal reports whether an AccordStore error is permanent for
// the exact signed command bytes.
//
// Checking nex/accord.go and nex/accord_evidence.go error sites:
//   - ErrAccordStale (wrong AccordID, stale Head, height mismatch/non-monotone),
//     ErrAccordEquivocation (duplicate/conflicting ballot or veto),
//     ErrAccordSpec (invalid UTF-8/shape/size/option/hash/duplicate option ID),
//     ErrAccordAuthority (unknown actor, wrong scope/grant/attester, expired
//     grant at cmd.Height, veto disabled/disallowed/over limit), and
//     "invalid signature" can never succeed for the exact signed command bytes.
//   - ErrAccordPhase (early height window, missing dynamically proposed option,
//     or terminal/max-events state) and ErrAccordEvidence (e.g. veto citing an
//     unattested evidence slot, or invalid attestation proof) are returned by
//     nex.Accord as bare sentinels without distinguishing transient window or
//     ordering failures from permanent ones, so Definitive remains false to
//     avoid falsely poisoning retryable outbox items.
func definitiveAccordRefusal(err error) bool {
	if err == nil || errors.Is(err, nex.ErrCommitUncertain) {
		return false
	}
	if errors.Is(err, nex.ErrAccordStale) ||
		errors.Is(err, nex.ErrAccordEquivocation) ||
		errors.Is(err, nex.ErrAccordSpec) ||
		errors.Is(err, nex.ErrAccordAuthority) {
		return true
	}
	return definitiveRefusal(err)
}

func SignAuthorityResponse(i nex.Identity, r AuthenticatedResponse) []byte {
	return SignResponse(i, r)
}
