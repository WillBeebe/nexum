package adapter

import (
	"errors"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/nexum"
	"github.com/WillBeebe/nexum/v2/nex"
)

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
	base := AuthenticatedResponse{Version: Version, Tenant: item.Tenant, AgreementID: item.AgreementID, RequestID: item.OperationID, CommandHash: CommandHash(item.SignedObject)}
	if item.Tenant != a.Tenant {
		base.Kind = ResultRefused
		base.Error = ErrTenant.Error()
		return base, ErrTenant
	}
	if item.Kind != KindAgreement {
		base.Kind = ResultRefused
		base.Definitive = true
		base.Error = ErrItem.Error()
		return base, ErrItem
	}
	payload, err := DecodePayload(item.SignedObject)
	if err != nil || payload.Kind != KindAgreement || payload.Operation == nil {
		base.Kind = ResultRefused
		base.Definitive = true
		base.Error = ErrItem.Error()
		return base, ErrItem
	}
	op := *payload.Operation
	if op.Command.Terms != item.AgreementID || op.ID != item.OperationID {
		base.Kind = ResultRefused
		base.Definitive = true
		base.Error = ErrForeign.Error()
		return base, ErrForeign
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
	base.Definitive = definitiveRefusal(err)
	return base, err
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
	base := AuthenticatedResponse{Version: Version, Tenant: item.Tenant, AgreementID: item.AgreementID, RequestID: item.OperationID, CommandHash: CommandHash(item.SignedObject)}
	if item.Tenant != a.Tenant {
		base.Kind = ResultRefused
		base.Error = ErrTenant.Error()
		return base, ErrTenant
	}
	if item.Kind != KindProtocol {
		base.Kind = ResultRefused
		base.Definitive = true
		base.Error = ErrItem.Error()
		return base, ErrItem
	}
	payload, err := DecodePayload(item.SignedObject)
	if err != nil || payload.Kind != KindProtocol || payload.Command == nil {
		base.Kind = ResultRefused
		base.Definitive = true
		base.Error = ErrItem.Error()
		return base, ErrItem
	}
	cmd := *payload.Command
	if cmd.ProtocolID != item.AgreementID || cmd.RequestID != item.OperationID {
		base.Kind = ResultRefused
		base.Definitive = true
		base.Error = ErrForeign.Error()
		return base, ErrForeign
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
	if err == nil {
		// This head belongs to the command that just committed. The latest
		// protocol phase is a different fact and is available from View.
		base.Kind = ResultAgreement
		base.ReceiptHead = head
		return base, nil
	}
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
	base.Definitive = definitiveRefusal(err)
	return base, err
}

func SignAuthorityResponse(i nex.Identity, r AuthenticatedResponse) []byte {
	return SignResponse(i, r)
}
