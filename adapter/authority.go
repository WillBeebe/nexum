package adapter

import (
	"errors"
	"time"

	"github.com/WillBeebe/nexum/nex"
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
	payload, err := DecodePayload(item.SignedObject)
	if err != nil || payload.Kind != KindAgreement || payload.Operation == nil {
		base.Kind = ResultRefused
		base.Error = ErrItem.Error()
		return base, ErrItem
	}
	op := *payload.Operation
	if op.Command.Terms != item.AgreementID || op.ID != item.OperationID {
		base.Kind = ResultRefused
		base.Error = ErrForeign.Error()
		return base, ErrForeign
	}
	applyAt := payload.ApplyAt
	if applyAt.IsZero() {
		applyAt = a.clock()
	}
	result, err := a.Store.Apply(item.AgreementID, op, payload.Signature, applyAt)
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
	return base, err
}

// ProtocolAuthority submits exact signed protocol commands to nex.ProtocolStore.
type ProtocolAuthority struct {
	Tenant   string
	Store    *nex.ProtocolStore
	DropNext bool
}

func (a *ProtocolAuthority) Apply(item OutboundItem) (AuthenticatedResponse, error) {
	base := AuthenticatedResponse{Version: Version, Tenant: item.Tenant, AgreementID: item.AgreementID, RequestID: item.OperationID, CommandHash: CommandHash(item.SignedObject)}
	if item.Tenant != a.Tenant {
		base.Kind = ResultRefused
		base.Error = ErrTenant.Error()
		return base, ErrTenant
	}
	payload, err := DecodePayload(item.SignedObject)
	if err != nil || payload.Kind != KindProtocol || payload.Command == nil {
		base.Kind = ResultRefused
		base.Error = ErrItem.Error()
		return base, ErrItem
	}
	cmd := *payload.Command
	if cmd.ProtocolID != item.AgreementID || cmd.RequestID != item.OperationID {
		base.Kind = ResultRefused
		base.Error = ErrForeign.Error()
		return base, ErrForeign
	}
	head, err := a.Store.Apply(item.AgreementID, cmd, payload.Signature, payload.Height)
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
		base.Kind = ResultAgreement
		base.ReceiptHead = head
		if v, viewErr := a.Store.View(base.AgreementID); viewErr == nil {
			base.Phase = v.Phase
			if v.Report != nil {
				base.WorkOutcome = string(v.Report.Outcome)
			}
		}
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
	return base, err
}

func SignAuthorityResponse(i nex.Identity, r AuthenticatedResponse) []byte {
	return SignResponse(i, r)
}
