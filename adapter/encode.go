package adapter

import (
	"encoding/json"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

// SignedPayload is the exact persisted object replayed on every retry.
type SignedPayload struct {
	Version   int                  `json:"version"`
	Kind      Kind                 `json:"kind"`
	Operation *nex.Operation       `json:"operation,omitempty"`
	Command   *nex.ProtocolCommand `json:"command,omitempty"`
	Accord    *nex.AccordCommand   `json:"accord,omitempty"`
	Signature []byte               `json:"signature"`
	ApplyAt   time.Time            `json:"apply_at,omitempty"`
	Height    uint64               `json:"height,omitempty"`
}

func EncodeOperation(op nex.Operation, signature []byte, applyAt time.Time) ([]byte, error) {
	return json.Marshal(SignedPayload{Version: Version, Kind: KindAgreement, Operation: &op, Signature: append([]byte(nil), signature...), ApplyAt: applyAt})
}

func EncodeProtocol(cmd nex.ProtocolCommand, signature []byte) ([]byte, error) {
	return json.Marshal(SignedPayload{Version: Version, Kind: KindProtocol, Command: &cmd, Signature: append([]byte(nil), signature...), Height: cmd.Height})
}

func EncodeAccord(cmd nex.AccordCommand, signature []byte) ([]byte, error) {
	return json.Marshal(SignedPayload{Version: Version, Kind: KindAccord, Accord: &cmd, Signature: append([]byte(nil), signature...), Height: cmd.Height})
}

func DecodePayload(raw []byte) (SignedPayload, error) {
	var p SignedPayload
	if json.Unmarshal(raw, &p) != nil || p.Version != Version {
		return SignedPayload{}, ErrItem
	}
	populated := 0
	if p.Operation != nil {
		populated++
	}
	if p.Command != nil {
		populated++
	}
	if p.Accord != nil {
		populated++
	}
	if populated != 1 || len(p.Signature) == 0 {
		return SignedPayload{}, ErrItem
	}
	switch p.Kind {
	case KindAgreement:
		if p.Operation == nil || p.Operation.ID == "" {
			return SignedPayload{}, ErrItem
		}
	case KindProtocol:
		if p.Command == nil || p.Command.RequestID == "" || p.Command.ProtocolID == "" {
			return SignedPayload{}, ErrItem
		}
	case KindAccord:
		if p.Accord == nil || p.Accord.RequestID == "" || p.Accord.AccordID == "" {
			return SignedPayload{}, ErrItem
		}
	default:
		return SignedPayload{}, ErrItem
	}
	return p, nil
}

func CommandHash(signedObject []byte) string { return nex.Hash(signedObject) }

func SignResponse(i nex.Identity, r AuthenticatedResponse) []byte {
	return nex.Sign(i, DomainResponse, r)
}

func VerifyResponse(p nex.Public, r AuthenticatedResponse, signature []byte) error {
	return nex.Verify(p, DomainResponse, r, signature)
}

func SignFence(i nex.Identity, f Fence) []byte { return nex.Sign(i, DomainFence, f) }

func VerifyFence(p nex.Public, f Fence, signature []byte) error {
	return nex.Verify(p, DomainFence, f, signature)
}
