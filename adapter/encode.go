package adapter

import (
	"encoding/json"
	"time"

	"github.com/WillBeebe/nexum/nex"
)

// SignedPayload is the exact persisted object replayed on every retry.
type SignedPayload struct {
	Version   int                  `json:"version"`
	Kind      Kind                 `json:"kind"`
	Operation *nex.Operation       `json:"operation,omitempty"`
	Command   *nex.ProtocolCommand `json:"command,omitempty"`
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

func DecodePayload(raw []byte) (SignedPayload, error) {
	var p SignedPayload
	if json.Unmarshal(raw, &p) != nil || p.Version != Version {
		return SignedPayload{}, ErrItem
	}
	if p.Kind == KindAgreement && p.Operation != nil && len(p.Signature) > 0 {
		return p, nil
	}
	if p.Kind == KindProtocol && p.Command != nil && len(p.Signature) > 0 {
		return p, nil
	}
	return SignedPayload{}, ErrItem
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
