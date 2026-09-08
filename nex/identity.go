package nex

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/WillBeebe/nexum/internal/message"
)

type Identity = message.Identity
type Public = message.Public

func NewIdentity() (Identity, error) { return message.NewIdentity() }

func Hash(v any) string {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Sign(i Identity, domain string, v any) []byte {
	return ed25519.Sign(i.Signing, []byte("nex-example/v1/"+domain+"/"+Hash(v)))
}
func Verify(p Public, domain string, v any, signature []byte) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !ed25519.Verify(p.Signing, []byte("nex-example/v1/"+domain+"/"+Hash(v)), signature) {
		return errors.New("invalid signature")
	}
	return nil
}
