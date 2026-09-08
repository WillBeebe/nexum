// Package lab contains local example helpers. Agreement behavior lives in nex.
package lab

import (
	"encoding/json"
	"github.com/WillBeebe/nexum/nex"
	"os"
	"time"
)

type Identity = nex.Identity
type Public = nex.Public
type Contract = nex.Contract
type Command = nex.Command

func NewIdentity() Identity                        { i, e := nex.NewIdentity(); Must(e); return i }
func PublicOf(i Identity) Public                   { p, e := i.Public(); Must(e); return p }
func Hash(v any) string                            { return nex.Hash(v) }
func Sign(i Identity, domain string, v any) []byte { return nex.Sign(i, domain, v) }
func Verify(p Public, domain string, v any, signature []byte) error {
	return nex.Verify(p, domain, v, signature)
}
func New(kind string, buyer, seller Public, amount int64, spec any, now, deadline time.Time) (*Contract, error) {
	return nex.New(kind, buyer, seller, amount, spec, now, deadline)
}
func Must(e error) {
	if e != nil {
		panic(e)
	}
}
func Print(v any) { e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); Must(e.Encode(v)) }
