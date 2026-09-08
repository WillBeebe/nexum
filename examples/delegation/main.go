// A signed grant is enforced by the tool runner, before any work executes.
package main

import (
	"errors"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"sync"
	"time"
)

type grant struct {
	ID, Audience    string
	Issuer, Subject lab.Public
	Tool            string
	Budget          int64
	MaxCalls        int
	Expires         time.Time
}
type invocation struct{ GrantHash, ID, Tool string }
type runner struct {
	mu      sync.Mutex
	grant   grant
	spent   int64
	calls   int
	seen    map[string]bool
	revoked bool
}

func newRunner(g grant, sig []byte, trustedIssuer lab.Public, now time.Time) (*runner, error) {
	if g.Issuer.ID() != trustedIssuer.ID() {
		return nil, errors.New("issuer not trusted")
	}
	if e := lab.Verify(trustedIssuer, "grant", g, sig); e != nil {
		return nil, e
	}
	if e := g.Subject.Validate(); e != nil {
		return nil, e
	}
	if g.ID == "" || g.Audience != "local-tool-runner" || g.Tool != "search-fixture" || g.Budget <= 0 || g.MaxCalls <= 0 || !now.Before(g.Expires) {
		return nil, errors.New("invalid grant")
	}
	return &runner{grant: g, seen: map[string]bool{}}, nil
}
func (r *runner) run(v invocation, sig []byte, now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := lab.Verify(r.grant.Subject, "invoke", v, sig); e != nil {
		return "", e
	}
	if r.revoked || !now.Before(r.grant.Expires) || v.GrantHash != lab.Hash(r.grant) || v.ID == "" || r.seen[v.ID] || v.Tool != r.grant.Tool {
		return "", errors.New("invocation not authorized")
	}
	const cost int64 = 3 // Trusted tool price; callers cannot choose their charge.
	if r.calls >= r.grant.MaxCalls || cost > r.grant.Budget-r.spent {
		return "", errors.New("budget exhausted")
	}
	r.spent += cost
	r.calls++
	r.seen[v.ID] = true
	// Only this admitted implementation is reachable. No arbitrary shell or URL.
	return "fixture://reference/agentic-trade", nil
}
func (r *runner) revoke(sig []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := lab.Verify(r.grant.Issuer, "revoke", lab.Hash(r.grant), sig); e != nil {
		return e
	}
	r.revoked = true
	return nil
}
func main() {
	now := time.Now().UTC()
	parent, child := lab.NewIdentity(), lab.NewIdentity()
	g := grant{"grant-1", "local-tool-runner", lab.PublicOf(parent), lab.PublicOf(child), "search-fixture", 6, 2, now.Add(time.Hour)}
	r, e := newRunner(g, lab.Sign(parent, "grant", g), lab.PublicOf(parent), now)
	lab.Must(e)
	c, e := lab.New("delegation", lab.PublicOf(parent), lab.PublicOf(child), 6, g, now, g.Expires)
	lab.Must(e)
	lab.Must(c.Execute(parent, "lock", "", now))
	lab.Must(c.Execute(child, "agree", "", now))
	for _, id := range []string{"call-1", "call-2"} {
		v := invocation{lab.Hash(g), id, g.Tool}
		_, e = r.run(v, lab.Sign(child, "invoke", v), now)
		lab.Must(e)
	}
	v := invocation{lab.Hash(g), "call-3", g.Tool}
	if _, e = r.run(v, lab.Sign(child, "invoke", v), now); e == nil {
		panic("overspend")
	}
	lab.Must(c.Execute(parent, "settle", lab.Hash(struct {
		Grant string
		Spent int64
		Calls int
	}{lab.Hash(g), r.spent, r.calls}), now))
	lab.Must(c.VerifyReceipts())
	lab.Print(map[string]any{"example": "delegation", "spent": r.spent, "budget": g.Budget, "excess_call": "refused", "receipt": c.Head()})
}
