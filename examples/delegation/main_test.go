package main

import (
	"fmt"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunnerEnforcesBudgetUnderConcurrency(t *testing.T) {
	now := time.Now().UTC()
	a, b, x := lab.NewIdentity(), lab.NewIdentity(), lab.NewIdentity()
	g := grant{"one", "local-tool-runner", lab.PublicOf(a), lab.PublicOf(b), "search-fixture", 6, 10, now.Add(time.Hour)}
	if _, e := newRunner(g, lab.Sign(a, "grant", g), lab.PublicOf(x), now); e == nil {
		t.Fatal("untrusted issuer")
	}
	r, e := newRunner(g, lab.Sign(a, "grant", g), lab.PublicOf(a), now)
	if e != nil {
		t.Fatal(e)
	}
	v := invocation{lab.Hash(g), "wrong", "search-fixture"}
	if _, e = r.run(v, lab.Sign(x, "invoke", v), now); e == nil {
		t.Fatal("forgery")
	}
	v.Tool = "shell"
	if _, e = r.run(v, lab.Sign(b, "invoke", v), now); e == nil {
		t.Fatal("unlisted tool")
	}
	v.Tool = g.Tool
	if _, e = r.run(v, lab.Sign(b, "invoke", v), g.Expires); e == nil {
		t.Fatal("expired grant")
	}
	var wg sync.WaitGroup
	var wins atomic.Int32
	for n := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := invocation{lab.Hash(g), fmt.Sprint(n), g.Tool}
			if _, e := r.run(v, lab.Sign(b, "invoke", v), now); e == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 2 || r.spent != 6 {
		t.Fatal(wins.Load(), r.spent)
	}
}
func TestReplayAndRevocation(t *testing.T) {
	now := time.Now().UTC()
	a, b := lab.NewIdentity(), lab.NewIdentity()
	g := grant{"one", "local-tool-runner", lab.PublicOf(a), lab.PublicOf(b), "search-fixture", 30, 10, now.Add(time.Hour)}
	r, e := newRunner(g, lab.Sign(a, "grant", g), lab.PublicOf(a), now)
	if e != nil {
		t.Fatal(e)
	}
	v := invocation{lab.Hash(g), "once", g.Tool}
	if _, e = r.run(v, lab.Sign(b, "invoke", v), now); e != nil {
		t.Fatal(e)
	}
	if _, e = r.run(v, lab.Sign(b, "invoke", v), now); e == nil {
		t.Fatal("replay")
	}
	if r.revoke(lab.Sign(b, "revoke", lab.Hash(g))) == nil {
		t.Fatal("child revoked grant")
	}
	if e = r.revoke(lab.Sign(a, "revoke", lab.Hash(g))); e != nil {
		t.Fatal(e)
	}
	v.ID = "later"
	if _, e = r.run(v, lab.Sign(b, "invoke", v), now); e == nil {
		t.Fatal("revoked grant used")
	}
}
