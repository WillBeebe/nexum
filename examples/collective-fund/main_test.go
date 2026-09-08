package main

import (
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"testing"
	"time"
)

func TestFundRequiresExactFundingAndMilestone(t *testing.T) {
	now := time.Now().UTC()
	a, b, v, x := lab.NewIdentity(), lab.NewIdentity(), lab.NewIdentity(), lab.NewIdentity()
	artifact := []byte("verified healthcheck")
	f, e := newFund("fund", 10, []lab.Public{lab.PublicOf(a), lab.PublicOf(b)}, lab.PublicOf(v), lab.Hash(artifact), now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	c := contribution{f.id, lab.PublicOf(a).ID(), 4}
	if f.contribute(c, lab.Sign(x, "contribution", c), now) == nil {
		t.Fatal("forgery")
	}
	lab.Must(f.contribute(c, lab.Sign(a, "contribution", c), now))
	if f.contribute(c, lab.Sign(a, "contribution", c), now) == nil {
		t.Fatal("duplicate contribution")
	}
	m := milestone{f.id, lab.Hash(artifact)}
	if _, e = f.release(m, lab.Sign(v, "milestone", m), artifact, now); e == nil {
		t.Fatal("underfunded release")
	}
	c = contribution{f.id, lab.PublicOf(b).ID(), 6}
	lab.Must(f.contribute(c, lab.Sign(b, "contribution", c), now))
	if _, e = f.release(m, lab.Sign(x, "milestone", m), artifact, now); e == nil {
		t.Fatal("wrong verifier")
	}
	if _, e = f.release(m, lab.Sign(v, "milestone", m), []byte("failed"), now); e == nil {
		t.Fatal("bad artifact")
	}
	if _, e = f.release(m, lab.Sign(v, "milestone", m), artifact, f.deadline); e == nil {
		t.Fatal("late release")
	}
	if _, e = f.release(m, lab.Sign(v, "milestone", m), artifact, now); e != nil {
		t.Fatal(e)
	}
	if _, e = f.release(m, lab.Sign(v, "milestone", m), artifact, now); e == nil {
		t.Fatal("double release")
	}
}

// Exercise the advertised local capacity through signed contributions and release.
func TestFund32Contributors(t *testing.T) {
	now := time.Now().UTC()
	verifier := lab.NewIdentity()
	identities := make([]lab.Identity, 32)
	members := make([]lab.Public, len(identities))
	for i := range identities {
		identities[i] = lab.NewIdentity()
		members[i] = lab.PublicOf(identities[i])
	}
	artifact := []byte("community milestone verified")
	f, err := newFund("community", 32, members, lab.PublicOf(verifier), lab.Hash(artifact), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for i, identity := range identities {
		c := contribution{f.id, members[i].ID(), 1}
		if err := f.contribute(c, lab.Sign(identity, "contribution", c), now); err != nil {
			t.Fatal(err)
		}
	}
	m := milestone{f.id, lab.Hash(artifact)}
	receipt, err := f.release(m, lab.Sign(verifier, "milestone", m), artifact, now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt == "" || len(f.seen) != 32 {
		t.Fatal("missing receipt or contributors")
	}
	if _, err := f.release(m, lab.Sign(verifier, "milestone", m), artifact, now); err == nil {
		t.Fatal("double release")
	}
}
