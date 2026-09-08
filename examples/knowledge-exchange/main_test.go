package main

import (
	"bytes"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"github.com/WillBeebe/nexum/nex"
	"testing"
	"time"
)

func TestEncryptedExchange(t *testing.T) {
	now := time.Now().UTC()
	a, b, other := lab.NewIdentity(), lab.NewIdentity(), lab.NewIdentity()
	plain := []byte("private fixture report")
	x, e := newExchange(a, lab.PublicOf(b), plain, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = nex.Open(b, x.record); e == nil {
		t.Fatal("read before consent")
	}
	if x.release(x.requirement, lab.Sign(b, "condition", x.requirement), lab.PublicOf(b), now) == nil {
		t.Fatal("release before consent")
	}
	d, e := nex.Decide(b, x.record.Offer, "agree", now)
	if e != nil {
		t.Fatal(e)
	}
	lab.Must(x.decide(d, now))
	if _, e = nex.Open(b, x.record); e == nil {
		t.Fatal("read without condition")
	}
	bad := x.requirement
	bad.Requirement = "changed"
	if x.release(bad, lab.Sign(b, "condition", bad), lab.PublicOf(b), now) == nil {
		t.Fatal("wrong condition")
	}
	if x.release(x.requirement, lab.Sign(other, "condition", x.requirement), lab.PublicOf(other), now) == nil {
		t.Fatal("wrong recipient")
	}
	if x.release(x.requirement, lab.Sign(b, "condition", x.requirement), lab.PublicOf(b), x.expiry) == nil {
		t.Fatal("late release")
	}
	lab.Must(x.release(x.requirement, lab.Sign(b, "condition", x.requirement), lab.PublicOf(b), now))
	got, e := nex.Open(b, x.record)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal(string(got), e)
	}
	if _, e = nex.Open(other, x.record); e == nil {
		t.Fatal("outsider read")
	}
	if x.release(x.requirement, lab.Sign(b, "condition", x.requirement), lab.PublicOf(b), now) == nil {
		t.Fatal("duplicate release")
	}
	if len(x.key) != 0 {
		t.Fatal("content key retained")
	}
}
func TestRejectionNeverReleases(t *testing.T) {
	now := time.Now().UTC()
	a, b := lab.NewIdentity(), lab.NewIdentity()
	x, e := newExchange(a, lab.PublicOf(b), []byte("report"), now)
	if e != nil {
		t.Fatal(e)
	}
	d, e := nex.Decide(b, x.record.Offer, "reject", now)
	if e != nil {
		t.Fatal(e)
	}
	lab.Must(x.decide(d, now))
	if x.release(x.requirement, lab.Sign(b, "condition", x.requirement), lab.PublicOf(b), now) == nil {
		t.Fatal("released rejected offer")
	}
}
