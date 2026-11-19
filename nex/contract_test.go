package nex_test

import (
	"github.com/WillBeebe/nexum/v2/nex"
	"testing"
	"time"
)

func TestContractAuthorizationAndTerminalState(t *testing.T) {
	now := time.Now().UTC()
	a, b, x := newIdentity(t), newIdentity(t), newIdentity(t)
	c, e := nex.New("test", publicOf(t, a), publicOf(t, b), 10, "scope", now, now.Add(time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	lock := c.Command("lock", "")
	if c.Apply(lock, nex.Sign(x, "contract", lock), now) == nil {
		t.Fatal("forged lock")
	}
	if e = c.Apply(lock, nex.Sign(a, "contract", lock), now); e != nil {
		t.Fatal(e)
	}
	if c.Apply(lock, nex.Sign(a, "contract", lock), now) == nil {
		t.Fatal("replayed lock")
	}
	if c.Execute(a, "settle", "evidence", now) == nil {
		t.Fatal("settled without consent")
	}
	if e = c.Execute(b, "agree", "", now); e != nil {
		t.Fatal(e)
	}
	if c.Execute(x, "settle", "evidence", now) == nil {
		t.Fatal("wrong verifier")
	}
	if e = c.Execute(a, "settle", "evidence", now); e != nil {
		t.Fatal(e)
	}
	if c.Execute(a, "settle", "evidence", now) == nil {
		t.Fatal("double settlement")
	}
	if c.Status() != nex.StatusAccepted {
		t.Fatal(c.Status())
	}
	if e = c.VerifyReceipts(); e != nil {
		t.Fatal(e)
	}
}
func TestConsentHistorySurvivesReject(t *testing.T) {
	now := time.Now().UTC()
	a, b := newIdentity(t), newIdentity(t)
	c, err := nex.New("consent", publicOf(t, a), publicOf(t, b), 4, "scope", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Execute(a, "lock", "", now); err != nil {
		t.Fatal(err)
	}
	if err = c.Execute(b, "agree", "", now); err != nil {
		t.Fatal(err)
	}
	if !c.Agreed() || c.Phase() != "agreed" {
		t.Fatalf("agreed=%v phase=%s", c.Agreed(), c.Phase())
	}
	if err = c.Execute(b, "reject", "", now); err != nil {
		t.Fatal(err)
	}
	history := c.ConsentHistory()
	if c.Phase() != string(nex.StatusRejected) || !c.Agreed() || len(history) != 2 || history[0].Action != "agree" || history[1].Action != "reject" {
		t.Fatalf("phase=%s agreed=%v history=%+v", c.Phase(), c.Agreed(), history)
	}
}

func TestExpiry(t *testing.T) {
	now := time.Now().UTC()
	a, b := newIdentity(t), newIdentity(t)
	c, e := nex.New("test", publicOf(t, a), publicOf(t, b), 1, "scope", now, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Execute(a, "lock", "", now); e != nil {
		t.Fatal(e)
	}
	if c.Execute(b, "agree", "", now.Add(time.Second)) == nil {
		t.Fatal("late consent")
	}
	if e = c.Execute(a, "expire", "", now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if c.Status() != nex.StatusExpired {
		t.Fatal(c.Status())
	}
}

func newIdentity(t *testing.T) nex.Identity {
	t.Helper()
	i, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}
func publicOf(t *testing.T, i nex.Identity) nex.Public {
	t.Helper()
	p, err := i.Public()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
