package nex

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/internal/nexum"
)

func TestFailedSettlementCanRetrySameSignedCommand(t *testing.T) {
	now := time.Now()
	buyer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	seller, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bp, err := buyer.Public()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := seller.Public()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("work.bounty", bp, sp, 10, "scope", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c.agreement.Kind != "work.bounty" || c.agreement.Receipts[0].Note != "agreement opened" {
		t.Fatal("client still initializes escrow")
	}
	if err := c.Execute(buyer, "lock", "", now); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(seller, "agree", "", now); err != nil {
		t.Fatal(err)
	}
	cmd := c.Command("settle", "verified-artifact")
	sig := Sign(buyer, "contract", cmd)
	c.agreement.Meter.MaxSteps = len(c.agreement.Receipts) + 1
	before := *c.agreement
	if err := c.Apply(cmd, sig, now); !errors.Is(err, nexum.ErrDoS) {
		t.Fatalf("settlement: %v", err)
	}
	if !reflect.DeepEqual(before, *c.agreement) || !c.agreed || c.Head() != cmd.Head {
		t.Fatal("failed command mutated contract")
	}
	c.agreement.Meter.MaxSteps++
	if err := c.Apply(cmd, sig, now); err != nil {
		t.Fatalf("same signed command failed retry: %v", err)
	}
	if c.Status() != StatusAccepted {
		t.Fatal(c.Status())
	}
	if err := c.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}
