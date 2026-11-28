package nex

import (
	"bytes"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/nexum"
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

func TestRebuildConsentIgnoresBuyerSettleEvidencePrefix(t *testing.T) {
	now := time.Now().UTC()
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
	// Rejecting before lock must fail without mutating state.
	before := *c.agreement
	if err := c.Execute(seller, "reject", "", now); err == nil {
		t.Fatal("reject before lock succeeded")
	}
	if !reflect.DeepEqual(before, *c.agreement) || c.Status() != StatusOpen {
		t.Fatal("failed reject before lock mutated contract")
	}

	store, err := OpenStore(filepath.Join(t.TempDir(), "contracts"), bytes.Repeat([]byte{33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(c); err != nil {
		t.Fatal(err)
	}
	id := c.ID()
	apply := func(opID, action, evidence string, signer Identity) {
		t.Helper()
		op, err := store.Prepare(id, opID, action, evidence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Apply(id, op, Sign(signer, "operation", op), now); err != nil {
			t.Fatal(action, err)
		}
	}
	apply("op-lock", "lock", "", buyer)
	apply("op-agree", "agree", "", seller)
	// Buyer settlement evidence starting with "signed-consent:" must not be
	// mistaken for a second seller consent event when rebuilding consent history.
	apply("op-settle", "settle", "signed-consent:buyer-settlement-proof", buyer)

	_, restored, err := store.read(id)
	if err != nil {
		t.Fatal(err)
	}
	history := restored.ConsentHistory()
	if !restored.Agreed() || len(history) != 1 || history[0].Action != "agree" {
		t.Fatalf("restored consent history = %+v, want single agree event", history)
	}
	if history[0].Head != restored.agreement.Receipts[3].Hash {
		t.Fatalf("consent head = %s, want seller agree receipt %s", history[0].Head, restored.agreement.Receipts[3].Hash)
	}
}
