// This local demonstration simulates losing a response and reopening storage.
// A real app keeps its storage key in its platform key store and the signed
// operation in a durable outbox. It must not generate a replacement key at restart.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/WillBeebe/nexum/nex"
)

func run() error {
	parent, err := os.MkdirTemp("", "nex-durable-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(parent) // Demonstration data only.
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	buyer, err := nex.NewIdentity()
	if err != nil {
		return err
	}
	seller, err := nex.NewIdentity()
	if err != nil {
		return err
	}
	bp, err := buyer.Public()
	if err != nil {
		return err
	}
	sp, err := seller.Public()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	c, err := nex.New("work.bounty", bp, sp, 10, "verify an artifact", now, now.Add(time.Hour))
	if err != nil {
		return err
	}
	dir := filepath.Join(parent, "agreements")
	store, err := nex.OpenStore(dir, key)
	if err != nil {
		return err
	}
	if err = store.Create(c); err != nil {
		return err
	}
	op, err := store.Prepare(c.ID(), "stable-lock-request-1", "lock", "")
	if err != nil {
		return err
	}
	signature := nex.Sign(buyer, "operation", op)
	committed, err := store.Apply(c.ID(), op, signature, now)
	if err != nil {
		return err
	}

	// Pretend the response was lost. Reopen using the SAME protected key and retry
	// the original signed operation, without preparing a new head or ID.
	restarted, err := nex.OpenStore(dir, key)
	if err != nil {
		return err
	}
	retry, err := restarted.Apply(c.ID(), op, signature, now)
	if err != nil {
		return err
	}
	if retry != committed {
		return fmt.Errorf("retry result changed")
	}
	for _, action := range []string{"agree", "settle"} {
		op, err = restarted.Prepare(c.ID(), "stable-"+action+"-request", action, "artifact verified")
		if err != nil {
			return err
		}
		signer := buyer
		if action == "agree" {
			signer = seller
		}
		if _, err = restarted.Apply(c.ID(), op, nex.Sign(signer, "operation", op), now); err != nil {
			return err
		}
	}
	view, err := restarted.View(c.ID())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"example": "durable-retry", "status": view.Status, "receipts": len(view.Receipts), "same_retry_result": retry == committed,
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
