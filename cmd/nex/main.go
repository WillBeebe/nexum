// Command nex runs a local signed agreement demonstration.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/WillBeebe/nexum/nex"
	"os"
	"time"
)

func run() error {
	if len(os.Args) != 2 || os.Args[1] != "demo" {
		return fmt.Errorf("usage: nex demo")
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
	contract, err := nex.New("demo.work", bp, sp, 1, "local fixture", now, now.Add(time.Hour))
	if err != nil {
		return err
	}
	if err = contract.Execute(buyer, "lock", "", now); err != nil {
		return err
	}
	if err = contract.Execute(seller, "agree", "", now); err != nil {
		return err
	}
	if err = contract.Execute(buyer, "settle", "fixture:verified", now); err != nil {
		return err
	}
	if err = contract.VerifyReceipts(); err != nil {
		return err
	}
	if contract.Execute(buyer, "settle", "fixture:verified", now) == nil {
		return fmt.Errorf("duplicate settlement accepted")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": contract.Status(), "receipt_head": contract.Head(), "duplicate_settlement": "refused", "mode": "local demonstration"})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
