package l2

import (
	"testing"
	"time"

	"github.com/WillBeebe/nexum/internal/nexum"
)

func TestSealBatch(t *testing.T) {
	now := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	a, err := nexum.OpenEscrow("h1", "buyer", "seller", 1, nexum.Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Lock("buyer", now); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept("seller", now); err != nil {
		t.Fatal(err)
	}
	b, err := Seal([]*nexum.Agreement{a}, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Header.Valid() {
		t.Fatal("unsealed")
	}
	if b.Header.BatchRoot == [32]byte{} {
		t.Fatal("empty root")
	}
}
