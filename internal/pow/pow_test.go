package pow

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSearchMeetsBits(t *testing.T) {
	h := Header{TimeUnix: time.Now().Unix(), DiffBits: 8}
	got, _, err := Search(h, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Valid() {
		t.Fatalf("hash %s bits<%d", got.DigestHex(), got.DiffBits)
	}
}

func TestInvalidBitsRejected(t *testing.T) {
	var h Header
	h.DiffBits = -1
	if h.Valid() {
		t.Fatal("negative bits")
	}
}

func TestSearchContextCancellation(t *testing.T) {
	h := Header{DiffBits: 64, TimeUnix: time.Now().Unix()} // effectively unfindable
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, _, err := SearchContext(ctx, h, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancellation too slow: %v", elapsed)
	}
	// Same header without cancellation still searches (tiny difficulty).
	h.DiffBits = 8
	if _, _, err := SearchContext(context.Background(), h, 0); err != nil {
		t.Fatal(err)
	}
}
