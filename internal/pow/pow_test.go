package pow

import (
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
