package pow

import (
	"bytes"
	"math/bits"
	"testing"
)

// TestV202_HeaderHashEncodesFull64BitDiffBits verifies BUG-41:
// Header.Hash() encodes the full 64-bit DiffBits value so DiffBits=8 and
// DiffBits=(1<<32)+8 never collide, and Valid() rejects DiffBits > 256.
func TestV202_HeaderHashEncodesFull64BitDiffBits(t *testing.T) {
	if bits.UintSize < 64 {
		t.Skip("64-bit int required")
	}
	h1 := Header{TimeUnix: 1700000000, DiffBits: 8, Nonce: 42}
	h2 := Header{TimeUnix: 1700000000, DiffBits: (1 << 32) + 8, Nonce: 42}
	if bytes.Equal(h1.Hash(), h2.Hash()) {
		t.Fatalf("Header.Hash() collided for DiffBits=%d and DiffBits=%d: %x",
			h1.DiffBits, h2.DiffBits, h1.Hash())
	}
	if h2.Valid() {
		t.Fatal("Header.Valid() accepted DiffBits > 256")
	}
	if (Header{DiffBits: 257}).Valid() {
		t.Fatal("Header.Valid() accepted DiffBits=257")
	}
	if (Header{DiffBits: -1}).Valid() {
		t.Fatal("Header.Valid() accepted negative DiffBits")
	}
}
