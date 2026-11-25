package keccak

import (
	"bytes"
	"encoding"
	"hash"
	"testing"
)

// TestV202_UnmarshalBinaryRejectsFullRateAbsorbingAndPreservesStateOnError verifies BUG-37:
// (1) UnmarshalBinary rejects n >= d.rate in spongeAbsorbing state (preventing Sum/padAndPermute
//
//	from XORing dsbyte into the first capacity byte d.a[d.rate]);
//
// (2) UnmarshalBinary permits n == d.rate in spongeSqueezing state and rejects n > d.rate;
// (3) UnmarshalBinary validates all fields before mutating receiver state on error.
func TestV202_UnmarshalBinaryRejectsFullRateAbsorbingAndPreservesStateOnError(t *testing.T) {
	cases := []struct {
		name string
		fn   func() hash.Hash
		rate int
	}{
		{"Keccak-256", NewLegacyKeccak256, rateK512},
		{"Keccak-512", NewLegacyKeccak512, rateK1024},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.fn()
			h.Write([]byte("before-error"))
			wantSum := h.Sum(nil)

			raw, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			// Case 1: n == rate in spongeAbsorbing state must fail without mutating h.
			fullRateAbsorb := append([]byte(nil), raw...)
			fullRateAbsorb[5] ^= 0xAA
			fullRateAbsorb[len(fullRateAbsorb)-2] = byte(tc.rate)
			fullRateAbsorb[len(fullRateAbsorb)-1] = byte(spongeAbsorbing)
			if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(fullRateAbsorb); err == nil {
				t.Fatalf("UnmarshalBinary accepted n==rate (%d) in spongeAbsorbing state", tc.rate)
			}
			if got := h.Sum(nil); !bytes.Equal(got, wantSum) {
				t.Fatalf("UnmarshalBinary mutated state on full-rate absorbing error: got %x want %x", got, wantSum)
			}

			// Case 2: n > rate in spongeSqueezing state must fail without mutating h.
			overRateSqueeze := append([]byte(nil), raw...)
			overRateSqueeze[5] ^= 0x55
			overRateSqueeze[len(overRateSqueeze)-2] = byte(tc.rate + 1)
			overRateSqueeze[len(overRateSqueeze)-1] = byte(spongeSqueezing)
			if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(overRateSqueeze); err == nil {
				t.Fatalf("UnmarshalBinary accepted n>rate (%d) in spongeSqueezing state", tc.rate+1)
			}
			if got := h.Sum(nil); !bytes.Equal(got, wantSum) {
				t.Fatalf("UnmarshalBinary mutated state on over-rate squeezing error: got %x want %x", got, wantSum)
			}

			// Case 3: invalid spongeDirection must fail without mutating h.
			badDir := append([]byte(nil), raw...)
			badDir[5] ^= 0xFF
			badDir[len(badDir)-2] = 7
			badDir[len(badDir)-1] = 99
			if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(badDir); err == nil {
				t.Fatal("UnmarshalBinary accepted invalid spongeDirection")
			}
			if got := h.Sum(nil); !bytes.Equal(got, wantSum) {
				t.Fatalf("UnmarshalBinary mutated state on invalid spongeDirection error: got %x want %x", got, wantSum)
			}

			// Case 4: n == rate in spongeSqueezing state is valid (exhausted output block).
			hSqueeze := tc.fn()
			fullRateSqueeze := append([]byte(nil), raw...)
			fullRateSqueeze[len(fullRateSqueeze)-2] = byte(tc.rate)
			fullRateSqueeze[len(fullRateSqueeze)-1] = byte(spongeSqueezing)
			if err := hSqueeze.(encoding.BinaryUnmarshaler).UnmarshalBinary(fullRateSqueeze); err != nil {
				t.Fatalf("UnmarshalBinary rejected valid n==rate (%d) in spongeSqueezing state: %v", tc.rate, err)
			}
		})
	}
}
