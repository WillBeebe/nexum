package l2

import (
	"fmt"

	"github.com/WillBeebe/nexum/internal/nexum"
	"github.com/WillBeebe/nexum/internal/pow"
)

// Verify independently re-derives a seal instead of trusting the
// miner's word. The Keccak path already seals barter
// — this is the checker side of that claim. A batch is valid only if
// all three hold:
//
//  1. every agreement's receipt chain still verifies (no tail edits)
//  2. the root recomputed from the agreements equals BatchRoot
//     (no history rewrite, no swapping agreements behind a valid seal)
//  3. the header still meets its own PoW target at or above minBits
//     (no difficulty downgrade)
//
// Editing any term of any agreement breaks 1 (stale receipt hash) or,
// for a full re-chain, 2 — and then the re-miner must burn a fresh
// Search to make 3 true again. That is the "expensive to rewrite"
// property, checked here without asking the sealer anything.
func Verify(as []*nexum.Agreement, h pow.Header, minBits int) error {
	if h.DiffBits < minBits {
		return fmt.Errorf("l2: verify: DiffBits %d below floor %d", h.DiffBits, minBits)
	}
	root, err := Root(as)
	if err != nil {
		return fmt.Errorf("l2: verify: %w", err)
	}
	if root != h.BatchRoot {
		return fmt.Errorf("l2: verify: batch root mismatch — barter history rewritten or seal bound to other agreements")
	}
	if !h.Valid() {
		return fmt.Errorf("l2: verify: PoW invalid — seal not re-mineable at DiffBits %d", h.DiffBits)
	}
	return nil
}

// VerifyBatch verifies a whole Batch at minBits.
func VerifyBatch(b Batch, minBits int) error {
	return Verify(b.Agreements, b.Header, minBits)
}
