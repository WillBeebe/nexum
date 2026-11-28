// Package l2 batches Nexums. PoW seals the batch. That is the product
// shape: not one tx, a rollup of binding obligations.
package l2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/nexum"
	"github.com/WillBeebe/nexum/v2/internal/pow"
	"github.com/WillBeebe/nexum/v2/quarry/keccak"
)

// Batch is one L2 window of agreements.
type Batch struct {
	Agreements []*nexum.Agreement
	Header     pow.Header
}

// TermsDigest is the keccak commitment to an agreement's binding
// terms — the economic facts, independent of the action trail.
// Single source of truth: the economic terms live in the kernel's
// Agreement.TermsDigest() (SHA-256, JSON-canonical); the L2 seal
// re-commits to that exact digest under keccak, keeping the PoW domain
// separate from the ledger domain. The two can no longer drift apart,
// because there is only one field list.
func TermsDigest(a *nexum.Agreement) ([32]byte, error) {
	if a == nil {
		return [32]byte{}, fmt.Errorf("l2: nil agreement")
	}
	kernel, err := hex.DecodeString(a.TermsDigest())
	if err != nil || len(kernel) != 32 {
		return [32]byte{}, fmt.Errorf("l2: invalid kernel terms digest")
	}
	st := keccak.NewLegacyKeccak256()
	_, _ = st.Write([]byte("nex/l2/v1/terms\x00"))
	_, _ = st.Write(kernel)
	var out [32]byte
	copy(out[:], st.Sum(nil))
	return out, nil
}

// PolicyDigest returns the keccak commitment to an agreement's current
// execution policy snapshot (deadline, meter, and v2 mode/scheme).
func PolicyDigest(a *nexum.Agreement) ([32]byte, error) {
	if a == nil {
		return [32]byte{}, fmt.Errorf("l2: nil agreement")
	}
	return executionPolicyDigest(a)
}

// executionPolicyDigest binds the current operational policy separately from
// the kernel's immutable terms. A policy can change during an agreement's
// lifetime, but a previously sealed batch commits to its particular snapshot.
func executionPolicyDigest(a *nexum.Agreement) ([32]byte, error) {
	// v1 keeps second-or-snapshot deadline bytes exactly as sealed before.
	// v2 commits canonical RFC3339Nano time plus the execution mode. A v1
	// batch root must not move because a newer profile exists.
	if a.Format >= nexum.FormatV2 {
		b, err := json.Marshal(struct {
			Deadline string      `json:"deadline"`
			Meter    nexum.Meter `json:"meter"`
			Mode     string      `json:"mode"`
			Scheme   string      `json:"scheme"`
		}{a.Deadline.UTC().Format(time.RFC3339Nano), a.Meter, a.Mode, a.Scheme})
		if err != nil {
			return [32]byte{}, fmt.Errorf("l2: invalid execution policy: %w", err)
		}
		st := keccak.NewLegacyKeccak256()
		_, _ = st.Write([]byte("nex/l2/v2/execution-policy\x00"))
		_, _ = st.Write(b)
		var out [32]byte
		copy(out[:], st.Sum(nil))
		return out, nil
	}
	b, err := json.Marshal(struct {
		Deadline time.Time   `json:"deadline"`
		Meter    nexum.Meter `json:"meter"`
	}{a.Deadline.UTC(), a.Meter})
	if err != nil {
		return [32]byte{}, fmt.Errorf("l2: invalid execution policy: %w", err)
	}
	st := keccak.NewLegacyKeccak256()
	_, _ = st.Write([]byte("nex/l2/v1/execution-policy\x00"))
	_, _ = st.Write(b)
	var out [32]byte
	copy(out[:], st.Sum(nil))
	return out, nil
}

// Root is keccak over each agreement's terms digest, execution-policy digest,
// and last receipt hash, in order. Rewriting any of these moves the root.
func Root(as []*nexum.Agreement) ([32]byte, error) {
	st := keccak.NewLegacyKeccak256()
	if len(as) == 0 || len(as) > 4096 {
		return [32]byte{}, fmt.Errorf("l2: batch size out of bounds")
	}
	for _, a := range as {
		if a == nil || len(a.Receipts) == 0 || len(a.Receipts) > 128 {
			return [32]byte{}, fmt.Errorf("l2: empty agreement")
		}
		if err := a.VerifyReceipts(); err != nil {
			return [32]byte{}, err
		}
		terms, err := TermsDigest(a)
		if err != nil {
			return [32]byte{}, err
		}
		policy, err := executionPolicyDigest(a)
		if err != nil {
			return [32]byte{}, err
		}
		_, _ = st.Write(terms[:])
		_, _ = st.Write(policy[:])
		last := a.Receipts[len(a.Receipts)-1].Hash
		raw, err := hex.DecodeString(last)
		if err != nil {
			return [32]byte{}, err
		}
		_, _ = st.Write(raw)
	}
	sum := st.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out, nil
}

// Seal builds a header on the batch root and burns PoW.
func Seal(as []*nexum.Agreement, bits int, now time.Time) (Batch, error) {
	if bits < 1 || bits > 64 {
		return Batch{}, fmt.Errorf("l2: difficulty must be 1..64")
	}
	root, err := Root(as)
	if err != nil {
		return Batch{}, err
	}
	h := pow.Header{BatchRoot: root, TimeUnix: now.Unix(), DiffBits: bits}
	sealed, _, err := pow.Search(h, 0)
	if err != nil {
		return Batch{}, err
	}
	return Batch{Agreements: as, Header: sealed}, nil
}
