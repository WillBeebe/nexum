// Package l2 batches Nexums. PoW seals the batch. That is the product
// shape: not one tx, a rollup of binding obligations.
package l2

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/WillBeebe/nexum/internal/nexum"
	"github.com/WillBeebe/nexum/internal/pow"
	"github.com/WillBeebe/nexum/quarry/keccak"
)

// Batch is one L2 window of agreements.
type Batch struct {
	Agreements []*nexum.Agreement
	Header     pow.Header
}

// TermsDigest is the keccak commitment to an agreement's binding
// terms — the economic facts, independent of the action trail.
// Integrity requirement: the receipt chain proves what
// happened but hashReceipt never saw the terms, so a sealed batch
// could be re-chained with a different Amount and the old seal still
// verified. The root therefore folds terms + receipt tail per
// agreement.
func TermsDigest(a *nexum.Agreement) ([32]byte, error) {
	if a == nil {
		return [32]byte{}, fmt.Errorf("l2: nil agreement")
	}
	st := keccak.NewLegacyKeccak256()
	w := func(s string) {
		_, _ = st.Write([]byte(s))
		_, _ = st.Write([]byte{0}) // field separator, no ambiguities
	}
	w(a.ID)
	w(a.Kind)
	w(string(a.Buyer))
	w(string(a.Seller))
	w(strconv.FormatInt(a.Amount, 10))
	w(fmt.Sprintf("%+v", a.Unit))
	w(strconv.FormatFloat(a.Meter.CostUSD, 'f', -1, 64))
	w(a.Meter.Effort)
	w(strconv.FormatFloat(a.Meter.BudgetUSD, 'f', -1, 64))
	w(strconv.Itoa(a.Meter.MaxSteps))
	w(a.CreatedAt.UTC().Format(time.RFC3339Nano))
	w(a.Deadline.UTC().Format(time.RFC3339Nano))
	var out [32]byte
	copy(out[:], st.Sum(nil))
	return out, nil
}

// Root is keccak over each agreement's terms digest and last receipt
// hash, in order. Terms binding plus history binding: rewrite either
// side and the root moves.
func Root(as []*nexum.Agreement) ([32]byte, error) {
	st := keccak.NewLegacyKeccak256()
	for _, a := range as {
		if a == nil || len(a.Receipts) == 0 {
			return [32]byte{}, fmt.Errorf("l2: empty agreement")
		}
		if err := a.VerifyReceipts(); err != nil {
			return [32]byte{}, err
		}
		terms, err := TermsDigest(a)
		if err != nil {
			return [32]byte{}, err
		}
		_, _ = st.Write(terms[:])
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
