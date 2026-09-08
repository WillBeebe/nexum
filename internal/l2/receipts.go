package l2

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/WillBeebe/nexum/internal/pow"
	"github.com/WillBeebe/nexum/quarry/keccak"
)

// ReceiptCommitment carries no message plaintext or keys. A client holding
// the signed message record independently derives Hash before verifying it.
type ReceiptCommitment struct {
	Sequence int64  `json:"sequence"`
	ID       string `json:"id"`
	Action   string `json:"action"`
	Hash     string `json:"hash"`
}
type ReceiptBatch struct {
	Version     int                 `json:"version"`
	Commitments []ReceiptCommitment `json:"commitments"`
	Header      pow.Header          `json:"header"`
}

func ReceiptRoot(cs []ReceiptCommitment) ([32]byte, error) {
	var zero [32]byte
	if len(cs) == 0 || len(cs) > 4096 {
		return zero, fmt.Errorf("l2: receipt batch size out of bounds")
	}
	nodes := make([][32]byte, 0, len(cs))
	var previous int64
	for _, c := range cs {
		h, e := hex.DecodeString(c.Hash)
		if e != nil || len(h) != 32 || c.Sequence <= previous || c.ID == "" || c.Action == "" {
			return zero, fmt.Errorf("l2: invalid receipt commitment")
		}
		previous = c.Sequence
		raw, e := json.Marshal(c)
		if e != nil {
			return zero, e
		}
		nodes = append(nodes, receiptHash(append([]byte("nex/l2/receipt/leaf/v1\x00"), raw...)))
	}
	for len(nodes) > 1 {
		next := make([][32]byte, 0, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); i += 2 {
			right := nodes[i]
			if i+1 < len(nodes) {
				right = nodes[i+1]
			}
			raw := append([]byte("nex/l2/receipt/node/v1\x00"), nodes[i][:]...)
			raw = append(raw, right[:]...)
			next = append(next, receiptHash(raw))
		}
		nodes = next
	}
	return nodes[0], nil
}
func receiptHash(b []byte) [32]byte {
	h := keccak.NewLegacyKeccak256()
	_, _ = h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func SealReceipts(cs []ReceiptCommitment, parent [32]byte, bits int, now time.Time) (ReceiptBatch, error) {
	if bits < 1 || bits > 24 {
		return ReceiptBatch{}, fmt.Errorf("l2: difficulty must be 1..24")
	}
	root, err := ReceiptRoot(cs)
	if err != nil {
		return ReceiptBatch{}, err
	}
	h, _, err := pow.Search(pow.Header{Parent: parent, BatchRoot: root, DiffBits: bits, TimeUnix: now.Unix()}, 0)
	return ReceiptBatch{Version: 1, Commitments: cs, Header: h}, err
}
func VerifyReceiptBatch(b ReceiptBatch, parent [32]byte, minBits int) error {
	root, err := ReceiptRoot(b.Commitments)
	if err != nil {
		return err
	}
	if b.Version != 1 || minBits < 1 || b.Header.DiffBits < minBits || b.Header.Parent != parent || b.Header.BatchRoot != root || !b.Header.Valid() {
		return fmt.Errorf("l2: invalid receipt batch or parent")
	}
	return nil
}
