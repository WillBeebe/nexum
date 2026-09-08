// Package settle is L2: verified Nexum receipts batched onto a
// hash root. GPU VMs execute; the kernel still owns lock / accept /
// reject / no takebacks.
package settle

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Batch is one L2 settlement of verified agreements.
type Batch struct {
	Height       uint64    `json:"height"`
	At           time.Time `json:"at"`
	NodeIDs      []string  `json:"node_ids"`
	AgreementIDs []string  `json:"agreement_ids"`
	ReceiptRoot  string    `json:"receipt_root"`
	Devices      []string  `json:"devices"`
	Token        string    `json:"token,omitempty"`
	Agreements   int       `json:"agreements"`
	Nodes        int       `json:"nodes"`
	GPUs         int       `json:"gpus"`
}

// Root is a pairwise merkle of receipt hashes. Odd leaves are
// duplicated so the tree is even at every layer.
func Root(hashes []string) string {
	if len(hashes) == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:])
	}
	layer := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) == 0 {
			sum := sha256.Sum256([]byte(h))
			b = sum[:]
		}
		layer[i] = b
	}
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			dup := make([]byte, len(layer[len(layer)-1]))
			copy(dup, layer[len(layer)-1])
			layer = append(layer, dup)
		}
		next := make([][]byte, 0, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			buf := make([]byte, 0, len(layer[i])+len(layer[i+1]))
			buf = append(buf, layer[i]...)
			buf = append(buf, layer[i+1]...)
			sum := sha256.Sum256(buf)
			next = append(next, sum[:])
		}
		layer = next
	}
	return hex.EncodeToString(layer[0])
}

// Commit builds a batch at height 1 unless prevHeight is set by
// the caller via Height on a subsequent call.
func Commit(height uint64, receipts []string, nodeIDs, agreementIDs, devices []string, token string, gpus int, now time.Time) *Batch {
	if height == 0 {
		height = 1
	}
	return &Batch{
		Height:       height,
		At:           now.UTC(),
		NodeIDs:      nodeIDs,
		AgreementIDs: agreementIDs,
		ReceiptRoot:  Root(receipts),
		Devices:      devices,
		Token:        token,
		Agreements:   len(agreementIDs),
		Nodes:        len(nodeIDs),
		GPUs:         gpus,
	}
}
