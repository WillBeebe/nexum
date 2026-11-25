// Package settle is L2: verified Nexum receipts batched onto a
// hash root. GPU VMs execute; the kernel still owns lock / accept /
// reject / no takebacks.
package settle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const (
	rootDomainEmpty   = "nex/settle/root/v2/empty\x00"
	rootDomainLeafHex = "nex/settle/root/v2/leaf-hex32\x00"
	rootDomainLeafRaw = "nex/settle/root/v2/leaf-raw\x00"
	rootDomainNode    = "nex/settle/root/v2/node\x00"
	rootDomainFinal   = "nex/settle/root/v2/final\x00"
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

// Root is a domain-separated pairwise merkle of receipt hashes committing
// leaf count and distinguishing empty lists, 32-byte hex leaves, raw leaves,
// and internal nodes.
func Root(hashes []string) string {
	if len(hashes) == 0 {
		sum := sha256.Sum256([]byte(rootDomainEmpty))
		return hex.EncodeToString(sum[:])
	}
	layer := make([][]byte, len(hashes))
	var lenBuf [8]byte
	for i, h := range hashes {
		dig := sha256.New()
		if len(h) == 64 {
			if b, err := hex.DecodeString(h); err == nil && len(b) == 32 {
				dig.Write([]byte(rootDomainLeafHex))
				dig.Write(b)
				layer[i] = dig.Sum(nil)
				continue
			}
		}
		dig.Write([]byte(rootDomainLeafRaw))
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(h)))
		dig.Write(lenBuf[:])
		dig.Write([]byte(h))
		layer[i] = dig.Sum(nil)
	}
	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			dup := make([]byte, len(layer[len(layer)-1]))
			copy(dup, layer[len(layer)-1])
			layer = append(layer, dup)
		}
		next := make([][]byte, 0, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			dig := sha256.New()
			dig.Write([]byte(rootDomainNode))
			dig.Write(layer[i])
			dig.Write(layer[i+1])
			next = append(next, dig.Sum(nil))
		}
		layer = next
	}
	final := sha256.New()
	final.Write([]byte(rootDomainFinal))
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(hashes)))
	final.Write(lenBuf[:])
	final.Write(layer[0])
	return hex.EncodeToString(final.Sum(nil))
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
