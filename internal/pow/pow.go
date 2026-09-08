// Package pow is GPU-barter work: burn cycles so a batch is expensive
// to rewrite. First engine is keccak (forked from geth crypto/keccak).
// Next: ethash-class memory-hard on GPU. Not a coin.
package pow

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/WillBeebe/nexum/quarry/keccak"
)

// Header is what we seal. BatchRoot binds the L2 agreements.
type Header struct {
	Parent    [32]byte
	BatchRoot [32]byte
	TimeUnix  int64
	DiffBits  int // leading zero bits required (tiny in tests)
	Nonce     uint64
}

// Hash is keccak-256 of the header fields including nonce.
func (h Header) Hash() []byte {
	st := keccak.NewLegacyKeccak256()
	_, _ = st.Write(h.Parent[:])
	_, _ = st.Write(h.BatchRoot[:])
	var tb [8]byte
	binary.BigEndian.PutUint64(tb[:], uint64(h.TimeUnix))
	_, _ = st.Write(tb[:])
	var db [4]byte
	binary.BigEndian.PutUint32(db[:], uint32(h.DiffBits))
	_, _ = st.Write(db[:])
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], h.Nonce)
	_, _ = st.Write(nb[:])
	return st.Sum(nil)
}

func leadingZeros(sum []byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(b)
		break
	}
	return n
}

// Valid reports whether Hash meets DiffBits.
func (h Header) Valid() bool {
	if h.DiffBits < 0 {
		return false
	}
	return leadingZeros(h.Hash()) >= h.DiffBits
}

// Search burns worker cycles until Valid. workers<=0 uses GOMAXPROCS.
func Search(h Header, workers int) (Header, uint64, error) {
	if h.DiffBits < 0 || h.DiffBits > 64 {
		return Header{}, 0, fmt.Errorf("pow: DiffBits %d", h.DiffBits)
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	var (
		found atomic.Uint64
		ok    atomic.Bool
		wg    sync.WaitGroup
	)
	found.Store(^uint64(0))
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			cand := h
			for n := uint64(w); ; n += uint64(workers) {
				if ok.Load() {
					return
				}
				cand.Nonce = n
				if cand.Valid() {
					found.Store(n)
					ok.Store(true)
					return
				}
			}
		}()
	}
	wg.Wait()
	n := found.Load()
	h.Nonce = n
	if !h.Valid() {
		return Header{}, 0, fmt.Errorf("pow: search failed")
	}
	return h, n, nil
}

// DigestHex is Hash as hex.
func (h Header) DigestHex() string {
	return hex.EncodeToString(h.Hash())
}
