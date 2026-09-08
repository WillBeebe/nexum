// A worker earns a sealed bounty by producing a sorted, lossless artifact.
package main

import (
	"errors"
	"fmt"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"slices"
	"sync"
	"time"
)

type bounty struct {
	mu       sync.Mutex
	contract *lab.Contract
	input    []int
}

func newBounty(buyer, worker lab.Public, input []int, now time.Time) (*bounty, error) {
	c, e := lab.New("work-bounty", buyer, worker, 10, struct {
		Rule  string
		Input []int
	}{"ascending-lossless-v1", input}, now, now.Add(time.Hour))
	return &bounty{contract: c, input: slices.Clone(input)}, e
}
func (b *bounty) submit(buyer lab.Identity, artifact []int, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// The buyer recomputes the predicate; a worker's success assertion is insufficient.
	expected := slices.Clone(b.input)
	slices.Sort(expected)
	if !slices.Equal(expected, artifact) {
		return errors.New("artifact does not satisfy signed scope")
	}
	return b.contract.Execute(buyer, "settle", lab.Hash(artifact), now)
}
func main() {
	now := time.Now().UTC()
	buyer, worker := lab.NewIdentity(), lab.NewIdentity()
	b, e := newBounty(lab.PublicOf(buyer), lab.PublicOf(worker), []int{9, 2, 2, 5}, now)
	lab.Must(e)
	lab.Must(b.contract.Execute(buyer, "lock", "", now))
	lab.Must(b.contract.Execute(worker, "agree", "", now))
	if b.submit(buyer, []int{2, 5, 9}, now) == nil {
		panic("lost item accepted")
	}
	lab.Must(b.submit(buyer, []int{2, 2, 5, 9}, now))
	lab.Must(b.contract.VerifyReceipts())
	lab.Print(map[string]any{"example": "work-bounty", "status": b.contract.Status(), "invalid_artifact": "refused", "receipt": b.contract.Head(), "settlement": "local demonstration units"})
	fmt.Println("Verified the artifact before releasing the sealed bounty.")
}
