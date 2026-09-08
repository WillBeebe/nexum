package main

import (
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBountyVerifiesAndSettlesOnce(t *testing.T) {
	now := time.Now().UTC()
	a, b := lab.NewIdentity(), lab.NewIdentity()
	input := []int{4, 1, 1}
	v, e := newBounty(lab.PublicOf(a), lab.PublicOf(b), input, now)
	if e != nil {
		t.Fatal(e)
	}
	input[0] = 0
	lab.Must(v.contract.Execute(a, "lock", "", now))
	lab.Must(v.contract.Execute(b, "agree", "", now))
	for _, bad := range [][]int{nil, {1, 4}, {1, 1, 5}, {4, 1, 1}} {
		if v.submit(a, bad, now) == nil {
			t.Fatal("bad artifact accepted", bad)
		}
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v.submit(a, []int{1, 1, 4}, now) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal(wins.Load())
	}
	if e = v.contract.VerifyReceipts(); e != nil {
		t.Fatal(e)
	}
}
