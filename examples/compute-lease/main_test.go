package main

import (
	"fmt"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedulerConcurrencyAndDispatch(t *testing.T) {
	now := time.Now().UTC()
	a, x := lab.NewIdentity(), lab.NewIdentity()
	s := newScheduler(8192)
	base := lease{"one", "gpu-0", lab.PublicOf(a), now, now.Add(time.Minute), 4096}
	var wg sync.WaitGroup
	var wins atomic.Int32
	for n := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l := base
			l.ID = fmt.Sprint(n)
			if s.reserve(l, lab.Sign(a, "lease", l), now) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal(wins.Load())
	}
	var id string
	for k := range s.leases {
		id = k
	}
	d := dispatch{id, "vector-sum-v1"}
	if _, e := s.run(d, lab.Sign(x, "dispatch", d), now); e == nil {
		t.Fatal("wrong owner")
	}
	if _, e := s.run(d, lab.Sign(a, "dispatch", d), now.Add(-time.Second)); e == nil {
		t.Fatal("early dispatch")
	}
	if _, e := s.run(d, lab.Sign(a, "dispatch", d), base.End); e == nil {
		t.Fatal("expired dispatch")
	}
	if _, e := s.run(d, lab.Sign(a, "dispatch", d), now); e != nil {
		t.Fatal(e)
	}
	if _, e := s.run(d, lab.Sign(a, "dispatch", d), now); e == nil {
		t.Fatal("replay")
	}
	next := base
	next.ID = "adjacent"
	next.Start = base.End
	next.End = base.End.Add(time.Minute)
	if e := s.reserve(next, lab.Sign(a, "lease", next), now); e != nil {
		t.Fatal(e)
	}
	huge := next
	huge.ID = "huge"
	huge.MemoryMiB = 9000
	if s.reserve(huge, lab.Sign(a, "lease", huge), now) == nil {
		t.Fatal("memory overflow")
	}
}
