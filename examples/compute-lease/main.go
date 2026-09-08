// A local scheduler reserves one device and enforces dispatch at the boundary.
package main

import (
	"errors"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"sync"
	"time"
)

type lease struct {
	ID, Device string
	Owner      lab.Public
	Start, End time.Time
	MemoryMiB  int
}
type reservation struct {
	terms         lease
	running, done bool
}
type scheduler struct {
	mu       sync.Mutex
	capacity int
	leases   map[string]*reservation
}

func newScheduler(memory int) *scheduler {
	return &scheduler{capacity: memory, leases: map[string]*reservation{}}
}
func (s *scheduler) reserve(l lease, sig []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := lab.Verify(l.Owner, "lease", l, sig); e != nil {
		return e
	}
	if l.ID == "" || l.Device != "gpu-0" || l.Start.Before(now) || !l.End.After(l.Start) || l.MemoryMiB <= 0 || l.MemoryMiB > s.capacity {
		return errors.New("invalid lease")
	}
	if _, ok := s.leases[l.ID]; ok {
		return errors.New("duplicate lease")
	}
	for _, r := range s.leases {
		if l.Start.Before(r.terms.End) && r.terms.Start.Before(l.End) {
			return errors.New("device already reserved")
		}
	}
	s.leases[l.ID] = &reservation{terms: l}
	return nil
}

type dispatch struct{ LeaseID, Job string }

func (s *scheduler) run(d dispatch, sig []byte, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.leases[d.LeaseID]
	if !ok {
		return "", errors.New("unknown lease")
	}
	if e := lab.Verify(r.terms.Owner, "dispatch", d, sig); e != nil {
		return "", e
	}
	if now.Before(r.terms.Start) || !now.Before(r.terms.End) || r.running || r.done {
		return "", errors.New("lease unavailable")
	}
	if d.Job != "vector-sum-v1" {
		return "", errors.New("job not admitted")
	}
	r.running = true
	// Fixed, bounded CPU fixture stands in for a device adapter. There is no GPU claim.
	sum := 0
	for i := 0; i < 1024; i++ {
		sum += i
	}
	r.running = false
	r.done = true
	return lab.Hash(struct {
		Lease, Job string
		Sum        int
	}{d.LeaseID, d.Job, sum}), nil
}
func main() {
	now := time.Now().UTC()
	renter, provider := lab.NewIdentity(), lab.NewIdentity()
	l := lease{"lease-1", "gpu-0", lab.PublicOf(renter), now, now.Add(time.Minute), 4096}
	s := newScheduler(8192)
	c, e := lab.New("compute-lease", lab.PublicOf(renter), lab.PublicOf(provider), 4, l, now, now.Add(2*time.Minute))
	lab.Must(e)
	lab.Must(c.Execute(renter, "lock", "", now))
	lab.Must(s.reserve(l, lab.Sign(renter, "lease", l), now))
	lab.Must(c.Execute(provider, "agree", "", now))
	overlap := l
	overlap.ID = "lease-2"
	if s.reserve(overlap, lab.Sign(renter, "lease", overlap), now) == nil {
		panic("overlap allowed")
	}
	d := dispatch{l.ID, "vector-sum-v1"}
	receipt, e := s.run(d, lab.Sign(renter, "dispatch", d), now)
	lab.Must(e)
	lab.Must(c.Execute(renter, "settle", receipt, now))
	lab.Must(c.VerifyReceipts())
	lab.Print(map[string]any{"example": "compute-lease", "status": c.Status(), "overlapping_reservation": "refused", "receipt": c.Head(), "executor": "bounded CPU fixture; GPU adapter required"})
}
