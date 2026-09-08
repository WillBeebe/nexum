// Contributions are aggregated with Nex's additive HE and milestone-gated release.
package main

import (
	"errors"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"github.com/WillBeebe/nexum/nex"
	"sync"
	"time"
)

type contribution struct {
	Fund, Contributor string
	Amount            int64
}
type milestone struct{ Fund, Artifact string }
type fund struct {
	mu               sync.Mutex
	id               string
	target           int64
	deadline         time.Time
	members          map[string]lab.Public
	verifier         lab.Public
	ledger           *nex.EncryptedLedger
	sealed           [][]byte
	seen             map[string]bool
	released         bool
	expectedArtifact string
}

func newFund(id string, target int64, members []lab.Public, verifier lab.Public, artifact string, deadline time.Time) (*fund, error) {
	if id == "" || target <= 0 || artifact == "" || len(members) < 2 || len(members) > 32 {
		return nil, errors.New("invalid fund")
	}
	if e := verifier.Validate(); e != nil {
		return nil, e
	}
	l, e := nex.NewEncryptedLedger(2048)
	if e != nil {
		return nil, e
	}
	f := &fund{id: id, target: target, deadline: deadline, members: map[string]lab.Public{}, verifier: verifier, ledger: l, seen: map[string]bool{}, expectedArtifact: artifact}
	for _, p := range members {
		if e := p.Validate(); e != nil {
			return nil, e
		}
		if _, ok := f.members[p.ID()]; ok {
			return nil, errors.New("duplicate member")
		}
		f.members[p.ID()] = p
	}
	// Contributions bind the complete immutable fund terms.
	f.id = lab.Hash(struct {
		ID       string
		Target   int64
		Members  []lab.Public
		Verifier lab.Public
		Artifact string
		Deadline time.Time
	}{id, target, members, verifier, artifact, deadline})
	return f, nil
}
func (f *fund) contribute(c contribution, sig []byte, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.members[c.Contributor]
	if !ok {
		return errors.New("unadmitted contributor")
	}
	if e := lab.Verify(p, "contribution", c, sig); e != nil {
		return e
	}
	if c.Fund != f.id || c.Amount <= 0 || c.Amount > f.target || f.released || f.seen[c.Contributor] || !now.Before(f.deadline) {
		return errors.New("contribution refused")
	}
	// Encryption takes place at this trusted local custody boundary. Plaintext
	// inputs and keys share this process; the evaluator only receives ciphertext.
	ct, e := f.ledger.SealLock(c.Amount)
	if e != nil {
		return e
	}
	f.sealed = append(f.sealed, ct)
	f.seen[c.Contributor] = true
	return nil
}
func (f *fund) release(m milestone, sig []byte, artifact []byte, now time.Time) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := lab.Verify(f.verifier, "milestone", m, sig); e != nil {
		return "", e
	}
	if m.Fund != f.id || m.Artifact != f.expectedArtifact || lab.Hash(artifact) != m.Artifact || f.released || !now.Before(f.deadline) {
		return "", errors.New("milestone refused")
	}
	sum, e := f.ledger.Aggregate(f.sealed)
	if e != nil {
		return "", e
	}
	proof, e := f.ledger.ProveEqual(sum, f.target)
	if e != nil {
		return "", e
	}
	ok, e := f.ledger.VerifyEqual(sum, f.target, proof)
	if e != nil {
		return "", e
	}
	if !ok {
		return "", errors.New("funding target not met exactly")
	}
	f.released = true
	return lab.Hash(struct {
		Milestone  milestone
		Sum, Proof []byte
		Target     int64
	}{m, sum, proof, f.target}), nil
}
func main() {
	now := time.Now().UTC()
	a, b, verifier := lab.NewIdentity(), lab.NewIdentity(), lab.NewIdentity()
	artifact := []byte("shared-cache-healthcheck:v1:passed")
	f, e := newFund("shared-cache-1", 10, []lab.Public{lab.PublicOf(a), lab.PublicOf(b)}, lab.PublicOf(verifier), lab.Hash(artifact), now.Add(time.Hour))
	lab.Must(e)
	for n, i := range []lab.Identity{a, b} {
		c := contribution{f.id, lab.PublicOf(i).ID(), int64(4 + 2*n)}
		lab.Must(f.contribute(c, lab.Sign(i, "contribution", c), now))
	}
	m := milestone{f.id, lab.Hash(artifact)}
	receipt, e := f.release(m, lab.Sign(verifier, "milestone", m), artifact, now)
	lab.Must(e)
	if _, e = f.release(m, lab.Sign(verifier, "milestone", m), artifact, now); e == nil {
		panic("duplicate release")
	}
	lab.Print(map[string]any{"example": "collective-fund", "contributors": len(f.seen), "funding_target": f.target, "milestone": "verified", "evaluation": "Paillier ciphertext aggregation and equality proof", "receipt": receipt, "individual_amounts_logged": false})
}
