// Consent and a buyer-signed condition receipt gate release of an encrypted artifact.
package main

import (
	"errors"
	"github.com/WillBeebe/nexum/examples/internal/lab"
	"github.com/WillBeebe/nexum/nex"
	"sync"
	"time"
)

type condition struct{ OfferHash, Requirement string }
type exchange struct {
	mu          sync.Mutex
	record      nex.Record
	key         []byte
	sender      lab.Identity
	requirement condition
	expiry      time.Time
}

func newExchange(sender lab.Identity, recipient lab.Public, artifact []byte, now time.Time) (*exchange, error) {
	expiry := now.Add(time.Hour)
	offer, key, e := nex.Seal(sender, recipient, artifact, "Agree to receive the report after acknowledging its usage terms.", now, expiry)
	if e != nil {
		return nil, e
	}
	return &exchange{record: nex.Record{Offer: offer}, key: key, sender: sender, requirement: condition{offer.Hash(), "internal-evaluation-only-v1"}, expiry: expiry}, nil
}
func (x *exchange) decide(d nex.Decision, now time.Time) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	r, e := x.record.ApplyDecision(d, now)
	if e == nil {
		x.record = r
	}
	return e
}
func (x *exchange) release(receipt condition, sig []byte, recipient lab.Public, now time.Time) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if !now.Before(x.expiry) || x.record.Release != nil {
		return errors.New("release unavailable")
	}
	if receipt != x.requirement {
		return errors.New("condition receipt does not match")
	}
	// Bind the attestation to the actual recipient in this offer, not a caller-selected key.
	if recipient.ID() != x.record.Offer.Terms.Recipient.ID() {
		return errors.New("wrong recipient")
	}
	if e := lab.Verify(recipient, "condition", receipt, sig); e != nil {
		return e
	}
	if x.record.Decision == nil {
		return errors.New("recipient consent required")
	}
	release, e := nex.WrapKey(x.sender, x.record.Offer, *x.record.Decision, x.key)
	if e != nil {
		return e
	}
	r, e := x.record.ApplyRelease(release)
	if e != nil {
		return e
	}
	x.record = r
	clear(x.key)
	x.key = nil
	return nil
}
func main() {
	now := time.Now().UTC()
	sender, recipient := lab.NewIdentity(), lab.NewIdentity()
	x, e := newExchange(sender, lab.PublicOf(recipient), []byte("Example report: verified citation fixture://research/42"), now)
	lab.Must(e)
	if _, e = nex.Open(recipient, x.record); e == nil {
		panic("opened before agreement")
	}
	d, e := nex.Decide(recipient, x.record.Offer, "agree", now)
	lab.Must(e)
	lab.Must(x.decide(d, now))
	if _, e = nex.Open(recipient, x.record); e == nil {
		panic("opened before condition receipt")
	}
	lab.Must(x.release(x.requirement, lab.Sign(recipient, "condition", x.requirement), lab.PublicOf(recipient), now))
	plaintext, e := nex.Open(recipient, x.record)
	lab.Must(e)
	if len(plaintext) == 0 {
		panic("empty report")
	}
	lab.Print(map[string]any{"example": "knowledge-exchange", "before_consent": "encrypted; recipient refused", "after_consent_before_condition": "recipient refused", "after_release": "recipient decrypted", "offer": x.record.Offer.Hash(), "contents_logged": false})
}
