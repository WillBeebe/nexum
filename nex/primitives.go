package nex

import (
	"github.com/WillBeebe/nexum/internal/message"
	"github.com/WillBeebe/nexum/internal/nexum"
	"github.com/WillBeebe/nexum/internal/settle"
	"time"
)

type Status = nexum.Status

const (
	StatusOpen     = nexum.StatusOpen
	StatusLocked   = nexum.StatusLocked
	StatusAccepted = nexum.StatusAccepted
	StatusRejected = nexum.StatusRejected
	StatusExpired  = nexum.StatusExpired
)

// Record contains the signed offer, recipient decision and sender key release.
type Record = message.Record
type Offer = message.Offer
type Decision = message.Decision
type Release = message.Release

func Seal(i Identity, recipient Public, text []byte, invitation string, now, expiry time.Time) (Offer, []byte, error) {
	return message.Seal(i, recipient, text, invitation, now, expiry)
}
func Decide(i Identity, o Offer, action string, now time.Time) (Decision, error) {
	return message.Decide(i, o, action, now)
}
func WrapKey(i Identity, o Offer, d Decision, key []byte) (Release, error) {
	return message.WrapKey(i, o, d, key)
}
func Open(i Identity, r Record) ([]byte, error) { return message.Open(i, r) }

// EncryptedLedger holds local Paillier keys and blinding factors. Its owner
// sees inputs; ciphertext evaluation does not establish privacy from that owner.
type EncryptedLedger = settle.EncryptedLedger

func NewEncryptedLedger(bits int) (*EncryptedLedger, error) { return settle.NewEncryptedLedger(bits) }
