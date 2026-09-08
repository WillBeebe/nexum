// Package message implements consent to open a sealed message. Acceptance is
// consent to receive this envelope, not agreement to its undisclosed contents.
// Text and content keys stay at the agents; the relay validates signed steps.
package message

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

const (
	Kind          = "message.sealed/v1"
	MaxText       = 64 * 1024
	MaxInvitation = 1024
	HPKESuite     = "HPKE-X25519-HKDF-SHA256-AES256GCM"
)

var (
	ErrInvalid  = errors.New("message: invalid signed envelope or receipt")
	ErrParty    = errors.New("message: wrong party")
	ErrState    = errors.New("message: illegal state transition")
	ErrExpired  = errors.New("message: offer expired")
	ErrNotReady = errors.New("message: key not released")
)

// Public is a self-certifying identity. Pin the complete record out of band;
// its ID commits to both keys. A future number registry can resolve to this ID.
type Public struct {
	Signing    []byte `json:"signing_key"`
	Encryption []byte `json:"encryption_key"`
}

func (p Public) ID() string { return digest("identity", p) }

func (p Public) Validate() error {
	if len(p.Signing) != ed25519.PublicKeySize || len(p.Encryption) != 32 {
		return ErrInvalid
	}
	peer, err := ecdh.X25519().NewPublicKey(p.Encryption)
	if err != nil {
		return err
	}
	// NewPublicKey checks length only. ECDH also rejects low-order keys that
	// would make the shared secret all zero. This fixed scalar is not a secret.
	probe := make([]byte, 32)
	probe[0] = 1
	private, err := ecdh.X25519().NewPrivateKey(probe)
	if err != nil {
		return err
	}
	_, err = private.ECDH(peer)
	return err
}

// Identity is private agent state, never sent to the relay.
type Identity struct {
	Signing    []byte `json:"signing_private"`
	Encryption []byte `json:"encryption_private"`
}

func NewIdentity() (Identity, error) {
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	encryption, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Signing: signing, Encryption: encryption.Bytes()}, nil
}

func (i Identity) Public() (Public, error) {
	if len(i.Signing) != ed25519.PrivateKeySize {
		return Public{}, ErrInvalid
	}
	// Detect corrupted private-key files instead of using an inconsistent key.
	want := ed25519.NewKeyFromSeed(i.Signing[:ed25519.SeedSize])
	if !equalJSON([]byte(want), i.Signing) {
		return Public{}, ErrInvalid
	}
	k, err := ecdh.X25519().NewPrivateKey(i.Encryption)
	if err != nil {
		return Public{}, err
	}
	return Public{Signing: []byte(want.Public().(ed25519.PublicKey)), Encryption: k.PublicKey().Bytes()}, nil
}

type Terms struct {
	Kind           string     `json:"kind"`
	ID             string     `json:"id"`
	Sender         Public     `json:"sender"`
	Recipient      Public     `json:"recipient"`
	Invitation     string     `json:"invitation"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	KeySuite       string     `json:"key_suite,omitempty"`
	ConversationID string     `json:"conversation_id,omitempty"`
	ReplyTo        string     `json:"reply_to,omitempty"`
	Trade          *TradeLink `json:"trade,omitempty"`
}

type Offer struct {
	Terms      Terms  `json:"terms"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  []byte `json:"signature"`
}

func (o Offer) unsigned() Offer { o.Signature = nil; return o }
func (o Offer) Hash() string    { return digest("offer", o.unsigned()) }

func (o Offer) Verify() error {
	t := o.Terms
	if !supportedKeySuite(t.KeySuite) || (t.ConversationID != "" && !validID(t.ConversationID)) || (t.ReplyTo != "" && !validID(t.ReplyTo)) {
		return ErrInvalid
	}
	if t.KeySuite == RekeySuite && !validID(t.ConversationID) {
		return ErrInvalid
	}
	if t.Trade != nil && t.Trade.Validate() != nil {
		return ErrInvalid
	}
	if t.Kind != Kind || !validID(t.ID) || t.Sender.Validate() != nil || t.Recipient.Validate() != nil ||
		t.Sender.ID() == t.Recipient.ID() || len(t.Invitation) > MaxInvitation || !utf8.ValidString(t.Invitation) ||
		t.CreatedAt.IsZero() || !t.ExpiresAt.After(t.CreatedAt) ||
		len(o.Ciphertext) < 28 || len(o.Ciphertext) > MaxText+28 ||
		!verify(t.Sender, "offer", o.unsigned(), o.Signature) {
		return ErrInvalid
	}
	return nil
}

type Decision struct {
	Rekey        *RekeyPublic `json:"rekey,omitempty"`
	EnvelopeHash string       `json:"envelope_hash"`
	Action       string       `json:"action"` // agree | reject
	At           time.Time    `json:"at"`
	Signature    []byte       `json:"signature"`
}

func (d Decision) unsigned() Decision { d.Signature = nil; return d }
func (d Decision) Hash() string       { return digest("decision", d.unsigned()) }
func (d Decision) Verify(o Offer) error {
	if o.Terms.KeySuite == RekeySuite && d.Action == "agree" {
		if d.Rekey == nil || d.Rekey.Validate() != nil {
			return ErrInvalid
		}
	} else if d.Rekey != nil {
		return ErrInvalid
	}
	if o.Verify() != nil || d.EnvelopeHash != o.Hash() || (d.Action != "agree" && d.Action != "reject") ||
		d.At.Before(o.Terms.CreatedAt) || !d.At.Before(o.Terms.ExpiresAt) ||
		!verify(o.Terms.Recipient, "decision", d.unsigned(), d.Signature) {
		return ErrInvalid
	}
	return nil
}

func Decide(i Identity, o Offer, action string, now time.Time) (Decision, error) {
	return decide(i, o, action, now, nil)
}

func decide(i Identity, o Offer, action string, now time.Time, rekey *RekeyPublic) (Decision, error) {
	p, err := i.Public()
	if err != nil {
		return Decision{}, err
	}
	if p.ID() != o.Terms.Recipient.ID() {
		return Decision{}, ErrParty
	}
	if !now.Before(o.Terms.ExpiresAt) {
		return Decision{}, ErrExpired
	}
	d := Decision{EnvelopeHash: o.Hash(), Action: action, At: now.UTC(), Rekey: rekey}
	d.Signature = sign(i, "decision", d.unsigned())
	return d, d.Verify(o)
}

type Release struct {
	KEMCiphertext  []byte `json:"kem_ciphertext,omitempty"`
	EnvelopeHash   string `json:"envelope_hash"`
	AcceptanceHash string `json:"acceptance_hash"`
	Ephemeral      []byte `json:"ephemeral_key"`
	WrappedKey     []byte `json:"wrapped_key"`
	Signature      []byte `json:"signature"`
}

func (r Release) unsigned() Release { r.Signature = nil; return r }
func (r Release) Verify(o Offer, d Decision) error {
	if o.Terms.KeySuite == RekeySuite {
		if len(r.KEMCiphertext) != rekeyCiphertextSize {
			return ErrInvalid
		}
	} else if len(r.KEMCiphertext) != 0 {
		return ErrInvalid
	}
	wrappedLen := 60
	if o.Terms.KeySuite == HPKESuite {
		wrappedLen = 48
	}
	if d.Verify(o) != nil || d.Action != "agree" || r.EnvelopeHash != o.Hash() ||
		r.AcceptanceHash != d.Hash() || len(r.Ephemeral) != 32 || len(r.WrappedKey) != wrappedLen ||
		!verify(o.Terms.Sender, "release", r.unsigned(), r.Signature) {
		return ErrInvalid
	}
	return nil
}

// Record is a linked chain of signed receipts: offer -> decision -> release.
// Each step commits to its predecessor; the relay cannot substitute an offer
// or invent either agent's consent. This is not distributed finality.
type Record struct {
	Offer    Offer     `json:"offer"`
	Decision *Decision `json:"decision,omitempty"`
	Release  *Release  `json:"release,omitempty"`
}

func (r Record) Verify() error {
	if err := r.Offer.Verify(); err != nil {
		return err
	}
	if r.Decision != nil {
		if err := r.Decision.Verify(r.Offer); err != nil {
			return err
		}
	}
	if r.Release != nil {
		if r.Decision == nil {
			return ErrInvalid
		}
		return r.Release.Verify(r.Offer, *r.Decision)
	}
	return nil
}

func (r Record) State(now time.Time) string {
	if r.Release != nil {
		return "key-released"
	}
	if r.Decision != nil {
		if r.Decision.Action == "agree" {
			return "accepted"
		}
		return "rejected"
	}
	if !now.Before(r.Offer.Terms.ExpiresAt) {
		return "expired"
	}
	return "offered"
}

func (r Record) ApplyDecision(d Decision, now time.Time) (Record, error) {
	if err := d.Verify(r.Offer); err != nil {
		return r, err
	}
	if r.Decision != nil {
		if equalJSON(*r.Decision, d) {
			return r, nil
		} // exact retry, no new step
		return r, ErrState
	}
	if !now.Before(r.Offer.Terms.ExpiresAt) {
		return r, ErrExpired
	}
	if d.At.After(now.Add(time.Minute)) {
		return r, ErrInvalid
	}
	r.Decision = &d
	return r, nil
}

func (r Record) ApplyRelease(release Release) (Record, error) {
	if r.Decision == nil {
		return r, ErrState
	}
	if err := release.Verify(r.Offer, *r.Decision); err != nil {
		return r, err
	}
	if r.Release != nil {
		if equalJSON(*r.Release, release) {
			return r, nil
		}
		return r, ErrState
	}
	r.Release = &release
	return r, nil
}

func wire(domain string, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("message: cannot encode protocol value: %v", err))
	}
	return append([]byte("nex/message/v1/"+domain+"\x00"), b...)
}
func digest(domain string, v any) string {
	h := sha256.Sum256(wire(domain, v))
	return hex.EncodeToString(h[:])
}
func sign(i Identity, domain string, v any) []byte {
	return ed25519.Sign(i.Signing, wire(domain, v))
}
func verify(p Public, domain string, v any, sig []byte) bool {
	return len(p.Signing) == ed25519.PublicKeySize && ed25519.Verify(p.Signing, wire(domain, v), sig)
}
func equalJSON(a, b any) bool { return string(wire("equal", a)) == string(wire("equal", b)) }
func validID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == id
}
