package message

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func identity(t *testing.T) Identity {
	t.Helper()
	i, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}
func public(t *testing.T, i Identity) Public {
	t.Helper()
	p, err := i.Public()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func offer(t *testing.T, a, b Identity, now time.Time) (Offer, []byte) {
	t.Helper()
	o, key, err := Seal(a, public(t, b), []byte("private message: meet at the observatory"), "May I send you the location?", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return o, key
}
func clone[T any](t *testing.T, value T) T {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy T
	if err := json.Unmarshal(b, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestConsentGatesDecryption(t *testing.T) {
	a, b, stranger := identity(t), identity(t), identity(t)
	now := time.Now().UTC()
	o, key := offer(t, a, b, now)
	r := Record{Offer: o}
	if _, err := Open(b, r); !errors.Is(err, ErrNotReady) {
		t.Fatalf("before agreement: %v", err)
	}
	d, err := Decide(b, o, "agree", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	r, err = r.ApplyDecision(d, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(b, r); !errors.Is(err, ErrNotReady) {
		t.Fatalf("before release: %v", err)
	}
	release, err := WrapKey(a, o, d, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err = r.ApplyRelease(release)
	if err != nil {
		t.Fatal(err)
	}
	text, err := Open(b, r)
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != "private message: meet at the observatory" {
		t.Fatalf("wrong plaintext: %q", text)
	}
	if _, err := Open(stranger, r); !errors.Is(err, ErrParty) {
		t.Fatalf("stranger opened: %v", err)
	}
	if _, err := Open(a, r); !errors.Is(err, ErrParty) {
		t.Fatalf("release for sender: %v", err)
	}
	if !strings.Contains(r.State(now), "key-released") {
		t.Fatal("release not terminal")
	}
	if _, err := r.ApplyDecision(d, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("exact retry after expiry: %v", err)
	}
	if _, err := r.ApplyRelease(release); err != nil {
		t.Fatalf("release retry: %v", err)
	}
	otherDecision, _ := Decide(b, o, "reject", now.Add(2*time.Second))
	if _, err := r.ApplyDecision(otherDecision, now.Add(2*time.Second)); !errors.Is(err, ErrState) {
		t.Fatalf("takeback: %v", err)
	}
}

func TestTamperReplayAndWrongParties(t *testing.T) {
	a, b, stranger := identity(t), identity(t), identity(t)
	now := time.Now().UTC()
	o, key := offer(t, a, b, now)
	d, _ := Decide(b, o, "agree", now.Add(time.Second))
	release, err := WrapKey(a, o, d, key)
	if err != nil {
		t.Fatal(err)
	}
	base := Record{Offer: o, Decision: &d, Release: &release}
	attacks := map[string]func(*Record){
		"ciphertext":         func(r *Record) { r.Offer.Ciphertext[15] ^= 1 },
		"invitation":         func(r *Record) { r.Offer.Terms.Invitation = "different consent" },
		"recipient":          func(r *Record) { r.Offer.Terms.Recipient = public(t, stranger) },
		"sender":             func(r *Record) { r.Offer.Terms.Sender = public(t, stranger) },
		"expiry":             func(r *Record) { r.Offer.Terms.ExpiresAt = now.Add(10 * time.Hour) },
		"id":                 func(r *Record) { r.Offer.Terms.ID = strings.Repeat("a", 64) },
		"acceptance":         func(r *Record) { r.Decision.Signature[0] ^= 1 },
		"acceptance time":    func(r *Record) { r.Decision.At = now.Add(2 * time.Second) },
		"wrapped key":        func(r *Record) { r.Release.WrappedKey[16] ^= 1 },
		"ephemeral key":      func(r *Record) { r.Release.Ephemeral[0] ^= 1 },
		"release signature":  func(r *Record) { r.Release.Signature[0] ^= 1 },
		"missing acceptance": func(r *Record) { r.Decision = nil },
	}
	for name, attack := range attacks {
		t.Run(name, func(t *testing.T) {
			r := clone(t, base)
			attack(&r)
			if r.Verify() == nil {
				t.Fatal("tampered receipt verified")
			}
			if _, err := Open(b, r); err == nil {
				t.Fatal("tampered envelope opened")
			}
		})
	}
	other, _ := offer(t, a, b, now)
	if d.Verify(other) == nil {
		t.Fatal("acceptance replayed against another message")
	}
	if release.Verify(other, d) == nil {
		t.Fatal("release replayed against another message")
	}
	if _, err := Decide(stranger, o, "agree", now); !errors.Is(err, ErrParty) {
		t.Fatal(err)
	}
	forged := d
	forged.Signature = sign(stranger, "decision", forged.unsigned())
	if _, err := (Record{Offer: o}).ApplyDecision(forged, now); err == nil {
		t.Fatal("forged actor accepted")
	}
	if _, err := WrapKey(stranger, o, d, key); !errors.Is(err, ErrParty) {
		t.Fatal(err)
	}
	badKey := bytes.Repeat([]byte{7}, 32)
	if _, err := WrapKey(a, o, d, badKey); err == nil {
		t.Fatal("wrong local content key released")
	}
	// Even a correctly signed but damaged ciphertext must fail AES-GCM auth.
	bad := clone(t, o)
	bad.Ciphertext[20] ^= 1
	bad.Signature = sign(a, "offer", bad.unsigned())
	badDecision, _ := Decide(b, bad, "agree", now.Add(time.Second))
	if _, err := WrapKey(a, bad, badDecision, key); err == nil {
		t.Fatal("GCM integrity check bypassed")
	}
}

func TestRejectExpiryAndBounds(t *testing.T) {
	a, b := identity(t), identity(t)
	now := time.Now().UTC()
	o, key := offer(t, a, b, now)
	reject, _ := Decide(b, o, "reject", now.Add(time.Second))
	r, err := (Record{Offer: o}).ApplyDecision(reject, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if r.State(now) != "rejected" {
		t.Fatal("wrong reject state")
	}
	if _, err := WrapKey(a, o, reject, key); err == nil {
		t.Fatal("rejected message released")
	}
	agree, _ := Decide(b, o, "agree", now.Add(2*time.Second))
	if _, err := r.ApplyDecision(agree, now.Add(2*time.Second)); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if _, err := (Record{Offer: o}).ApplyDecision(agree, o.Terms.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if _, err := Decide(b, o, "agree", o.Terms.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if (Record{Offer: o}).State(o.Terms.ExpiresAt) != "expired" {
		t.Fatal("expiry boundary")
	}
	if _, _, err := Seal(a, public(t, b), make([]byte, MaxText+1), "", now, now.Add(time.Hour)); err == nil {
		t.Fatal("oversized text accepted")
	}
	if _, _, err := Seal(a, public(t, b), nil, strings.Repeat("x", MaxInvitation+1), now, now.Add(time.Hour)); err == nil {
		t.Fatal("oversized invitation accepted")
	}
	if _, _, err := Seal(a, public(t, a), nil, "", now, now.Add(time.Hour)); err == nil {
		t.Fatal("same party accepted")
	}
	if _, err := r.ApplyRelease(Release{}); err == nil {
		t.Fatal("empty release accepted")
	}
	lowOrder := public(t, b)
	lowOrder.Encryption = make([]byte, 32)
	if lowOrder.Validate() == nil {
		t.Fatal("low-order encryption key accepted")
	}
	if _, _, err := Seal(a, public(t, b), []byte{0xff}, "", now, now.Add(time.Hour)); err == nil {
		t.Fatal("non-UTF-8 text accepted")
	}
}
