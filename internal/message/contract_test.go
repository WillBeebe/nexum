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

func TestLegacySuiteWriteDeprecated(t *testing.T) {
	a, b := identity(t), identity(t)
	// A fresh offer signed today with the empty (legacy) suite: reading it
	// is fine, but WrapKey must refuse to release under it.
	now := time.Now().UTC()
	o, key := offer(t, a, b, now)
	o.Terms.KeySuite = ""
	var err error
	o.Ciphertext, err = encrypt(key, []byte("legacy message"), wire("text", o.Terms))
	if err != nil {
		t.Fatal(err)
	}
	o.Signature = sign(a, "offer", o.unsigned())
	d, err := Decide(b, o, "agree", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = WrapKey(a, o, d, key); !errors.Is(err, ErrInvalid) {
		t.Fatalf("legacy release after cutoff: %v", err)
	}
	// The same offer signed before the cutoff still releases (read compat).
	old := o
	old.Terms.CreatedAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	old.Terms.ExpiresAt = old.Terms.CreatedAt.Add(time.Hour)
	old.Ciphertext, err = encrypt(key, []byte("legacy message"), wire("text", old.Terms))
	if err != nil {
		t.Fatal(err)
	}
	old.Signature = sign(a, "offer", old.unsigned())
	dOld, err := Decide(b, old, "agree", time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = WrapKey(a, old, dOld, key); err != nil {
		t.Fatalf("pre-cutoff legacy release: %v", err)
	}
}

func TestConversationGapDetected(t *testing.T) {
	a, b := identity(t), identity(t)
	now := time.Now().UTC()
	first, _, _ := Seal(a, public(t, b), []byte("one"), "start", now, now.Add(time.Hour))
	second, _, _ := SealWithOptions(a, public(t, b), []byte("two"), "continue", now, now.Add(time.Hour),
		SendOptions{ConversationID: first.Terms.ConversationID, ReplyTo: first.Terms.ID, ReplyChain: ReplyChainHash(Record{Offer: first})})
	third, _, _ := SealWithOptions(a, public(t, b), []byte("three"), "continue", now, now.Add(time.Hour),
		SendOptions{ConversationID: first.Terms.ConversationID, ReplyTo: second.Terms.ID, ReplyChain: ReplyChainHash(Record{Offer: second})})
	if err := VerifyConversationOrder([]Record{{Offer: first}, {Offer: second}, {Offer: third}}); err != nil {
		t.Fatal(err)
	}
	// Drop the middle message: the relay hid it. The gap must be visible.
	if err := VerifyConversationOrder([]Record{{Offer: first}, {Offer: third}}); err == nil {
		t.Fatal("conversation gap not detected")
	}
	// Out-of-order delivery is fine.
	if err := VerifyConversationOrder([]Record{{Offer: third}, {Offer: first}, {Offer: second}}); err != nil {
		t.Fatal(err)
	}
}

func TestOfferReleaseByInvarianceAndDeadline(t *testing.T) {
	a, b := identity(t), identity(t)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	o, _ := offer(t, a, b, now)
	if o.Terms.ReleaseBy != nil {
		t.Fatal("default offer unexpectedly set ReleaseBy")
	}
	rawTerms, err := json.Marshal(o.Terms)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rawTerms, []byte("release_by")) {
		t.Fatalf("nil ReleaseBy changed serialized terms: %s", rawTerms)
	}
	type v1Terms struct {
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
		ReplyChain     string     `json:"reply_chain,omitempty"`
		Trade          *TradeLink `json:"trade,omitempty"`
	}
	type v1Offer struct {
		Terms      v1Terms `json:"terms"`
		Ciphertext []byte  `json:"ciphertext"`
		Signature  []byte  `json:"signature"`
	}
	legacyUnsigned := v1Offer{
		Terms: v1Terms{
			Kind: o.Terms.Kind, ID: o.Terms.ID, Sender: o.Terms.Sender, Recipient: o.Terms.Recipient,
			Invitation: o.Terms.Invitation, CreatedAt: o.Terms.CreatedAt, ExpiresAt: o.Terms.ExpiresAt,
			KeySuite: o.Terms.KeySuite, ConversationID: o.Terms.ConversationID, ReplyTo: o.Terms.ReplyTo,
			ReplyChain: o.Terms.ReplyChain, Trade: o.Terms.Trade,
		},
		Ciphertext: o.Ciphertext,
	}
	if !bytes.Equal(wire("offer", o.unsigned()), wire("offer", legacyUnsigned)) || o.Hash() != digest("offer", legacyUnsigned) {
		t.Fatal("Offer v1 canonical bytes or hash changed when ReleaseBy is nil")
	}

	expiry := now.Add(5 * time.Minute)
	if _, _, err := SealWithReleaseBy(a, public(t, b), []byte("deadline"), "open", now, expiry, expiry, SendOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ReleaseBy == ExpiresAt accepted: %v", err)
	}
	if _, _, err := SealWithReleaseBy(a, public(t, b), []byte("deadline"), "open", now, expiry, expiry.Add(-time.Second), SendOptions{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ReleaseBy < ExpiresAt accepted: %v", err)
	}

	releaseBy := expiry.Add(5 * time.Minute)
	bounded, key, err := SealWithReleaseBy(a, public(t, b), []byte("bounded release secret"), "open", now, expiry, releaseBy, SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tamperedNil := clone(t, bounded)
	tamperedNil.Terms.ReleaseBy = nil
	if tamperedNil.Verify() == nil {
		t.Fatal("stripping signed ReleaseBy passed Verify")
	}
	tamperedLater := clone(t, bounded)
	later := releaseBy.Add(time.Minute)
	tamperedLater.Terms.ReleaseBy = &later
	if tamperedLater.Verify() == nil {
		t.Fatal("extending signed ReleaseBy passed Verify")
	}

	d, err := Decide(b, bounded, "agree", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := (Record{Offer: bounded}).ApplyDecision(d, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rel, err := WrapKey(a, bounded, d, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.ApplyReleaseAt(rel, releaseBy); !errors.Is(err, ErrExpired) {
		t.Fatalf("release at exact ReleaseBy should fail with ErrExpired: %v", err)
	}
	if _, err := rec.ApplyReleaseAt(rel, releaseBy.Add(time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("release after ReleaseBy should fail with ErrExpired: %v", err)
	}
	released, err := rec.ApplyReleaseAt(rel, releaseBy.Add(-time.Nanosecond))
	if err != nil {
		t.Fatalf("release before ReleaseBy failed: %v", err)
	}
	if _, err := released.ApplyReleaseAt(rel, releaseBy.Add(time.Hour)); err != nil {
		t.Fatalf("idempotent exact release retry after ReleaseBy failed: %v", err)
	}
	relOther, err := WrapKey(a, bounded, d, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := released.ApplyReleaseAt(relOther, releaseBy.Add(-time.Second)); !errors.Is(err, ErrState) {
		t.Fatalf("competing release did not return ErrState: %v", err)
	}
	if _, err := rec.ApplyRelease(rel); err != nil {
		t.Fatalf("zero-time ApplyRelease unit helper failed: %v", err)
	}
	plain, err := Open(b, released)
	if err != nil || string(plain) != "bounded release secret" {
		t.Fatalf("Open bounded release: %q %v", plain, err)
	}
}

func TestNewTradeAuditValidation(t *testing.T) {
	id1 := strings.Repeat("1", 64)
	id2 := strings.Repeat("2", 64)
	attempt := strings.Repeat("3", 64)
	audit, err := NewTradeAudit(id2, TradeAudit{
		TradeID:     id1,
		AttemptID:   attempt,
		HeadHash:    strings.Repeat("a", 64),
		Disposition: "expired",
	})
	if err != nil {
		t.Fatal(err)
	}
	if audit.TradeID != id2 || audit.PriorTrade != id1 || audit.AttemptID != attempt || audit.Disposition != "expired" {
		t.Fatalf("unexpected TradeAudit: %+v", audit)
	}
	for _, bad := range []struct {
		next  string
		prior TradeAudit
	}{
		{"short", TradeAudit{TradeID: id1, AttemptID: attempt, HeadHash: "h", Disposition: "expired"}},
		{id2, TradeAudit{TradeID: "bad", AttemptID: attempt, HeadHash: "h", Disposition: "expired"}},
		{id2, TradeAudit{TradeID: id1, AttemptID: "bad", HeadHash: "h", Disposition: "expired"}},
		{id2, TradeAudit{TradeID: id1, AttemptID: attempt, HeadHash: "", Disposition: "expired"}},
		{id2, TradeAudit{TradeID: id1, AttemptID: attempt, HeadHash: "h", Disposition: ""}},
	} {
		if _, err := NewTradeAudit(bad.next, bad.prior); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected ErrInvalid for %+v, got %v", bad, err)
		}
	}
}
