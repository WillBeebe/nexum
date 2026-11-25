package message

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestV202_VerifyConversationOrderRejectsSplicingMismatchDanglingAndDuplicates
// verifies BUG-17: VerifyConversationOrder requires consistent ConversationID,
// ReplyChain matching ReplyTo in the same conversation, non-dangling ReplyTo,
// no duplicates, and no reply cycles.
func TestV202_VerifyConversationOrderRejectsSplicingMismatchDanglingAndDuplicates(t *testing.T) {
	a, b, c, d := identity(t), identity(t), identity(t), identity(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	conv1Root, _, err := Seal(a, public(t, b), []byte("hello conv 1"), "conv1", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	conv1Second, _, err := SealWithOptions(b, public(t, a), []byte("reply conv 1"), "reply1", now, now.Add(time.Hour), SendOptions{
		ConversationID: conv1Root.Terms.ConversationID,
		ReplyTo:        conv1Root.Terms.ID,
		ReplyChain:     ReplyChainHash(Record{Offer: conv1Root}),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Valid reply without optional ReplyChain still passes.
	conv1LegacyReply, _, err := SealWithOptions(a, public(t, b), []byte("no-chain reply"), "reply2", now, now.Add(time.Hour), SendOptions{
		ConversationID: conv1Root.Terms.ConversationID,
		ReplyTo:        conv1Second.Terms.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConversationOrder([]Record{{Offer: conv1Root}, {Offer: conv1Second}, {Offer: conv1LegacyReply}}); err != nil {
		t.Fatalf("valid conversation rejected: %v", err)
	}

	// Conversation 2 (unrelated parties, distinct ConversationID).
	conv2Root, _, err := Seal(c, public(t, d), []byte("hello conv 2"), "conv2", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Cross-conversation splice: claims conv2 ConversationID and ReplyTo conv2Root,
	// yet ReplyChain points to conv1Root in a different conversation.
	crossReply, _, err := SealWithOptions(c, public(t, d), []byte("spliced"), "splice", now, now.Add(time.Hour), SendOptions{
		ConversationID: conv2Root.Terms.ConversationID,
		ReplyTo:        conv2Root.Terms.ID,
		ReplyChain:     ReplyChainHash(Record{Offer: conv1Root}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConversationOrder([]Record{{Offer: conv1Root}, {Offer: conv2Root}, {Offer: crossReply}}); err == nil {
		t.Fatal("VerifyConversationOrder accepted cross-conversation splice")
	}

	// Same-conversation ReplyTo / ReplyChain mismatch.
	mismatchedReply, _, err := SealWithOptions(a, public(t, b), []byte("mismatch"), "mismatch", now, now.Add(time.Hour), SendOptions{
		ConversationID: conv1Root.Terms.ConversationID,
		ReplyTo:        conv1Second.Terms.ID,
		ReplyChain:     ReplyChainHash(Record{Offer: conv1Root}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConversationOrder([]Record{{Offer: conv1Root}, {Offer: conv1Second}, {Offer: mismatchedReply}}); err == nil {
		t.Fatal("VerifyConversationOrder accepted ReplyTo/ReplyChain mismatch in same conversation")
	}

	// ReplyChain without ReplyTo.
	chainWithoutReplyTo, _, err := SealWithOptions(b, public(t, a), []byte("no reply_to"), "no-rt", now, now.Add(time.Hour), SendOptions{
		ConversationID: conv1Root.Terms.ConversationID,
		ReplyChain:     ReplyChainHash(Record{Offer: conv1Root}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConversationOrder([]Record{{Offer: conv1Root}, {Offer: chainWithoutReplyTo}}); err == nil {
		t.Fatal("VerifyConversationOrder accepted ReplyChain without matching ReplyTo")
	}

	// Dangling ReplyTo with empty ReplyChain.
	danglingReplyTo, _, err := SealWithOptions(a, public(t, b), []byte("orphan"), "orphan", now, now.Add(time.Hour), SendOptions{
		ConversationID: conv1Root.Terms.ConversationID,
		ReplyTo:        strings.Repeat("f", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConversationOrder([]Record{{Offer: conv1Root}, {Offer: danglingReplyTo}}); err == nil {
		t.Fatal("VerifyConversationOrder accepted dangling ReplyTo")
	}

	// Duplicate record.
	if err := VerifyConversationOrder([]Record{{Offer: conv1Root}, {Offer: conv1Root}}); err == nil {
		t.Fatal("VerifyConversationOrder accepted duplicate record")
	}

	// Unrelated conversations with no ReplyChain/ReplyTo still rejected.
	if err := VerifyConversationOrder([]Record{{Offer: conv1Root}, {Offer: conv2Root}}); err == nil {
		t.Fatal("VerifyConversationOrder accepted mixed ConversationIDs")
	}
}

// TestV202_ValidateTradeSuccessorRejectsForgedRejectedAndMismatchedChain
// verifies BUG-18: ValidateTradeSuccessor calls parent.Verify() and child.Verify(),
// requires parent.Decision != nil && parent.Decision.Action == "agree", and
// verifies child.Terms.ReplyChain matches ReplyChainHash(parent) when set.
func TestV202_ValidateTradeSuccessorRejectsForgedRejectedAndMismatchedChain(t *testing.T) {
	a, b := identity(t), identity(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	tradeID := strings.Repeat("1", 64)
	commit := strings.Repeat("2", 64)

	// (1) Unsigned/forged/rejected parent with dummy Release and unsigned/expired child.
	forgedParent := Record{
		Offer: Offer{
			Terms: Terms{
				Kind:           Kind,
				ID:             strings.Repeat("3", 64),
				Sender:         public(t, a),
				Recipient:      public(t, b),
				CreatedAt:      now,
				ExpiresAt:      now.Add(time.Hour),
				ConversationID: strings.Repeat("4", 64),
				Trade:          &TradeLink{ID: tradeID, Action: "request", Commitment: commit},
			},
			Ciphertext: []byte("not-even-valid"),
			Signature:  nil,
		},
		Decision: &Decision{Action: "reject"},
		Release:  &Release{},
	}
	forgedChild := Offer{
		Terms: Terms{
			Kind:           Kind,
			ID:             strings.Repeat("5", 64),
			Sender:         public(t, b),
			Recipient:      public(t, a),
			CreatedAt:      now,
			ExpiresAt:      now.Add(-time.Hour),
			ConversationID: forgedParent.Offer.Terms.ConversationID,
			ReplyTo:        forgedParent.Offer.Terms.ID,
			ReplyChain:     strings.Repeat("9", 64),
			Trade:          &TradeLink{ID: tradeID, Action: "offer", Parent: forgedParent.Offer.Hash(), Commitment: commit},
		},
		Signature: nil,
	}
	if err := ValidateTradeSuccessor(forgedParent, forgedChild); err == nil {
		t.Fatal("ValidateTradeSuccessor accepted forged/unsigned/rejected parent and forged child")
	}

	// Build a legitimate agreed & released parent trade request.
	reqOffer, reqKey, err := SealWithOptions(a, public(t, b), []byte("trade request"), "req", now, now.Add(time.Hour), SendOptions{
		Trade: &TradeLink{ID: tradeID, Action: "request", Commitment: commit},
	})
	if err != nil {
		t.Fatal(err)
	}
	reqDecision, err := Decide(b, reqOffer, "agree", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	reqRec, err := (Record{Offer: reqOffer}).ApplyDecision(reqDecision, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	reqRel, err := WrapKey(a, reqOffer, reqDecision, reqKey)
	if err != nil {
		t.Fatal(err)
	}
	reqRec, err = reqRec.ApplyRelease(reqRel)
	if err != nil {
		t.Fatal(err)
	}

	// (2) Valid child with matching ReplyChain succeeds.
	goodChild, _, err := SealWithOptions(b, public(t, a), []byte("trade offer"), "offer", now.Add(2*time.Minute), now.Add(time.Hour), SendOptions{
		ConversationID: reqOffer.Terms.ConversationID,
		ReplyTo:        reqOffer.Terms.ID,
		ReplyChain:     ReplyChainHash(reqRec),
		Trade:          &TradeLink{ID: tradeID, Action: "offer", Parent: reqOffer.Hash(), Commitment: commit},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTradeSuccessor(reqRec, goodChild); err != nil {
		t.Fatalf("valid trade successor rejected: %v", err)
	}

	// (3) Valid child with omitted ReplyChain (backwards compatible) succeeds.
	noChainChild, _, err := SealWithOptions(b, public(t, a), []byte("trade offer"), "offer", now.Add(2*time.Minute), now.Add(time.Hour), SendOptions{
		ConversationID: reqOffer.Terms.ConversationID,
		ReplyTo:        reqOffer.Terms.ID,
		Trade:          &TradeLink{ID: tradeID, Action: "offer", Parent: reqOffer.Hash(), Commitment: commit},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTradeSuccessor(reqRec, noChainChild); err != nil {
		t.Fatalf("valid trade successor without ReplyChain rejected: %v", err)
	}

	// (4) Validly signed child with mismatched ReplyChain is rejected.
	badChainChild, _, err := SealWithOptions(b, public(t, a), []byte("trade offer"), "offer", now.Add(2*time.Minute), now.Add(time.Hour), SendOptions{
		ConversationID: reqOffer.Terms.ConversationID,
		ReplyTo:        reqOffer.Terms.ID,
		ReplyChain:     strings.Repeat("9", 64),
		Trade:          &TradeLink{ID: tradeID, Action: "offer", Parent: reqOffer.Hash(), Commitment: commit},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTradeSuccessor(reqRec, badChainChild); !errors.Is(err, ErrState) {
		t.Fatalf("mismatched ReplyChain got %v, want ErrState", err)
	}

	// (5) Tampered child signature is rejected.
	tamperedChild := goodChild
	tamperedChild.Signature = append([]byte(nil), goodChild.Signature...)
	tamperedChild.Signature[0] ^= 0x01
	if err := ValidateTradeSuccessor(reqRec, tamperedChild); err == nil {
		t.Fatal("ValidateTradeSuccessor accepted child with forged signature")
	}

	// (6) Tampered parent release signature is rejected.
	tamperedParent := clone(t, reqRec)
	tamperedParent.Release.Signature[0] ^= 0x01
	if err := ValidateTradeSuccessor(tamperedParent, goodChild); err == nil {
		t.Fatal("ValidateTradeSuccessor accepted parent with forged release")
	}

	// (7) Rejected parent (even with valid signature) is rejected.
	rejDec, err := Decide(b, reqOffer, "reject", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rejRec, err := (Record{Offer: reqOffer}).ApplyDecision(rejDec, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTradeSuccessor(rejRec, goodChild); err == nil {
		t.Fatal("ValidateTradeSuccessor accepted rejected parent")
	}
}

// TestV202_DecideValidatesBeforeSigningAndReturnsZeroOnError verifies BUG-34:
// Decide validates the Offer and all inputs before signing and returns a zero
// Decision{} on any error so no recipient signature is ever created or leaked.
func TestV202_DecideValidatesBeforeSigningAndReturnsZeroOnError(t *testing.T) {
	a, b := identity(t), identity(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	// (1) Forged offer (bad sender signature, invalid ciphertext).
	forgedOffer := Offer{
		Terms: Terms{
			Kind:      Kind,
			ID:        strings.Repeat("a", 64),
			Sender:    public(t, a),
			Recipient: public(t, b),
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		},
		Signature: make([]byte, ed25519.SignatureSize),
	}
	d, err := Decide(b, forgedOffer, "agree", now.Add(time.Second))
	if err == nil {
		t.Fatal("Decide succeeded on forged offer")
	}
	if len(d.Signature) != 0 || d.EnvelopeHash != "" || d.Action != "" {
		t.Fatalf("Decide leaked non-zero Decision on forged offer error: %+v", d)
	}

	// (2) Valid offer with invalid action or pre-CreatedAt timestamp returns zero Decision.
	validOffer, _, err := Seal(a, public(t, b), []byte("hello"), "hi", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if d, err := Decide(b, validOffer, "maybe", now.Add(time.Second)); err == nil || len(d.Signature) != 0 || d.EnvelopeHash != "" {
		t.Fatalf("Decide invalid action: d=%+v err=%v", d, err)
	}
	if d, err := Decide(b, validOffer, "agree", now.Add(-time.Second)); err == nil || len(d.Signature) != 0 || d.EnvelopeHash != "" {
		t.Fatalf("Decide before CreatedAt: d=%+v err=%v", d, err)
	}
}

// TestV202_RecordStateRespectsReleaseByExpiry verifies BUG-40: Record.State(now)
// reports "expired" at and after Offer.Terms.ReleaseBy when agreed but unreleased,
// while remaining "accepted" before ReleaseBy and "key-released" once released.
func TestV202_RecordStateRespectsReleaseByExpiry(t *testing.T) {
	a, b := identity(t), identity(t)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(5 * time.Minute)
	releaseBy := expiry.Add(5 * time.Minute)

	o, key, err := SealWithReleaseBy(a, public(t, b), []byte("secret"), "open", now, expiry, releaseBy, SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decide(b, o, "agree", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := (Record{Offer: o}).ApplyDecision(d, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	rel, err := WrapKey(a, o, d, key)
	if err != nil {
		t.Fatal(err)
	}

	if got := rec.State(releaseBy.Add(-time.Nanosecond)); got != "accepted" {
		t.Fatalf("State before ReleaseBy = %q, want accepted", got)
	}
	if got := rec.State(releaseBy); got != "expired" {
		t.Fatalf("State at exact ReleaseBy = %q, want expired", got)
	}
	if got := rec.State(releaseBy.Add(time.Hour)); got != "expired" {
		t.Fatalf("State after ReleaseBy = %q, want expired", got)
	}
	if _, err := rec.ApplyReleaseAt(rel, releaseBy); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired at ReleaseBy, got %v", err)
	}

	// Once released before ReleaseBy, state remains "key-released" even past ReleaseBy.
	released, err := rec.ApplyReleaseAt(rel, releaseBy.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got := released.State(releaseBy.Add(time.Hour)); got != "key-released" {
		t.Fatalf("released State after ReleaseBy = %q, want key-released", got)
	}
}
