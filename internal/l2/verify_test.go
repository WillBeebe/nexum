package l2

import (
	"strings"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/internal/nexum"
	"github.com/WillBeebe/nexum/internal/pow"
)

// closed builds a fully accepted house escrow, the barter unit.
func closed(t *testing.T, id string, amount int64, now time.Time) *nexum.Agreement {
	a, err := nexum.OpenEscrow(id, "buyer", "seller", amount, nexum.Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Lock("buyer", now); err != nil {
		t.Fatal(err)
	}
	if err := a.Accept("seller", now); err != nil {
		t.Fatal(err)
	}
	return a
}

// TestVerifyGoodSeal proves the checker accepts a genuine seal.
func TestVerifyGoodSeal(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a := closed(t, "h-good", 350_000, now)
	b, err := Seal([]*nexum.Agreement{a}, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBatch(b, 8); err != nil {
		t.Fatalf("genuine seal rejected: %v", err)
	}
}

// TestVerifyTamperReceipt proves editing a receipt breaks the seal
// even when the attacker leaves the stored hashes alone.
func TestVerifyTamperReceipt(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a := closed(t, "h-tamper", 350_000, now)
	b, err := Seal([]*nexum.Agreement{a}, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	a.Receipts[1].Note = "rewritten after sealing"
	if err := Verify(b.Agreements, b.Header, 8); err == nil {
		t.Fatal("in-place edit accepted — seal is not tamper-evident")
	}
}

// TestVerifyRechain proves a fully re-chained (internally consistent)
// rewritten history still fails: with terms in the root, the forged
// agreement's digest cannot match the sealed one.
func TestVerifyRechain(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	orig := closed(t, "h-orig", 350_000, now)
	b, err := Seal([]*nexum.Agreement{orig}, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	// Attack: rewrite the amount and re-run the kernel so the receipt
	// chain is internally valid, then present it under the old seal.
	forged := closed(t, "h-orig", 999_000, now)
	if err := Verify([]*nexum.Agreement{forged}, b.Header, 8); err == nil {
		t.Fatal("re-chained history accepted under old seal — terms not bound")
	}
}

// TestTermsDigestAmountSensitivity pins the exact regression the
// rechain attack exploited: terms digests of identical agreements
// differing only in Amount must differ.
func TestTermsDigestAmountSensitivity(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a := closed(t, "h-sens", 350_000, now)
	b := closed(t, "h-sens", 999_000, now)
	da, err := TermsDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := TermsDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da == db {
		t.Fatal("terms digest blind to Amount — terms not committed")
	}
}

// TestTermsDigestStable pins determinism: same agreement twice,
// same digest. (The .steps field and receipt contents must not leak
// into the digest — terms only.)
func TestTermsDigestStable(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a := closed(t, "h-stable", 350_000, now)
	d1, err := TermsDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating the action trail must not move the terms digest.
	// (Kernel is correct: notes on a terminal agreement are refused,
	// so mutate while still open.)
	op, err := nexum.OpenEscrow("h-stable-trail", "buyer", "seller", 350_000, nexum.Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	td1, err := TermsDigest(op)
	if err != nil {
		t.Fatal(err)
	}
	if err := op.Note("buyer", "evidence", "open-note:trail-only", now); err != nil {
		t.Fatal(err)
	}
	td2, err := TermsDigest(op)
	if err != nil {
		t.Fatal(err)
	}
	if td1 != td2 {
		t.Fatal("terms digest moved on action-trail change")
	}
	d2, err := TermsDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("terms digest unstable across action-trail changes")
	}
}

// TestVerifySwap proves a valid seal over one batch cannot be replayed
// for a different set of agreements.
func TestVerifySwap(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a := closed(t, "h-a", 350_000, now)
	sealed, err := Seal([]*nexum.Agreement{a}, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	other := closed(t, "h-b", 1, now)
	if err := Verify([]*nexum.Agreement{other}, sealed.Header, 8); err == nil {
		t.Fatal("seal replayed across different agreements")
	}
}

// TestVerifyForgedNonce proves a header that claims the root but never
// burned the Search fails the PoW check.
func TestVerifyForgedNonce(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a := closed(t, "h-forged", 350_000, now)
	b, err := Seal([]*nexum.Agreement{a}, 8, now)
	if err != nil {
		t.Fatal(err)
	}
	h := b.Header
	h.Nonce = b.Header.Nonce + 1
	for h.Valid() && h.Nonce-b.Header.Nonce < 1<<16 {
		h.Nonce++
	}
	if h.Valid() {
		t.Skip("no invalid nonce found in range; target degenerate")
	}
	if err := Verify(b.Agreements, h, 8); err == nil {
		t.Fatal("forged nonce accepted")
	}
}

// TestVerifyDifficultyFloor proves a verifier can refuse seals below
// its own minimum target — no cheap downgrade.
func TestVerifyDifficultyFloor(t *testing.T) {
	now := time.Date(2026, 9, 3, 1, 0, 0, 0, time.UTC)
	a := closed(t, "h-floor", 350_000, now)
	b, err := Seal([]*nexum.Agreement{a}, 4, now)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyBatch(b, 8)
	if err == nil || !strings.Contains(err.Error(), "below floor") {
		t.Fatalf("want floor error, got %v", err)
	}
}

// TestVerifyEmptyRoot proves Verify refuses to bless an empty batch —
// Root errors, so nothing seals without barter behind it.
func TestVerifyEmptyRoot(t *testing.T) {
	h := pow.Header{DiffBits: 8}
	if err := Verify(nil, h, 8); err == nil {
		t.Fatal("empty batch verified")
	}
}
