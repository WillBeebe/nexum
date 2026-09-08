package nexum

import (
	"errors"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/internal/settle"
)

// Sealed-path acceptance test: a two-agent Room escrow on ciphertext. The buyer's
// value is sealed (Paillier), the kernel aggregates on ciphertext,
// and Release decrypts the sum exactly once against the committed
// Amount. takeback is refused at every stage.
func TestRoomSealedEscrow(t *testing.T) {
	now := time.Date(2026, 9, 3, 2, 0, 0, 0, time.UTC)
	a, err := OpenEscrow("room-sealed", "buyer", "seller", 350_000, Meter{BudgetUSD: 42}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.StartSealed(2048); err != nil {
		t.Fatal(err)
	}
	// Two sealed partials via the Room move interface.
	if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 200_000}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 150_000}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Sealed path: kernel never stored a plaintext partial. The receipt
	// notes are ciphertext (base64), not "200000".
	for _, r := range a.Receipts {
		if r.Action == "seal" && r.Note != "" && len(r.Note) < 64 {
			t.Fatalf("seal receipt note looks like plaintext: %q", r.Note)
		}
	}
	if a.Status != StatusLocked {
		t.Fatalf("status=%s want locked after seal", a.Status)
	}
	if a.isSealed() != true || len(a.SealedLocks) != 2 {
		t.Fatalf("sealed locks=%d want 2", len(a.SealedLocks))
	}
	// takeback refused after seal.
	if err := a.Apply(Move{Actor: "buyer", Action: "takeback"}, now.Add(3*time.Minute)); !errors.Is(err, ErrTakeback) {
		t.Fatalf("takeback after seal: %v", err)
	}
	// Seller accepts: Release decrypts once, sum must equal committed.
	if err := a.Apply(Move{Actor: "seller", Action: "accept"}, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusAccepted || a.ReleasedTo != "seller" {
		t.Fatalf("status=%s to=%s", a.Status, a.ReleasedTo)
	}
	if a.SealedSum != nil {
		t.Fatal("SealedSum not nilled after release — decrypt-once violated")
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestRoomSealedSumMismatchFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("room-bad", "buyer", "seller", 350_000, Meter{}, now)
	if err := a.StartSealed(2048); err != nil {
		t.Fatal(err)
	}
	// Partial sums to 300k, committed says 350k.
	if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 300_000}, now); err != nil {
		t.Fatal(err)
	}
	err := a.Apply(Move{Actor: "seller", Action: "accept"}, now.Add(time.Minute))
	if !errors.Is(err, settle.ErrSumMismatch) {
		t.Fatalf("want ErrSumMismatch, got %v", err)
	}
	// Fail closed: status unchanged, no accept receipt, no plaintext total.
	if a.Status != StatusLocked {
		t.Fatalf("status=%s after failed release, want locked (unchanged)", a.Status)
	}
	if a.ClosedAt != nil || a.ReleasedTo != "" {
		t.Fatal("failed release mutated terminal fields")
	}
	// Escrow can still settle after a failed release attempt: partial
	// top-up to the committed amount, then accept.
	if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 50_000}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(Move{Actor: "seller", Action: "accept"}, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusAccepted {
		t.Fatalf("status=%s after top-up accept", a.Status)
	}
}

func TestRoomSealedTamperFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("room-tamper", "buyer", "seller", 350_000, Meter{}, now)
	if err := a.StartSealed(2048); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 350_000}, now); err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the aggregate ciphertext.
	a.SealedSum[0] ^= 0xFF
	err := a.Apply(Move{Actor: "seller", Action: "accept"}, now.Add(time.Minute))
	if err == nil {
		t.Fatal("tampered ciphertext settled — kernel broken")
	}
	if a.Status != StatusLocked {
		t.Fatalf("status=%s after tampered release, want locked", a.Status)
	}
}

func TestRoomSealedRejectKeepsSumSealed(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("room-reject", "buyer", "seller", 350_000, Meter{}, now)
	if err := a.StartSealed(2048); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 350_000}, now); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(Move{Actor: "seller", Action: "reject"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if a.Status != StatusRejected || a.ReleasedTo != "buyer" {
		t.Fatalf("status=%s to=%s", a.Status, a.ReleasedTo)
	}
	// Sum stays sealed on the reject path: the kernel never decrypted.
	if a.SealedSum == nil || len(a.SealedSum) == 0 {
		t.Fatal("SealedSum must remain sealed (non-nil) after reject")
	}
	if err := a.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func TestRoomSealedRequiresArming(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("room-noarm", "buyer", "seller", 350_000, Meter{}, now)
	err := a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 350_000}, now)
	if !errors.Is(err, ErrNoSeal) {
		t.Fatalf("want ErrNoSeal, got %v", err)
	}
	// Nothing sealed, kernel never saw a partial.
	if len(a.SealedLocks) != 0 || a.SealedSum != nil {
		t.Fatal("unarmed escrow stored seal material")
	}
}

func TestRoomSealedWrongPartySeal(t *testing.T) {
	now := time.Now().UTC()
	a, _ := OpenEscrow("room-wrong", "buyer", "seller", 350_000, Meter{}, now)
	if err := a.StartSealed(2048); err != nil {
		t.Fatal(err)
	}
	err := a.Apply(Move{Actor: "seller", Action: "seal", Partial: 350_000}, now)
	if !errors.Is(err, ErrWrongParty) {
		t.Fatalf("want ErrWrongParty, got %v", err)
	}
}
