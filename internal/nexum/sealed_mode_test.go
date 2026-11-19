package nexum

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/settle"
)

func TestSealedModeGuardsAndPublicProof(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	plain, err := OpenEscrow("plain-then-seal", "buyer", "seller", 5, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = plain.Lock("buyer", now); err != nil {
		t.Fatal(err)
	}
	if err = plain.StartSealed(2048); err == nil {
		t.Fatal("plaintext lock accepted sealing")
	}

	a, err := OpenEscrow("sealed-guard", "buyer", "seller", 350_000, Meter{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.StartSealed(2048); err != nil {
		t.Fatal(err)
	}
	if err = a.StartSealed(2048); err == nil {
		t.Fatal("replaced an existing ledger")
	}
	before := snapshot(t, a)
	if err = a.Lock("buyer", now); err == nil {
		t.Fatal("plaintext lock after StartSealed")
	}
	if snapshot(t, a) != before {
		t.Fatal("failed lock mutated the agreement")
	}
	if err = a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 200_000}, now); err != nil {
		t.Fatal(err)
	}
	if err = a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 100_000}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	locked := snapshot(t, a)
	if err = a.Accept("seller", now.Add(2*time.Minute)); !errors.Is(err, settle.ErrSumMismatch) {
		t.Fatalf("incomplete total: %v", err)
	}
	if snapshot(t, a) != locked {
		t.Fatal("failed sealed accept mutated the agreement")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Agreement
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Sealed != nil {
		t.Fatal("json restored private custody")
	}
	decodedBefore := snapshot(t, &decoded)
	if err = decoded.Lock("buyer", now); err == nil {
		t.Fatal("decoded sealed snapshot accepted plaintext lock")
	}
	if err = decoded.Accept("seller", now); err == nil {
		t.Fatal("decoded sealed snapshot accepted plaintext accept")
	}
	if err = decoded.Reject("seller", now); err == nil {
		t.Fatal("decoded sealed snapshot accepted plaintext reject")
	}
	if err = decoded.Expire("buyer", now.Add(time.Hour)); err == nil {
		t.Fatal("decoded sealed snapshot accepted plaintext expiry")
	}
	if snapshot(t, &decoded) != decodedBefore || snapshot(t, a) != locked {
		t.Fatal("rejected plaintext mutation changed state")
	}
	if err = a.Apply(Move{Actor: "buyer", Action: "seal", Partial: 50_000}, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = a.Accept("seller", now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	bundle, err := a.PublicSealedProof()
	if err != nil {
		t.Fatal(err)
	}
	without := *a
	without.Sealed = nil
	if err = VerifySealedProofBundle(bundle); err != nil {
		t.Fatal(err)
	}
	if err = without.VerifySealedSettlement(bundle); err != nil {
		t.Fatal(err)
	}
	forged := bundle
	forged.EqualityProof = append([]byte(nil), bundle.EqualityProof...)
	forged.EqualityProof[0] ^= 0xff
	if err = VerifySealedProofBundle(forged); err == nil {
		t.Fatal("forged proof verified")
	}
	swapped := bundle
	swapped.Ciphertexts = cloneBytes(bundle.Ciphertexts)
	swapped.Ciphertexts[0] = append([]byte(nil), swapped.Ciphertexts[0]...)
	swapped.Ciphertexts[0][0] ^= 0xff
	swapped.Commitments = commitCiphertexts(swapped.Ciphertexts)
	if err = VerifySealedProofBundle(swapped); err == nil {
		t.Fatal("substituted ciphertext verified")
	}
	restored, err := RestorePrivate(a.PrivateCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	if restored.head() != a.head() || len(restored.SealedLocks) != len(a.SealedLocks) {
		t.Fatal("restore did not reproduce the checkpoint")
	}
	if !bytes.Equal(restored.SealedAggregate, a.SealedAggregate) {
		t.Fatal("accepted restore dropped the aggregate")
	}
	damaged := a.PrivateCheckpoint()
	clone := *damaged.Agreement
	clone.Mode = ModePlaintext
	damaged.Agreement = &clone
	if _, err = RestorePrivate(damaged); err == nil {
		t.Fatal("mode mismatch restored")
	}
	broken := a.PrivateCheckpoint()
	broken.Ledger.Key.N[0] ^= 0xff
	if _, err = RestorePrivate(broken); err == nil {
		t.Fatal("damaged key restored")
	}
}

func TestV2SealedModeIsCommittedBeforeOpen(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 30, 0, 0, time.UTC)
	plain, err := OpenAgreementV2("v2-plain", KindHouseEscrow, "buyer", "seller", 3, Meter{}, now, ModePlaintext, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = plain.StartSealed(2048); err == nil {
		t.Fatal("v2 plaintext mode accepted StartSealed")
	}
	if err = plain.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
	sealed, err := OpenAgreementV2("v2-sealed", KindHouseEscrow, "buyer", "seller", 9, Meter{}, now, ModeSealed, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err = sealed.Lock("buyer", now); err == nil {
		t.Fatal("v2 sealed mode accepted plaintext lock")
	}
	if err = sealed.StartSealed(2048); err == nil {
		t.Fatal("v2 replaced a committed ledger")
	}
	key := append([]byte(nil), sealed.PublicKey...)
	if err = sealed.Apply(Move{Actor: "buyer", Action: "seal", Partial: 9}, now); err != nil {
		t.Fatal(err)
	}
	sealed.PublicKey[0] ^= 0xff
	if err = sealed.VerifyReceipts(); err == nil {
		t.Fatal("public key is outside the v2 terms digest")
	}
	sealed.PublicKey[0] = key[0]
	if err = sealed.VerifyReceipts(); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, a *Agreement) string {
	t.Helper()
	raw, err := json.Marshal(struct {
		Status string
		Head   string
		N      int
	}{string(a.Status), a.head(), len(a.Receipts)})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
