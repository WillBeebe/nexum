package nexum

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/WillBeebe/nexum/v2/internal/settle"
)

// SealedProofBundle is public settlement evidence. It never contains Paillier
// secrets or encryption randomness. Equality verification uses the public key
// only. A receipt note that mentions a proof is not itself this bundle.
type SealedProofBundle struct {
	Version       int      `json:"version"`
	Scheme        string   `json:"scheme"`
	PublicKey     []byte   `json:"public_key"`
	Ciphertexts   [][]byte `json:"ciphertexts"`
	Commitments   [][]byte `json:"commitments"`
	Aggregate     []byte   `json:"aggregate"`
	Amount        int64    `json:"amount"`
	EqualityProof []byte   `json:"equality_proof"`
	TermsDigest   string   `json:"terms_digest"`
	ReceiptHead   string   `json:"receipt_head"`
}

const (
	maxSealedLocks     = 128
	maxCiphertextBytes = 8192
	maxProofBytes      = 8192
	maxPublicKeyBytes  = 1024
)

// PublicSealedProof builds a bundle from public fields. Private ledger custody
// is not required when the aggregate, proof and public key were retained.
func (a *Agreement) PublicSealedProof() (SealedProofBundle, error) {
	var zero SealedProofBundle
	if a == nil || a.Status != StatusAccepted {
		return zero, ErrInvalid
	}
	if err := a.VerifyReceipts(); err != nil {
		return zero, err
	}
	if err := a.sealsMatchReceipts(); err != nil {
		return zero, err
	}
	proof, err := committedEqualityProof(a)
	if err != nil {
		return zero, err
	}
	aggregate := a.SealedAggregate
	if len(aggregate) == 0 {
		aggregate = a.SealedSum
	}
	pub := a.PublicKey
	if len(pub) == 0 && a.Sealed != nil {
		pub = a.Sealed.PublicModulus()
	}
	bundle := SealedProofBundle{
		Version: 1, Scheme: a.Scheme, PublicKey: append([]byte(nil), pub...),
		Ciphertexts: cloneBytes(a.SealedLocks), Commitments: commitCiphertexts(a.SealedLocks),
		Aggregate: append([]byte(nil), aggregate...), Amount: a.Amount,
		EqualityProof: proof, TermsDigest: a.TermsDigest(), ReceiptHead: a.head(),
	}
	if bundle.Scheme == "" {
		bundle.Scheme = SchemePaillier
	}
	if err := VerifySealedProofBundle(bundle); err != nil {
		return zero, err
	}
	return bundle, nil
}

// VerifySealedProofBundle checks cryptographic structure only: group membership,
// commitments, aggregate and public equality. Callers bind the result to a
// receipt chain with VerifySealedSettlement. This function does not accept a
// private ledger and does not treat a receipt sentence as a proof.
func VerifySealedProofBundle(b SealedProofBundle) error {
	if b.Version != 1 || b.Scheme != SchemePaillier || b.Amount <= 0 {
		return ErrInvalid
	}
	if len(b.PublicKey) < 128 || len(b.PublicKey) > maxPublicKeyBytes || len(b.EqualityProof) == 0 || len(b.EqualityProof) > maxProofBytes {
		return ErrInvalid
	}
	if len(b.Ciphertexts) == 0 || len(b.Ciphertexts) > maxSealedLocks || len(b.Commitments) != len(b.Ciphertexts) {
		return ErrInvalid
	}
	if !hex64(b.TermsDigest) || !hex64(b.ReceiptHead) {
		return ErrInvalid
	}
	for i, ct := range b.Ciphertexts {
		if len(ct) == 0 || len(ct) > maxCiphertextBytes || !bytes.Equal(b.Commitments[i], ciphertextCommitment(ct)) {
			return ErrInvalid
		}
	}
	if err := settle.VerifyPublic(b.PublicKey, b.Ciphertexts, b.Aggregate, b.Amount, b.EqualityProof); err != nil {
		return err
	}
	return nil
}

// VerifySealedSettlement binds a public bundle to this agreement's verified
// receipt chain, ordered seal notes and terms. It does not require private
// custody. Receipt-chain success alone is not settlement verification.
func (a *Agreement) VerifySealedSettlement(b SealedProofBundle) error {
	if a == nil || a.Status != StatusAccepted {
		return ErrInvalid
	}
	if err := a.VerifyReceipts(); err != nil {
		return err
	}
	if err := a.sealsMatchReceipts(); err != nil {
		return err
	}
	want, err := committedEqualityProof(a)
	if err != nil {
		return err
	}
	if err := VerifySealedProofBundle(b); err != nil {
		return err
	}
	if b.TermsDigest != a.TermsDigest() || b.ReceiptHead != a.head() || b.Amount != a.Amount {
		return ErrInvalid
	}
	if a.Scheme != "" && b.Scheme != a.Scheme {
		return ErrInvalid
	}
	if len(a.PublicKey) > 0 && !bytes.Equal(b.PublicKey, a.PublicKey) {
		return ErrInvalid
	}
	if len(b.Ciphertexts) != len(a.SealedLocks) {
		return ErrInvalid
	}
	for i := range b.Ciphertexts {
		if !bytes.Equal(b.Ciphertexts[i], a.SealedLocks[i]) {
			return ErrInvalid
		}
	}
	if !bytes.Equal(want, b.EqualityProof) {
		return ErrInvalid
	}
	if len(a.SealedAggregate) > 0 && !bytes.Equal(a.SealedAggregate, b.Aggregate) {
		return ErrInvalid
	}
	if len(a.SealedSum) > 0 && !bytes.Equal(a.SealedSum, b.Aggregate) {
		return ErrInvalid
	}
	return nil
}

// committedEqualityProof returns the equality proof committed in the "accept"
// receipt of an accepted sealed agreement. If the unhashed SealedEqualityProof
// field is also populated, it must match the receipt commitment exactly.
func committedEqualityProof(a *Agreement) ([]byte, error) {
	if a == nil || a.Status != StatusAccepted {
		return nil, ErrInvalid
	}
	receiptProof := legacyEqualityProof(a)
	if len(receiptProof) == 0 {
		return nil, ErrInvalid
	}
	if len(a.SealedEqualityProof) > 0 && !bytes.Equal(a.SealedEqualityProof, receiptProof) {
		return nil, ErrInvalid
	}
	return append([]byte(nil), receiptProof...), nil
}

func (a *Agreement) sealsMatchReceipts() error {
	var want [][]byte
	for _, r := range a.Receipts {
		if r.Action != "seal" {
			continue
		}
		ct, err := base64.StdEncoding.DecodeString(r.Note)
		if err != nil || len(ct) == 0 {
			return ErrInvalid
		}
		want = append(want, ct)
	}
	if len(want) != len(a.SealedLocks) {
		return ErrInvalid
	}
	for i := range want {
		if !bytes.Equal(want[i], a.SealedLocks[i]) {
			return ErrInvalid
		}
	}
	return nil
}

func legacyEqualityProof(a *Agreement) []byte {
	const marker = "proof: "
	for i := len(a.Receipts) - 1; i >= 0; i-- {
		r := a.Receipts[i]
		if r.Action != "accept" {
			continue
		}
		idx := bytes.LastIndex([]byte(r.Note), []byte(marker))
		if idx < 0 {
			return nil
		}
		raw, err := base64.StdEncoding.DecodeString(r.Note[idx+len(marker):])
		if err != nil || len(raw) == 0 {
			return nil
		}
		return raw
	}
	return nil
}

func ciphertextCommitment(ct []byte) []byte {
	sum := sha256.Sum256(ct)
	return sum[:]
}

func commitCiphertexts(cts [][]byte) [][]byte {
	out := make([][]byte, len(cts))
	for i, ct := range cts {
		out[i] = ciphertextCommitment(ct)
	}
	return out
}

func cloneBytes(src [][]byte) [][]byte {
	out := make([][]byte, len(src))
	for i, b := range src {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
