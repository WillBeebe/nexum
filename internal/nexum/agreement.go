// Package nexum is the agreement kernel: binding obligations with
// a hash-chained ledger. Metering is cost / effort / budget.
// Do not import Ethereum's fee-unit name into these types.
package nexum

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/settle"
)

// Status is the life of a Nexum. Terminal states do not reopen.
type Status string

const (
	StatusOpen     Status = "open"
	StatusLocked   Status = "locked"
	StatusAccepted Status = "accepted"
	StatusRejected Status = "rejected"
	StatusExpired  Status = "expired"
)

// Execution modes are committed in format v2 terms. Format v1 digests omit
// them so existing receipt chains keep their hashes.
const (
	FormatV2       = 2
	ModePlaintext  = "plaintext"
	ModeSealed     = "sealed"
	SchemePaillier = "paillier"
)

// Kind names the contract shape. House escrow is the acceptance test.
const KindHouseEscrow = "escrow.house"

// Meter is inference spent on the user's behalf. Not a fee market.
// The kernel checks CostUSD against BudgetUSD on every step but does not
// meter itself: callers own accruing CostUSD (agents report their spend).
// MaxSteps is the kernel-enforced DoS bound, clamped to 1..128 at open.
type Meter struct {
	CostUSD   float64 `json:"cost_usd"`
	Effort    string  `json:"effort"` // flash | max | …
	BudgetUSD float64 `json:"budget_usd"`
	MaxSteps  int     `json:"max_steps"` // DoS bound
}

// Party is an agent or human identifier. Not a chain address.
type Party string

// Receipt is one irreversible step on the agreement. ActorKey, when present,
// is the actor's Ed25519 public key; VerifyReceipts then requires its
// signature over the receipt, so the chain is forge-resistant evidence.
type Receipt struct {
	Seq      int       `json:"seq"`
	At       time.Time `json:"at"`
	Action   string    `json:"action"`
	Actor    Party     `json:"actor"`
	Note     string    `json:"note,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
	// ActorKey + ActorSignature authenticate the actor's step. Absent both
	// for legacy local-only ledgers within one trust domain.
	ActorKey       ed25519.PublicKey `json:"actor_key,omitempty"`
	ActorSignature []byte            `json:"actor_signature,omitempty"`
}

// Agreement is a Nexum: a binding obligation.
type Agreement struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Buyer      Party      `json:"buyer"`
	Seller     Party      `json:"seller"`
	Amount     int64      `json:"amount"` // integer units of Unit (or untyped)
	Unit       Unit       `json:"unit,omitempty"`
	Status     Status     `json:"status"`
	Meter      Meter      `json:"meter"`
	Deadline   time.Time  `json:"deadline,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LockedAt   *time.Time `json:"locked_at,omitempty"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	ReleasedTo Party      `json:"released_to,omitempty"`
	Receipts   []Receipt  `json:"receipts"`
	// Sealed escrow: value lives as Paillier ciphertext. The
	// key never leaves the ledger; the kernel sees only ciphertext.
	Sealed      *settle.EncryptedLedger `json:"-"`                      // owns the key; never serialized
	SealedLocks [][]byte                `json:"sealed_locks,omitempty"` // ciphertext partials
	SealedSum   []byte                  `json:"sealed_sum,omitempty"`   // ciphertext aggregate, cleared after accept
	// Format 0 is the original terms domain. FormatV2 commits Mode before opening.
	Format              int    `json:"format,omitempty"`
	Mode                string `json:"mode,omitempty"`
	Scheme              string `json:"scheme,omitempty"`
	PublicKey           []byte `json:"public_key,omitempty"`
	SealedAggregate     []byte `json:"sealed_aggregate,omitempty"`
	SealedEqualityProof []byte `json:"sealed_equality_proof,omitempty"`
	steps               int
	// actorKeys maps Party to the signing key used for new receipts.
	// Nil disables receipt signatures (legacy local ledgers).
	actorKeys map[Party]ed25519.PrivateKey
}

// SignReceipts arms receipt signatures: every appended receipt is signed by
// the given party keys, and VerifyReceipts requires them. Parties without
// a key keep legacy unsigned receipts.
func (a *Agreement) SignReceipts(keys map[Party]ed25519.PrivateKey) error {
	if a == nil {
		return ErrInvalid
	}
	cloned, err := cloneActorKeys(keys, func(p Party) bool {
		return p == a.Buyer || p == a.Seller
	})
	if err != nil {
		return err
	}
	a.actorKeys = cloned
	return nil
}

func cloneActorKeys(keys map[Party]ed25519.PrivateKey, allowed func(Party) bool) (map[Party]ed25519.PrivateKey, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	cloned := make(map[Party]ed25519.PrivateKey, len(keys))
	for party, key := range keys {
		if len(key) != ed25519.PrivateKeySize {
			return nil, ErrInvalid
		}
		want := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if !bytes.Equal(want, key) {
			return nil, ErrInvalid
		}
		if !allowed(party) {
			return nil, ErrWrongParty
		}
		cloned[party] = append(ed25519.PrivateKey(nil), key...)
	}
	return cloned, nil
}

func validMeterNumbers(m Meter) bool {
	if math.IsNaN(m.CostUSD) || math.IsInf(m.CostUSD, 0) || m.CostUSD < 0 {
		return false
	}
	if math.IsNaN(m.BudgetUSD) || math.IsInf(m.BudgetUSD, 0) || m.BudgetUSD < 0 {
		return false
	}
	return true
}

var (
	ErrWrongParty    = errors.New("nexum: wrong party")
	ErrBadState      = errors.New("nexum: illegal state transition")
	ErrTakeback      = errors.New("nexum: takeback refused")
	ErrBudget        = errors.New("nexum: budget exceeded")
	ErrDoS           = errors.New("nexum: step bound exceeded")
	ErrZeroAmount    = errors.New("nexum: amount must be positive")
	ErrSameParty     = errors.New("nexum: buyer and seller must differ")
	ErrMissingParty  = errors.New("nexum: buyer and seller required")
	ErrNotYet        = errors.New("nexum: deadline not reached")
	ErrNoDeadline    = errors.New("nexum: no deadline set")
	ErrEmptyCitation = errors.New("nexum: evidence citation required")
	ErrNoSeal        = errors.New("nexum: sealed escrow not armed; call StartSealed first")
	ErrInvalid       = errors.New("nexum: invalid agreement or receipt")
)

// OpenEscrow preserves the house-escrow acceptance example and its receipt format.
func OpenEscrow(id string, buyer, seller Party, amount int64, meter Meter, now time.Time) (*Agreement, error) {
	return openAgreement(id, KindHouseEscrow, buyer, seller, amount, meter, now, "escrow opened")
}

// OpenAgreement starts a bilateral agreement with its final kind.
func OpenAgreement(id, kind string, buyer, seller Party, amount int64, meter Meter, now time.Time) (*Agreement, error) {
	if kind == "" {
		return nil, errors.New("nexum: agreement kind required")
	}
	return openAgreement(id, kind, buyer, seller, amount, meter, now, "agreement opened")
}

// OpenAgreementV2 commits the execution mode before the opening receipt.
// Sealed mode binds the Paillier scheme and public modulus into the v2 terms
// digest. Plaintext mode refuses StartSealed. v1 OpenEscrow is unchanged.
func OpenAgreementV2(id, kind string, buyer, seller Party, amount int64, meter Meter, now time.Time, mode string, bits int) (*Agreement, error) {
	if id == "" {
		return nil, ErrInvalid
	}
	if kind == "" {
		return nil, errors.New("nexum: agreement kind required")
	}
	if mode != ModePlaintext && mode != ModeSealed {
		return nil, ErrInvalid
	}
	if buyer == "" || seller == "" {
		return nil, ErrMissingParty
	}
	if buyer == seller {
		return nil, ErrSameParty
	}
	if amount <= 0 {
		return nil, ErrZeroAmount
	}
	if !validMeterNumbers(meter) {
		return nil, ErrInvalid
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 8
	}
	if meter.MaxSteps > 128 {
		return nil, ErrInvalid
	}
	if meter.Effort == "" {
		meter.Effort = "flash"
	}
	a := &Agreement{
		ID: id, Kind: kind, Buyer: buyer, Seller: seller, Amount: amount, Status: StatusOpen,
		Meter: meter, CreatedAt: now.UTC(), Format: FormatV2, Mode: mode,
	}
	if mode == ModeSealed {
		ledger, err := settle.NewEncryptedLedger(bits)
		if err != nil {
			return nil, err
		}
		a.Sealed = ledger
		a.Scheme = SchemePaillier
		a.PublicKey = ledger.PublicModulus()
	}
	if err := a.append(buyer, "open", "agreement opened", now); err != nil {
		return nil, err
	}
	return a, nil
}
func openAgreement(id, kind string, buyer, seller Party, amount int64, meter Meter, now time.Time, note string) (*Agreement, error) {
	if id == "" {
		return nil, ErrInvalid
	}
	if buyer == "" || seller == "" {
		return nil, ErrMissingParty
	}
	if buyer == seller {
		return nil, ErrSameParty
	}
	if amount <= 0 {
		return nil, ErrZeroAmount
	}
	if !validMeterNumbers(meter) {
		return nil, ErrInvalid
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 8
	}
	if meter.MaxSteps > 128 {
		return nil, ErrInvalid
	}
	if meter.Effort == "" {
		meter.Effort = "flash"
	}
	a := &Agreement{
		ID:        id,
		Kind:      kind,
		Buyer:     buyer,
		Seller:    seller,
		Amount:    amount,
		Status:    StatusOpen,
		Meter:     meter,
		CreatedAt: now.UTC(),
	}
	if err := a.append(buyer, "open", note, now); err != nil {
		return nil, err
	}
	return a, nil
}

// Lock is the buyer placing value. After this, the buyer cannot
// unwind except by the seller's reject (or expiry, later).
func (a *Agreement) Lock(actor Party, now time.Time) error {
	if err := a.requireExecutableCustody(); err != nil {
		return err
	}
	if a.sealedPath() {
		return ErrBadState
	}
	if actor != a.Buyer {
		return ErrWrongParty
	}
	if a.Status != StatusOpen {
		if a.terminal() {
			return ErrTakeback
		}
		return ErrBadState
	}
	if err := a.append(actor, "lock", "value locked", now); err != nil {
		return err
	}
	t := now.UTC()
	a.LockedAt = &t
	a.Status = StatusLocked
	return nil
}

// Accept releases locked value, checking the equality proof when sealed. Terminal.
func (a *Agreement) Accept(actor Party, now time.Time) error {
	if a.sealedPath() {
		if a.Sealed == nil {
			return ErrBadState
		}
		return a.acceptSealed(actor, now)
	}
	if actor != a.Seller {
		return ErrWrongParty
	}
	if a.Status != StatusLocked {
		if a.terminal() {
			return ErrTakeback
		}
		return ErrBadState
	}
	if err := a.append(actor, "accept", "released to seller", now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Seller
	a.Status = StatusAccepted
	return nil
}

// Reject is the seller returning the locked value to the buyer. Terminal.
func (a *Agreement) Reject(actor Party, now time.Time) error {
	if a.sealedPath() {
		if a.Sealed == nil {
			return ErrBadState
		}
		return a.rejectSealed(actor, now)
	}
	if actor != a.Seller {
		return ErrWrongParty
	}
	if a.Status != StatusLocked {
		if a.terminal() {
			return ErrTakeback
		}
		return ErrBadState
	}
	if err := a.append(actor, "reject", "returned to buyer", now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Buyer
	a.Status = StatusRejected
	return nil
}

// SetDeadline fixes the expiry time. A deadline is a material term,
// so it goes on the ledger, not a silent struct write. Either party
// may set or extend it before terminal state; the step bound applies.
func (a *Agreement) SetDeadline(actor Party, deadline, now time.Time) error {
	if err := a.requireExecutableCustody(); err != nil {
		return err
	}
	if actor != a.Buyer && actor != a.Seller {
		return ErrWrongParty
	}
	if a.terminal() {
		return ErrTakeback
	}
	if !deadline.After(now) {
		return ErrNotYet
	}
	note := deadline.UTC().Format(time.RFC3339)
	recorded, err := time.Parse(time.RFC3339, note)
	if err != nil {
		return ErrInvalid
	}
	if !recorded.After(now.UTC()) {
		return ErrNotYet
	}
	if err := a.append(actor, "deadline", note, now); err != nil {
		return err
	}
	a.Deadline = deadline.UTC()
	return nil
}

// Expire is time running out on the agreement. Either party
// may call it, but only after the deadline, and it is terminal:
// value returns to whoever locked it. There is no state where
// expiry reopens the obligation.
func (a *Agreement) Expire(actor Party, now time.Time) error {
	if err := a.requireExecutableCustody(); err != nil {
		return err
	}
	if actor != a.Buyer && actor != a.Seller {
		return ErrWrongParty
	}
	if a.Status != StatusOpen && a.Status != StatusLocked {
		return ErrTakeback
	}
	if a.Deadline.IsZero() {
		return ErrNoDeadline
	}
	if now.Before(a.Deadline) {
		return ErrNotYet
	}
	if err := a.append(actor, "expire", "deadline passed, value unlocked", now); err != nil {
		return err
	}
	t := now.UTC()
	a.ClosedAt = &t
	a.ReleasedTo = a.Buyer
	a.Status = StatusExpired
	return nil
}

// Note is evidence: an agent recording what it saw before deciding.
// No gas, no fee market — a citation the network can check later.
func (a *Agreement) Note(actor Party, action, citation string, now time.Time) error {
	if err := a.requireExecutableCustody(); err != nil {
		return err
	}
	if actor != a.Buyer && actor != a.Seller {
		return ErrWrongParty
	}
	if a.terminal() {
		return ErrTakeback
	}
	if citation == "" {
		return ErrEmptyCitation
	}
	if action != "evidence" {
		return fmt.Errorf("nexum: note action must be evidence, got %q", action)
	}
	if err := a.append(actor, action, citation, now); err != nil {
		return err
	}
	return nil
}

func (a *Agreement) terminal() bool {
	switch a.Status {
	case StatusAccepted, StatusRejected, StatusExpired:
		return true
	default:
		return false
	}
}

func (a *Agreement) append(actor Party, action, note string, now time.Time) error {
	if a.steps >= a.Meter.MaxSteps {
		return ErrDoS
	}
	if !validMeterNumbers(a.Meter) {
		return ErrInvalid
	}
	if a.Meter.BudgetUSD > 0 && a.Meter.CostUSD > a.Meter.BudgetUSD {
		return ErrBudget
	}
	prev := ""
	if n := len(a.Receipts); n > 0 {
		prev = a.Receipts[n-1].Hash
	}
	r := Receipt{
		Seq:      len(a.Receipts) + 1,
		At:       now.UTC(),
		Action:   action,
		Actor:    actor,
		Note:     note,
		PrevHash: prev,
	}
	// Sign before hashing: the signature is part of the hash chain, so a
	// forged signature cannot borrow an honest receipt's hash.
	if key, ok := a.actorKeys[actor]; ok && len(key) == ed25519.PrivateKeySize {
		r.ActorKey = key.Public().(ed25519.PublicKey)
		r.ActorSignature = ed25519.Sign(key, receiptMessage(a, r))
	}
	r.Hash = hashReceipt(a, r)
	a.Receipts = append(a.Receipts, r)
	a.steps++
	return nil
}

// TermsDigest commits to the agreement's binding terms — the economic facts
// the receipts speak about. Folded into every receipt hash so rewriting
// Amount, a party, a unit or the kind breaks the chain from the first
// receipt. Deliberately excludes derived status, the deadline and the
// meter: all change over the agreement's life by design, and each change
// is itself a signed, chained receipt. Metering is operational bound, not
// economic terms.
func (a *Agreement) TermsDigest() string {
	if a.Format >= FormatV2 {
		sum := sha256.Sum256(wireDigestV2("terms", termsViewV2{
			ID: a.ID, Kind: a.Kind, Buyer: string(a.Buyer), Seller: string(a.Seller),
			Amount: a.Amount, Unit: a.Unit, CreatedAt: a.CreatedAt,
			Mode: a.Mode, Scheme: a.Scheme, PublicKey: a.PublicKey,
		}))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(wireDigest("terms", termsView{
		ID: a.ID, Kind: a.Kind, Buyer: string(a.Buyer), Seller: string(a.Seller),
		Amount: a.Amount, Unit: a.Unit, CreatedAt: a.CreatedAt,
	}))
	return hex.EncodeToString(sum[:])
}

type termsView struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Buyer     string    `json:"buyer"`
	Seller    string    `json:"seller"`
	Amount    int64     `json:"amount"`
	Unit      Unit      `json:"unit"`
	CreatedAt time.Time `json:"created_at"`
}

type termsViewV2 struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Buyer     string    `json:"buyer"`
	Seller    string    `json:"seller"`
	Amount    int64     `json:"amount"`
	Unit      Unit      `json:"unit"`
	CreatedAt time.Time `json:"created_at"`
	Mode      string    `json:"mode"`
	Scheme    string    `json:"scheme"`
	PublicKey []byte    `json:"public_key"`
}

// receiptMessage is the canonical bytes an actor signs for one receipt.
// Length-delimited so distinct fields cannot be confused.
func receiptMessage(a *Agreement, r Receipt) []byte {
	return canonicalReceiptBytes(r, a.TermsDigest())
}

type canonicalReceipt struct {
	Seq      int       `json:"seq"`
	At       time.Time `json:"at"`
	Action   string    `json:"action"`
	Actor    string    `json:"actor"`
	Note     string    `json:"note"`
	PrevHash string    `json:"prev_hash"`
	Terms    string    `json:"terms"`
}

// hashSignedReceipt is the canonical, unambiguous receipt hash for the
// sibling ledgers (council, workflow, delegate): JSON-canonical fields
// plus that ledger's terms digest. Distinct receipts cannot collide.
func hashSignedReceipt(kind string, terms string, r Receipt) string {
	sum := sha256.Sum256(wireDigest(kind, struct {
		Canonical []byte `json:"canonical"`
		ActorKey  []byte `json:"actor_key,omitempty"`
		Signature []byte `json:"actor_signature,omitempty"`
	}{canonicalReceiptBytes(r, terms), r.ActorKey, r.ActorSignature}))
	return hex.EncodeToString(sum[:])
}
func canonicalReceiptBytes(r Receipt, terms string) []byte {
	b, _ := json.Marshal(canonicalReceipt{r.Seq, r.At.UTC(), r.Action, string(r.Actor), r.Note, r.PrevHash, terms})
	return b
}

// hashReceipt hashes the canonical receipt plus its signature and the
// agreement terms digest. JSON encoding removes the old "|" separator
// ambiguity: no two distinct receipts can share a hash.
func hashReceipt(a *Agreement, r Receipt) string {
	return hashSignedReceipt("receipt", a.TermsDigest(), r)
}
func wireDigest(domain string, v any) []byte {
	return digestDomain(1, domain, v)
}

func wireDigestV2(domain string, v any) []byte {
	return digestDomain(2, domain, v)
}

func digestDomain(version int, domain string, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("nexum: cannot encode digest input: %v", err))
	}
	return append([]byte(fmt.Sprintf("nex/nexum/v%d/%s\x00", version, domain)), b...)
}

// sealedPath is true when public ciphertext, a seal receipt, armed sealed
// scheme/public key, or a committed sealed mode shows this agreement is not a
// plaintext escrow. A nil Sealed pointer is not evidence of plaintext: JSON
// drops that private field.
func (a *Agreement) sealedPath() bool {
	if a == nil {
		return false
	}
	if a.Mode == ModeSealed || a.Sealed != nil || a.Scheme != "" || len(a.PublicKey) > 0 ||
		len(a.SealedLocks) > 0 || len(a.SealedSum) > 0 || len(a.SealedAggregate) > 0 || len(a.SealedEqualityProof) > 0 {
		return true
	}
	for _, r := range a.Receipts {
		if r.Action == "seal" {
			return true
		}
	}
	return false
}

// requireExecutableCustody rejects plaintext mutation of a decoded sealed
// snapshot that no longer carries its private ledger.
func (a *Agreement) requireExecutableCustody() error {
	if a.sealedPath() && (a == nil || a.Sealed == nil) {
		return ErrBadState
	}
	return nil
}

func validateAgreementTerms(a *Agreement) error {
	if a == nil {
		return ErrInvalid
	}
	if a.ID == "" || a.Kind == "" {
		return ErrInvalid
	}
	if a.Buyer == "" || a.Seller == "" {
		return ErrMissingParty
	}
	if a.Buyer == a.Seller {
		return ErrSameParty
	}
	if a.Amount <= 0 {
		return ErrZeroAmount
	}
	if !validMeterNumbers(a.Meter) {
		return ErrInvalid
	}
	if a.Format != 0 && a.Format != 1 && a.Format != FormatV2 {
		return ErrInvalid
	}
	if a.Format >= FormatV2 {
		if a.Mode != ModePlaintext && a.Mode != ModeSealed {
			return ErrInvalid
		}
		if a.Mode == ModePlaintext && (a.Scheme != "" || len(a.PublicKey) > 0 || len(a.SealedLocks) > 0 || len(a.SealedSum) > 0 || len(a.SealedAggregate) > 0 || len(a.SealedEqualityProof) > 0) {
			return ErrInvalid
		}
		if a.Mode == ModeSealed && (a.Scheme != SchemePaillier || len(a.PublicKey) == 0) {
			return ErrInvalid
		}
	} else {
		if a.Mode != "" {
			return ErrInvalid
		}
		if a.Scheme != "" && a.Scheme != SchemePaillier {
			return ErrInvalid
		}
	}
	return nil
}

// VerifyReceipts checks the hash chain, the terms digest in every link and
// each actor's signature where present. An error means the ledger was
// rewritten — its terms or its steps. Each receipt verifies against the
// terms digest of its moment: a "unit" receipt changes the terms mid-chain,
// so the verifier walks the receipts forward, applying each material-term
// receipt to its view before checking the next link.
func (a *Agreement) VerifyReceipts() error {
	if a == nil || len(a.Receipts) == 0 {
		return ErrInvalid
	}
	if err := validateAgreementTerms(a); err != nil {
		return err
	}
	var prev string
	var lockedBy string
	view := *a
	view.Receipts = nil
	view.steps = 0
	view.actorKeys = nil
	view.Status = ""
	view.LockedAt = nil
	view.ClosedAt = nil
	view.ReleasedTo = ""
	view.Deadline = time.Time{}
	// Replay from the genesis terms: the unit (if any) is a material term
	// set mid-chain by a "unit" receipt, so the verifier starts without it
	// and lets the chain justify the final state.
	view.Unit = Unit{}
	for i, r := range a.Receipts {
		if r.Seq != i+1 {
			return fmt.Errorf("nexum: receipt seq %d want %d", r.Seq, i+1)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("nexum: receipt %d broken prev", r.Seq)
		}
		terms := view.TermsDigest()
		want := hashSignedReceipt("receipt", terms, r)
		if r.Hash != want {
			return fmt.Errorf("nexum: receipt %d rewritten", r.Seq)
		}
		if len(r.ActorKey) != 0 || len(r.ActorSignature) != 0 {
			if len(r.ActorKey) != ed25519.PublicKeySize ||
				!ed25519.Verify(r.ActorKey, canonicalReceiptBytes(r, terms), r.ActorSignature) {
				return fmt.Errorf("nexum: receipt %d forged signature", r.Seq)
			}
		}
		prev = r.Hash
		if err := applyReceiptState(&view, r, &lockedBy); err != nil {
			return fmt.Errorf("nexum: receipt %d invalid transition: %w", r.Seq, err)
		}
		applyMaterialReceipt(&view, r)
	}
	if view.Unit != a.Unit {
		return fmt.Errorf("nexum: receipt chain does not account for the unit: %w", ErrInvalid)
	}
	if view.Status != a.Status || view.ReleasedTo != a.ReleasedTo ||
		!sameReceiptTime(view.LockedAt, a.LockedAt) || !sameReceiptTime(view.ClosedAt, a.ClosedAt) {
		return fmt.Errorf("nexum: receipt chain does not account for the outcome: %w", ErrInvalid)
	}
	return nil
}

func sameReceiptTime(a, b *time.Time) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.Equal(*b))
}

// applyReceiptState derives the public execution state from authenticated
// actions. Sealed equality-proof validation belongs to the settlement layer;
// this replay validates the actors and lifecycle that surround that proof.
func applyReceiptState(a *Agreement, r Receipt, lockedBy *string) error {
	if r.Actor != a.Buyer && r.Actor != a.Seller {
		return ErrWrongParty
	}
	if r.Action == "open" {
		if r.Seq != 1 || a.Status != "" || r.Actor != a.Buyer || !r.At.Equal(a.CreatedAt) {
			return ErrBadState
		}
		a.Status = StatusOpen
		return nil
	}
	if a.Status == "" || a.terminal() {
		return ErrBadState
	}
	at := r.At.UTC()
	switch r.Action {
	case "lock":
		if r.Actor != a.Buyer || a.Status != StatusOpen || a.Mode == ModeSealed || a.Scheme != "" || len(a.PublicKey) > 0 || *lockedBy != "" {
			return ErrBadState
		}
		*lockedBy = "lock"
		a.Status = StatusLocked
		a.LockedAt = &at
	case "seal":
		if r.Actor != a.Buyer || a.Mode == ModePlaintext {
			return ErrBadState
		}
		if a.Status != StatusOpen && (a.Status != StatusLocked || *lockedBy != "seal") {
			return ErrBadState
		}
		*lockedBy = "seal"
		a.Status = StatusLocked
		a.LockedAt = &at
	case "accept", "reject":
		if r.Actor != a.Seller || a.Status != StatusLocked {
			return ErrBadState
		}
		a.ClosedAt = &at
		if r.Action == "accept" {
			a.Status, a.ReleasedTo = StatusAccepted, a.Seller
		} else {
			a.Status, a.ReleasedTo = StatusRejected, a.Buyer
		}
	case "expire":
		if a.Deadline.IsZero() || r.At.Before(a.Deadline) {
			return ErrNotYet
		}
		a.Status, a.ReleasedTo, a.ClosedAt = StatusExpired, a.Buyer, &at
	case "deadline":
		deadline, err := time.Parse(time.RFC3339, r.Note)
		if err != nil {
			return ErrInvalid
		}
		if !deadline.After(r.At) {
			return ErrNotYet
		}
		// Historical deadline receipts have second precision. Replay uses the
		// recorded time without replacing the live snapshot's precise policy.
		a.Deadline = deadline
	case "unit":
		if r.Actor != a.Buyer || a.Status != StatusOpen {
			return ErrBadState
		}
	case "evidence":
		if r.Note == "" {
			return ErrEmptyCitation
		}
	default:
		return ErrInvalid
	}
	return nil
}

// applyMaterialReceipt advances the verification view with the fields a
// mid-chain receipt may legitimately change. This map IS the contract:
// a new kernel action that mutates a terms field must register here, and
// TestMaterialTermActionsExhaustive fails the build-adjacent suite if an
// emitted action is missing.
var materialTermActions = map[string]func(v *Agreement, r Receipt){
	"unit": func(v *Agreement, r Receipt) { v.Unit = Unit{Symbol: r.Note} },
}

func applyMaterialReceipt(v *Agreement, r Receipt) {
	if fn, ok := materialTermActions[r.Action]; ok {
		fn(v, r)
	}
}

// agreementActions is every action the Agreement kernel can emit. Kept
// beside the whitelist so they evolve together; the exhaustive test
// cross-checks them.
var agreementActions = []string{
	"open", "lock", "accept", "reject", "deadline", "expire", "evidence",
	"seal", "unit",
}

// AgreementActions returns the receipt actions the kernel may emit, in no
// particular order. TestMaterialTermActionsExhaustive pins that every one
// is either in materialTermActions or provably leaves terms untouched.
func AgreementActions() []string {
	return append([]string(nil), agreementActions...)
}

// AcceptWithEvidence records evidence and accepts as one in-memory transition.
// Callers must serialize access. Failed proof or metering checks change no state.
func (a *Agreement) AcceptWithEvidence(author, actor Party, citation string, now time.Time) error {
	next := *a
	// Note and Accept only append receipts and replace scalar/pointer fields.
	// Equality proving reads the ledger; it does not mutate it.
	next.Receipts = append([]Receipt(nil), a.Receipts...)
	if err := next.Note(author, "evidence", citation, now); err != nil {
		return err
	}
	if err := next.Accept(actor, now); err != nil {
		return err
	}
	*a = next
	return nil
}

func (a *Agreement) head() string {
	if n := len(a.Receipts); n > 0 {
		return a.Receipts[n-1].Hash
	}
	return ""
}

// signReceipt arms one receipt with the actor's Ed25519 signature over
// its canonical message, shared by every receipt-bearing ledger. Callers
// own deciding which parties may sign; the signature covers the receipt
// fields, the previous hash and the ledger's terms digest.
func signReceipt(r *Receipt, key ed25519.PrivateKey, terms string) {
	if len(key) != ed25519.PrivateKeySize {
		return
	}
	r.ActorKey = key.Public().(ed25519.PublicKey)
	r.ActorSignature = ed25519.Sign(key, canonicalReceiptBytes(*r, terms))
}
