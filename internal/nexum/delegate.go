package nexum

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// KindDelegate is a parent offering work to an intern. Reward moves
// when the work is proven done (citation on the ledger).
const KindDelegate = "delegate.intern"

const (
	StatusOffered Status = "offered"
	StatusClaimed Status = "claimed"
	StatusProven  Status = "proven"
	StatusPaid    Status = "paid"
)

// Task is the work being offered. ProofKind v1 is "citation": a
// ledger note the parent accepts. Not a vibe.
type Task struct {
	Offer     string `json:"offer"`
	ProofKind string `json:"proof_kind"` // citation
}

// Delegate is a Nexum: parent → intern, reward on proven work.
// Format 0 notes are human text. The proof citation is the whole proof
// note, which is unambiguous. FormatV2 binds a canonical event instead.
// RejectStage is set only on format v2. Format 0 keeps the historical
// reject-proof action even when no proof was submitted.
type Delegate struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Parent      Party      `json:"parent"`
	Intern      Party      `json:"intern"`
	Reward      int64      `json:"reward"`
	Unit        Unit       `json:"unit,omitempty"`
	Task        Task       `json:"task"`
	Status      Status     `json:"status"`
	Proof       string     `json:"proof,omitempty"`
	Meter       Meter      `json:"meter"`
	CreatedAt   time.Time  `json:"created_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
	ReleasedTo  Party      `json:"released_to,omitempty"`
	Receipts    []Receipt  `json:"receipts"`
	Format      int        `json:"format,omitempty"`
	RejectStage string     `json:"reject_stage,omitempty"`
	steps       int
	// actorKeys maps Party to the signing key for new receipts; nil
	// keeps legacy unsigned local ledgers.
	actorKeys map[Party]ed25519.PrivateKey
}

// SignReceipts arms receipt signatures for the delegation parties.
func (d *Delegate) SignReceipts(keys map[Party]ed25519.PrivateKey) error {
	if d == nil {
		return ErrInvalid
	}
	cloned, err := cloneActorKeys(keys, func(p Party) bool {
		return p == d.Parent || p == d.Intern
	})
	if err != nil {
		return err
	}
	d.actorKeys = cloned
	return nil
}

var (
	ErrEmptyOffer = errors.New("nexum: task offer required")
	ErrNoProof    = errors.New("nexum: proof citation required")
	ErrNotClaimed = errors.New("nexum: intern has not claimed")
)

// OpenDelegate is a parent offering work. Intern has not claimed yet.
// New delegations use format v2.
func OpenDelegate(id string, parent, intern Party, reward int64, task Task, meter Meter, now time.Time) (*Delegate, error) {
	return openDelegate(FormatV2, id, parent, intern, reward, task, meter, now)
}

func openDelegate(format int, id string, parent, intern Party, reward int64, task Task, meter Meter, now time.Time) (*Delegate, error) {
	if !validSiblingFormat(format) {
		return nil, ErrInvalid
	}
	if parent == "" || intern == "" {
		return nil, ErrMissingParty
	}
	if parent == intern {
		return nil, ErrSameParty
	}
	if reward <= 0 {
		return nil, ErrZeroAmount
	}
	if task.Offer == "" {
		return nil, ErrEmptyOffer
	}
	if task.ProofKind == "" {
		task.ProofKind = "citation"
	}
	if !validMeterNumbers(meter) {
		return nil, ErrInvalid
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 16
	}
	if meter.MaxSteps > 128 {
		return nil, ErrInvalid
	}
	d := &Delegate{
		ID:        id,
		Kind:      KindDelegate,
		Parent:    parent,
		Intern:    intern,
		Reward:    reward,
		Task:      task,
		Status:    StatusOffered,
		Meter:     meter,
		CreatedAt: now.UTC(),
		Format:    format,
	}
	note, err := d.offerNote()
	if err != nil {
		return nil, err
	}
	if err := d.append(parent, "offer", note, now); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Delegate) offerNote() (string, error) {
	if d.Format != FormatV2 {
		return d.Task.Offer, nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:      FormatV2,
		Ledger: ledgerDelegate,
		Action: "offer",
		Actor:  string(d.Parent),
		Reward: d.Reward,
	})
}

func (d *Delegate) phase() (delegatePhase, error) {
	ph, ok := delegatePhaseOf(d.Status)
	if !ok {
		return "", ErrBadState
	}
	return ph, nil
}

func (d *Delegate) commit(fn func(*Delegate) error) error {
	next := d.clone()
	if err := fn(next); err != nil {
		return err
	}
	*d = *next
	return nil
}

func (d *Delegate) clone() *Delegate {
	next := *d
	next.Receipts = append([]Receipt(nil), d.Receipts...)
	return &next
}

// Claim is the intern taking the work. Cancel is illegal after this.
func (d *Delegate) Claim(actor Party, now time.Time) error {
	return d.commit(func(n *Delegate) error {
		return n.claim(actor, now)
	})
}

func (d *Delegate) claim(actor Party, now time.Time) error {
	if actor != d.Intern {
		return ErrWrongParty
	}
	if _, err := d.phase(); err != nil {
		return err
	}
	if d.terminal() {
		return ErrTakeback
	}
	if !phaseAllows(delegatePhaseTable, d.Format, "claim", d.Status) {
		return ErrBadState
	}
	note, err := d.simpleNote(actor, "claim", "intern claimed")
	if err != nil {
		return err
	}
	if err := d.append(actor, "claim", note, now); err != nil {
		return err
	}
	d.Status = StatusClaimed
	return nil
}

// SubmitProof is the intern citing evidence the work is done.
func (d *Delegate) SubmitProof(actor Party, citation string, now time.Time) error {
	return d.commit(func(n *Delegate) error {
		return n.submitProof(actor, citation, now)
	})
}

func (d *Delegate) submitProof(actor Party, citation string, now time.Time) error {
	if actor != d.Intern {
		return ErrWrongParty
	}
	if _, err := d.phase(); err != nil {
		return err
	}
	if d.Status != StatusClaimed {
		return ErrNotClaimed
	}
	if !phaseAllows(delegatePhaseTable, d.Format, "proof", d.Status) {
		return ErrBadState
	}
	if citation == "" {
		return ErrNoProof
	}
	note, err := d.proofNote(actor, citation)
	if err != nil {
		return err
	}
	if err := d.append(actor, "proof", note, now); err != nil {
		return err
	}
	d.Proof = citation
	d.Status = StatusProven
	return nil
}

func (d *Delegate) proofNote(actor Party, citation string) (string, error) {
	if d.Format != FormatV2 {
		return citation, nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:               FormatV2,
		Ledger:          ledgerDelegate,
		Action:          "proof",
		Actor:           string(actor),
		Proof:           citation,
		ProofCommitment: commitString("proof", citation),
	})
}

// AcceptProof is the parent releasing the reward. Terminal. No takeback.
func (d *Delegate) AcceptProof(actor Party, now time.Time) error {
	return d.commit(func(n *Delegate) error {
		return n.acceptProof(actor, now)
	})
}

func (d *Delegate) acceptProof(actor Party, now time.Time) error {
	if actor != d.Parent {
		return ErrWrongParty
	}
	if _, err := d.phase(); err != nil {
		return err
	}
	if d.terminal() {
		return ErrTakeback
	}
	if !phaseAllows(delegatePhaseTable, d.Format, "pay", d.Status) {
		return ErrBadState
	}
	if d.Proof == "" {
		return ErrNoProof
	}
	note, err := d.payNote(actor)
	if err != nil {
		return err
	}
	if err := d.append(actor, "pay", note, now); err != nil {
		return err
	}
	t := now.UTC()
	d.ClosedAt = &t
	d.ReleasedTo = d.Intern
	d.Status = StatusPaid
	return nil
}

func (d *Delegate) payNote(actor Party) (string, error) {
	if d.Format != FormatV2 {
		return fmt.Sprintf("reward %d released to intern", d.Reward), nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:          FormatV2,
		Ledger:     ledgerDelegate,
		Action:     "pay",
		Actor:      string(actor),
		Reward:     d.Reward,
		ReleasedTo: string(d.Intern),
	})
}

// RejectProof is the parent refusing the work. No reward. Terminal.
// Claimed and proven are both legal. Format v2 records stage "claimed"
// with action "reject" when no proof was submitted, and "reject-proof"
// only after proof. Format 0 still writes the historical reject-proof
// receipt and is not re-signed.
func (d *Delegate) RejectProof(actor Party, now time.Time) error {
	return d.commit(func(n *Delegate) error {
		return n.rejectProof(actor, now)
	})
}

func (d *Delegate) rejectProof(actor Party, now time.Time) error {
	if actor != d.Parent {
		return ErrWrongParty
	}
	if _, err := d.phase(); err != nil {
		return err
	}
	if d.terminal() {
		return ErrTakeback
	}
	action := "reject-proof"
	stage := RejectStageProven
	reason := "proof refused"
	legacy := "proof refused, no reward"
	if d.Status == StatusClaimed {
		stage = RejectStageClaimed
		reason = "rejected-before-proof"
		if d.Format == FormatV2 {
			action = "reject"
		}
	}
	if !phaseAllows(delegatePhaseTable, d.Format, action, d.Status) {
		return ErrBadState
	}
	if stage == RejectStageProven && d.Proof == "" {
		return ErrNoProof
	}
	note, err := d.rejectNote(actor, action, stage, reason, legacy)
	if err != nil {
		return err
	}
	if err := d.append(actor, action, note, now); err != nil {
		return err
	}
	t := now.UTC()
	d.ClosedAt = &t
	d.ReleasedTo = d.Parent
	d.Status = StatusRejected
	if d.Format == FormatV2 {
		d.RejectStage = stage
	}
	return nil
}

func (d *Delegate) rejectNote(actor Party, action, stage, reason, legacy string) (string, error) {
	if d.Format != FormatV2 {
		return legacy, nil
	}
	ev := siblingEvent{
		V:          FormatV2,
		Ledger:     ledgerDelegate,
		Action:     action,
		Actor:      string(actor),
		Stage:      stage,
		Reason:     reason,
		ReleasedTo: string(d.Parent),
	}
	if stage == RejectStageProven {
		ev.ProofCommitment = commitString("proof", d.Proof)
	}
	return encodeSiblingEvent(ev)
}

// Cancel is the parent pulling the offer. Legal only before claim.
func (d *Delegate) Cancel(actor Party, now time.Time) error {
	return d.commit(func(n *Delegate) error {
		return n.cancel(actor, now)
	})
}

func (d *Delegate) cancel(actor Party, now time.Time) error {
	if actor != d.Parent {
		return ErrWrongParty
	}
	if _, err := d.phase(); err != nil {
		return err
	}
	// Claimed, proven and terminal offers do not reopen into a cancel.
	// Unknown statuses already returned ErrBadState.
	if !phaseAllows(delegatePhaseTable, d.Format, "cancel", d.Status) {
		return ErrTakeback
	}
	note, err := d.cancelNote(actor)
	if err != nil {
		return err
	}
	if err := d.append(actor, "cancel", note, now); err != nil {
		return err
	}
	t := now.UTC()
	d.ClosedAt = &t
	d.ReleasedTo = d.Parent
	d.Status = StatusRejected
	return nil
}

func (d *Delegate) cancelNote(actor Party) (string, error) {
	if d.Format != FormatV2 {
		return "offer cancelled before claim", nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:          FormatV2,
		Ledger:     ledgerDelegate,
		Action:     "cancel",
		Actor:      string(actor),
		Reason:     "cancelled-before-claim",
		ReleasedTo: string(d.Parent),
	})
}

func (d *Delegate) simpleNote(actor Party, action, legacy string) (string, error) {
	if d.Format != FormatV2 {
		return legacy, nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:      FormatV2,
		Ledger: ledgerDelegate,
		Action: action,
		Actor:  string(actor),
	})
}

func (d *Delegate) terminal() bool {
	ph, ok := delegatePhaseOf(d.Status)
	return ok && ph.terminal()
}

// DerivedRejectStage reports whether a rejection happened before proof
// or after it. Cancel is not a proof stage. Format 0 is derived from
// the receipt sequence; its reject-proof prose is not a witness.
func (d *Delegate) DerivedRejectStage() (string, error) {
	if err := d.VerifyReceipts(); err != nil {
		return "", err
	}
	return deriveRejectStage(d.Receipts), nil
}

func deriveRejectStage(receipts []Receipt) string {
	sawProof := false
	stage := ""
	for _, r := range receipts {
		switch r.Action {
		case "proof":
			sawProof = true
		case "reject":
			stage = RejectStageClaimed
		case "reject-proof":
			if sawProof {
				stage = RejectStageProven
			} else {
				stage = RejectStageClaimed
			}
		}
	}
	return stage
}

func (d *Delegate) ledger() receiptLedger {
	return receiptLedger{
		format:      d.Format,
		maxSteps:    d.Meter.MaxSteps,
		budget:      d.Meter.BudgetUSD,
		cost:        d.Meter.CostUSD,
		checkBudget: true,
		steps:       &d.steps,
		receipts:    &d.Receipts,
		terms:       d.termsDigest,
		hashKind:    hashDelegateReceipt,
		keys:        d.actorKeys,
	}
}

func (d *Delegate) append(actor Party, action, note string, now time.Time) error {
	return d.ledger().append(actor, action, note, now)
}

// VerifyReceipts checks the hash chain and replays claim, proof,
// rejection, payment, beneficiary and close time. Delegate notes are
// unambiguous: a proof note is the whole citation, and other notes are
// not parsed. An empty receipt list cannot establish a paid or rejected
// delegation. An embedded key is not the parent or the intern.
func (d *Delegate) VerifyReceipts() error {
	_, err := d.classify()
	return err
}

// ReceiptAssurance is state-replay when verification succeeds. Format 0
// and format v2 both replay; v0 does not treat the reject-proof sentence
// as proof that a citation was submitted.
func (d *Delegate) ReceiptAssurance() (string, error) {
	return d.classify()
}

func (d *Delegate) classify() (string, error) {
	if d == nil || len(d.Receipts) == 0 {
		return "", ErrInvalid
	}
	if !validSiblingFormat(d.Format) || d.Kind != KindDelegate || !validMeterNumbers(d.Meter) {
		return "", ErrInvalid
	}
	if err := validateDelegateShape(d); err != nil {
		return "", err
	}
	if err := verifySiblingChain(d.Receipts, d.termsDigest(), hashDelegateReceipt); err != nil {
		return "", err
	}
	if err := replayDelegate(d); err != nil {
		return "", err
	}
	return AssuranceStateReplay, nil
}

func validateDelegateShape(d *Delegate) error {
	if d.Parent == "" || d.Intern == "" {
		return ErrMissingParty
	}
	if d.Parent == d.Intern {
		return ErrSameParty
	}
	if d.Reward <= 0 {
		return ErrZeroAmount
	}
	if d.Task.Offer == "" {
		return ErrEmptyOffer
	}
	return nil
}

type delegateView struct {
	status   Status
	proof    string
	released Party
	closed   *time.Time
	stage    string
}

func replayDelegate(d *Delegate) error {
	view := delegateView{status: StatusOffered}
	for i, r := range d.Receipts {
		if err := applyDelegateReceipt(d, &view, r, i == 0); err != nil {
			return fmt.Errorf("nexum: receipt %d: %w", r.Seq, err)
		}
	}
	if view.status != d.Status || view.proof != d.Proof || view.released != d.ReleasedTo || !sameReceiptTime(view.closed, d.ClosedAt) {
		return snapshotMismatch(ErrInvalid)
	}
	if d.Format == FormatV2 && view.stage != d.RejectStage {
		return snapshotMismatch(ErrInvalid)
	}
	if _, ok := delegatePhaseOf(d.Status); !ok {
		return snapshotMismatch(ErrBadState)
	}
	return nil
}

func applyDelegateReceipt(d *Delegate, view *delegateView, r Receipt, genesis bool) error {
	if r.Actor != d.Parent && r.Actor != d.Intern {
		return ErrWrongParty
	}
	var ev siblingEvent
	if d.Format == FormatV2 {
		parsed, err := parseSiblingEvent(r.Note)
		if err != nil {
			return err
		}
		if err := eventMatchesReceipt(parsed, ledgerDelegate, r); err != nil {
			return err
		}
		ev = parsed
	}
	if genesis {
		if r.Action != "offer" || r.Actor != d.Parent || !r.At.Equal(d.CreatedAt) {
			return ErrBadState
		}
		if d.Format == FormatV2 && ev.Reward != d.Reward {
			return ErrInvalid
		}
		return nil
	}
	if view.status == StatusPaid || view.status == StatusRejected {
		return ErrBadState
	}
	if !phaseAllows(delegatePhaseTable, d.Format, r.Action, view.status) {
		return ErrBadState
	}
	switch r.Action {
	case "claim":
		if r.Actor != d.Intern {
			return ErrWrongParty
		}
		view.status = StatusClaimed
	case "proof":
		if r.Actor != d.Intern {
			return ErrWrongParty
		}
		citation := r.Note
		if d.Format == FormatV2 {
			citation = ev.Proof
			if citation == "" || ev.ProofCommitment != commitString("proof", citation) {
				return ErrNoProof
			}
		}
		if citation == "" {
			return ErrNoProof
		}
		view.proof = citation
		view.status = StatusProven
	case "pay":
		if r.Actor != d.Parent {
			return ErrWrongParty
		}
		if view.proof == "" {
			return ErrNoProof
		}
		if d.Format == FormatV2 && (ev.Reward != d.Reward || ev.ReleasedTo != string(d.Intern)) {
			return ErrInvalid
		}
		t := r.At.UTC()
		view.closed = &t
		view.released = d.Intern
		view.status = StatusPaid
	case "reject", "reject-proof":
		if r.Actor != d.Parent {
			return ErrWrongParty
		}
		stage := RejectStageProven
		if view.proof == "" {
			stage = RejectStageClaimed
		}
		if d.Format == FormatV2 {
			if ev.Stage != stage || ev.ReleasedTo != string(d.Parent) {
				return ErrInvalid
			}
			if stage == RejectStageClaimed && (r.Action != "reject" || ev.ProofCommitment != "") {
				return ErrInvalid
			}
			if stage == RejectStageProven && (r.Action != "reject-proof" || ev.ProofCommitment != commitString("proof", view.proof)) {
				return ErrInvalid
			}
		}
		t := r.At.UTC()
		view.closed = &t
		view.released = d.Parent
		view.status = StatusRejected
		view.stage = stage
	case "cancel":
		if r.Actor != d.Parent || view.status != StatusOffered {
			return ErrBadState
		}
		if d.Format == FormatV2 && ev.ReleasedTo != string(d.Parent) {
			return ErrInvalid
		}
		t := r.At.UTC()
		view.closed = &t
		view.released = d.Parent
		view.status = StatusRejected
	default:
		return ErrInvalid
	}
	return nil
}

// termsDigest commits the delegation's immutable binding terms into every
// receipt hash. Excludes status and proof: those change as work happens,
// and each change is itself a chained receipt. Format v2 also binds the
// unit and the cost-and-steps meter policy. Format 0 is unchanged.
func (d *Delegate) termsDigest() string {
	if d.Format == FormatV2 {
		sum := sha256.Sum256(wireDigestV2("delegate-terms", struct {
			ID          string    `json:"id"`
			Kind        string    `json:"kind"`
			Parent      Party     `json:"parent"`
			Intern      Party     `json:"intern"`
			Reward      int64     `json:"reward"`
			Unit        Unit      `json:"unit"`
			Task        Task      `json:"task"`
			CreatedAt   time.Time `json:"created_at"`
			Format      int       `json:"format"`
			MeterPolicy string    `json:"meter_policy"`
		}{d.ID, d.Kind, d.Parent, d.Intern, d.Reward, d.Unit, d.Task, d.CreatedAt, d.Format, meterPolicyCostAndSteps}))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(wireDigest("delegate-terms", struct {
		ID        string    `json:"id"`
		Kind      string    `json:"kind"`
		Parent    Party     `json:"parent"`
		Intern    Party     `json:"intern"`
		Reward    int64     `json:"reward"`
		Task      Task      `json:"task"`
		CreatedAt time.Time `json:"created_at"`
	}{d.ID, d.Kind, d.Parent, d.Intern, d.Reward, d.Task, d.CreatedAt}))
	return hex.EncodeToString(sum[:])
}
