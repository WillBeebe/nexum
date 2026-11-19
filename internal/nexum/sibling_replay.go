package nexum

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Sibling receipt formats. Format 0 keeps the original human notes and the
// original terms digest. FormatV2 binds a canonical event payload, and the
// council decision, into the receipt hash. v1 hashes are not recomputed.
const (
	hashCouncilReceipt  = "council-receipt"
	hashDelegateReceipt = "delegate-receipt"
	hashWorkflowReceipt = "workflow-receipt"

	ledgerCouncil  = "council"
	ledgerDelegate = "delegate"
	ledgerWorkflow = "workflow"

	// Meter policies committed in format v2 terms. Workflow stays step-only;
	// a budget rule would be a later format, not a rereading of old receipts.
	meterPolicySteps        = "steps"
	meterPolicyCostAndSteps = "cost-and-steps"

	// ReceiptAssurance values. State replay compares the snapshot with the
	// chain. Path replay (format 0 workflow execute) uniquely replays the
	// exact path, action, status and close time against the committed graph
	// without committed input facts. Commitment-only means a format v2
	// workflow receipt bound a facts digest without the facts or a checked
	// proof. Legacy chain-only means the hash chain, roles, phases and
	// terminal fields are checked while legacy prose matched multiple
	// structural interpretations (prefix-colliding req IDs on one holder or
	// whitespace-colliding node IDs).
	AssuranceStateReplay    = "state-replay"
	AssurancePathReplay     = "path-replay"
	AssuranceLegacyChain    = "legacy-chain-only"
	AssuranceCommitmentOnly = "commitment-only"

	// FactsCommitted means the host facts were supplied and bound, then the
	// tree was walked. It does not mean those facts are true.
	// FactsCommitmentOnly means the receipt has a digest and a recorded path,
	// not the facts needed to re-select the branch.
	// FactsVerified is rejected: this kernel has no host-fact proof.
	FactsCommitted      = "committed"
	FactsCommitmentOnly = "commitment-only"
	FactsVerified       = "verified"

	// Rejection stages. "claimed" is a refusal before any proof. Only
	// "proven" is a proof rejection. Format 0 keeps the historical
	// reject-proof action and does not store this field.
	RejectStageClaimed = "claimed"
	RejectStageProven  = "proven"
)

// Internal lifecycle names. The exported Status strings stay the serialized
// values; these types are the per-ledger allowlists.
type councilPhase string

const (
	councilOpen     councilPhase = "open"
	councilReady    councilPhase = "ready"
	councilExecuted councilPhase = "executed"
	councilRefused  councilPhase = "refused"
)

func councilPhaseOf(s Status) (councilPhase, bool) {
	switch councilPhase(s) {
	case councilOpen, councilReady, councilExecuted, councilRefused:
		return councilPhase(s), true
	default:
		return "", false
	}
}

func (p councilPhase) terminal() bool {
	return p == councilExecuted || p == councilRefused
}

type delegatePhase string

const (
	delegateOffered  delegatePhase = "offered"
	delegateClaimed  delegatePhase = "claimed"
	delegateProven   delegatePhase = "proven"
	delegatePaid     delegatePhase = "paid"
	delegateRejected delegatePhase = "rejected"
)

func delegatePhaseOf(s Status) (delegatePhase, bool) {
	switch delegatePhase(s) {
	case delegateOffered, delegateClaimed, delegateProven, delegatePaid, delegateRejected:
		return delegatePhase(s), true
	default:
		return "", false
	}
}

func (p delegatePhase) terminal() bool {
	return p == delegatePaid || p == delegateRejected
}

type workflowPhase string

const (
	workflowOpen     workflowPhase = "open"
	workflowExecuted workflowPhase = "executed"
)

func workflowPhaseOf(s Status) (workflowPhase, bool) {
	switch workflowPhase(s) {
	case workflowOpen, workflowExecuted:
		return workflowPhase(s), true
	default:
		return "", false
	}
}

func (p workflowPhase) terminal() bool {
	return p == workflowExecuted
}

// phaseRule is one legal action. From is empty for the genesis action.
// Formats empty means every supported sibling format.
type phaseRule struct {
	Action  string
	From    []Status
	Role    string
	Formats []int
}

func (r phaseRule) allowsFormat(format int) bool {
	if len(r.Formats) == 0 {
		return true
	}
	for _, f := range r.Formats {
		if f == format {
			return true
		}
	}
	return false
}

// councilPhaseTable, delegatePhaseTable and workflowPhaseTable are the
// live and replay allowlists. Refuse stays legal after opt-in (ready).
// Delegate rejection stays legal from claimed or proven; format v2 uses
// action "reject" before proof so the receipt is not a proof rejection.
var councilPhaseTable = []phaseRule{
	{Action: "open", Role: "first-party"},
	{Action: "satisfy", From: []Status{StatusOpen}, Role: "holder"},
	{Action: "opt-in", From: []Status{StatusOpen, StatusReady}, Role: "party"},
	{Action: "refuse", From: []Status{StatusOpen, StatusReady}, Role: "party"},
	{Action: "execute", From: []Status{StatusOpen, StatusReady}, Role: "party"},
}

var delegatePhaseTable = []phaseRule{
	{Action: "offer", Role: "parent"},
	{Action: "claim", From: []Status{StatusOffered}, Role: "intern"},
	{Action: "proof", From: []Status{StatusClaimed}, Role: "intern"},
	{Action: "pay", From: []Status{StatusProven}, Role: "parent"},
	{Action: "cancel", From: []Status{StatusOffered}, Role: "parent"},
	{Action: "reject-proof", From: []Status{StatusClaimed, StatusProven}, Role: "parent", Formats: []int{0}},
	{Action: "reject-proof", From: []Status{StatusProven}, Role: "parent", Formats: []int{FormatV2}},
	{Action: "reject", From: []Status{StatusClaimed}, Role: "parent", Formats: []int{FormatV2}},
}

var workflowPhaseTable = []phaseRule{
	{Action: "open", Role: "actor"},
	{Action: "execute", From: []Status{StatusOpen}, Role: "actor"},
}

func matchPhase(rules []phaseRule, format int, action string, from Status) (phaseRule, bool) {
	for _, rule := range rules {
		if rule.Action != action || !rule.allowsFormat(format) || len(rule.From) == 0 {
			continue
		}
		for _, st := range rule.From {
			if st == from {
				return rule, true
			}
		}
	}
	return phaseRule{}, false
}

func phaseAllows(rules []phaseRule, format int, action string, from Status) bool {
	_, ok := matchPhase(rules, format, action, from)
	return ok
}

func validSiblingFormat(format int) bool {
	return format == 0 || format == FormatV2
}

// siblingEvent is the format-v2 receipt note. It is JSON, not a delimiter
// scheme over the historical prose. Format 0 notes are never parsed into it.
type siblingEvent struct {
	V                  int             `json:"v"`
	Ledger             string          `json:"ledger"`
	Action             string          `json:"action"`
	Actor              string          `json:"actor"`
	ReqID              string          `json:"req_id,omitempty"`
	Citation           string          `json:"citation,omitempty"`
	CitationCommitment string          `json:"citation_commitment,omitempty"`
	Proof              string          `json:"proof,omitempty"`
	ProofCommitment    string          `json:"proof_commitment,omitempty"`
	Stage              string          `json:"stage,omitempty"`
	Reason             string          `json:"reason,omitempty"`
	Decision           string          `json:"decision,omitempty"`
	Reward             int64           `json:"reward,omitempty"`
	ReleasedTo         string          `json:"released_to,omitempty"`
	FactsPresent       bool            `json:"facts_present,omitempty"`
	Facts              map[string]bool `json:"facts,omitempty"`
	FactsCommitment    string          `json:"facts_commitment,omitempty"`
	FactsAssurance     string          `json:"facts_assurance,omitempty"`
	Path               []string        `json:"path,omitempty"`
	Result             string          `json:"result,omitempty"`
}

func commitString(domain, value string) string {
	sum := sha256.Sum256([]byte("nex/nexum/commit/v1/" + domain + "\x00" + value))
	return hex.EncodeToString(sum[:])
}

func commitFacts(facts map[string]bool) (string, error) {
	if facts == nil {
		facts = map[string]bool{}
	}
	raw, err := json.Marshal(facts)
	if err != nil {
		return "", err
	}
	return commitString("facts", string(raw)), nil
}

func encodeSiblingEvent(ev siblingEvent) (string, error) {
	if ev.V != FormatV2 {
		return "", ErrInvalid
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseSiblingEvent(note string) (siblingEvent, error) {
	dec := json.NewDecoder(strings.NewReader(note))
	dec.DisallowUnknownFields()
	var ev siblingEvent
	if err := dec.Decode(&ev); err != nil {
		return siblingEvent{}, fmt.Errorf("nexum: event payload: %w", ErrInvalid)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return siblingEvent{}, fmt.Errorf("nexum: trailing event payload: %w", ErrInvalid)
	}
	if ev.V != FormatV2 {
		return siblingEvent{}, fmt.Errorf("nexum: event version: %w", ErrInvalid)
	}
	return ev, nil
}

func eventMatchesReceipt(ev siblingEvent, ledger string, r Receipt) error {
	if ev.Ledger != ledger || ev.Action != r.Action || ev.Actor != string(r.Actor) {
		return fmt.Errorf("nexum: event does not match receipt %d: %w", r.Seq, ErrInvalid)
	}
	return nil
}

type receiptLedger struct {
	format      int
	maxSteps    int
	budget      float64
	cost        float64
	checkBudget bool
	steps       *int
	receipts    *[]Receipt
	terms       func() string
	hashKind    string
	keys        map[Party]ed25519.PrivateKey
}

// append commits one receipt only after the step and budget checks. A
// failure leaves the slice, the step counter and the hash head alone.
func (l receiptLedger) append(actor Party, action, note string, now time.Time) error {
	if !validSiblingFormat(l.format) {
		return ErrInvalid
	}
	if note == "" || action == "" || actor == "" {
		return ErrInvalid
	}
	if l.receipts == nil {
		return ErrInvalid
	}
	n := len(*l.receipts)
	if l.maxSteps <= 0 || n >= l.maxSteps {
		return ErrDoS
	}
	if l.checkBudget && l.budget > 0 && l.cost > l.budget {
		return ErrBudget
	}
	prev := ""
	if n > 0 {
		prev = (*l.receipts)[n-1].Hash
	}
	r := Receipt{
		Seq:      n + 1,
		At:       now.UTC(),
		Action:   action,
		Actor:    actor,
		Note:     note,
		PrevHash: prev,
	}
	terms := l.terms()
	signReceipt(&r, l.keys[actor], terms)
	r.Hash = hashSignedReceipt(l.hashKind, terms, r)
	*l.receipts = append(*l.receipts, r)
	if l.steps != nil {
		*l.steps = len(*l.receipts)
	}
	return nil
}

// verifySiblingChain checks sequence, linkage, hash and, when present, the
// signature under the embedded key. The key is not a role. Callers still
// match Actor to the ledger roster.
func verifySiblingChain(receipts []Receipt, terms, kind string) error {
	if len(receipts) == 0 {
		return ErrInvalid
	}
	var prev string
	for i, r := range receipts {
		if r.Seq != i+1 {
			return fmt.Errorf("nexum: receipt seq %d want %d", r.Seq, i+1)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("nexum: receipt %d broken prev", r.Seq)
		}
		if r.Hash != hashSignedReceipt(kind, terms, r) {
			return fmt.Errorf("nexum: receipt %d rewritten", r.Seq)
		}
		if len(r.ActorKey) != 0 || len(r.ActorSignature) != 0 {
			if len(r.ActorKey) != ed25519.PublicKeySize ||
				!ed25519.Verify(r.ActorKey, canonicalReceiptBytes(r, terms), r.ActorSignature) {
				return fmt.Errorf("nexum: receipt %d forged signature", r.Seq)
			}
		}
		prev = r.Hash
	}
	return nil
}

func sameConsent(a, b map[Party]bool) bool {
	if countConsent(a) != countConsent(b) {
		return false
	}
	for k, v := range a {
		if v && !b[k] {
			return false
		}
	}
	return true
}

func countConsent(m map[Party]bool) int {
	n := 0
	for _, v := range m {
		if v {
			n++
		}
	}
	return n
}

func sameReqs(a, b []Requirement) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func snapshotMismatch(err error) error {
	if err == nil {
		err = ErrInvalid
	}
	return fmt.Errorf("nexum: receipt replay does not match the snapshot: %w", err)
}

func hexCommitment(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
