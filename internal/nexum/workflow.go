package nexum

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KindWorkflow is a deterministic hierarchical decision tree.
// The tree walks; the agent does not invent the path.
const KindWorkflow = "workflow.tree"

// Node is one step. Kind is "gate" (branch on facts, first matching
// child in listed order) or "action" (terminal).
type Node struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"` // gate | action
	Require []string `json:"require,omitempty"`
	Next    []string `json:"next,omitempty"`
}

// Workflow is a Nexum: facts in, a single path out, recorded.
// Format 0 execute notes record the path and terminal action against the
// committed graph without committing input facts. FormatV2 binds the
// path, the action and a facts commitment. Supplied facts are committed,
// not verified: walking them does not prove the host facts are true.
// The meter policy is steps only.
type Workflow struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"`
	Root           string          `json:"root"`
	Nodes          map[string]Node `json:"nodes"`
	Status         Status          `json:"status"`
	Path           []string        `json:"path,omitempty"`
	Action         string          `json:"action,omitempty"`
	FactsAssurance string          `json:"facts_assurance,omitempty"`
	Meter          Meter           `json:"meter"`
	CreatedAt      time.Time       `json:"created_at"`
	ClosedAt       *time.Time      `json:"closed_at,omitempty"`
	Receipts       []Receipt       `json:"receipts"`
	Actor          Party           `json:"actor"`
	Format         int             `json:"format,omitempty"`
	steps          int
	// actorKeys maps Party to the signing key for new receipts; nil
	// keeps legacy unsigned local ledgers.
	actorKeys map[Party]ed25519.PrivateKey
}

// SignReceipts arms receipt signatures for workflow actors.
func (w *Workflow) SignReceipts(keys map[Party]ed25519.PrivateKey) error {
	if w == nil {
		return ErrInvalid
	}
	cloned, err := cloneActorKeys(keys, func(p Party) bool {
		return p == w.Actor
	})
	if err != nil {
		return err
	}
	w.actorKeys = cloned
	return nil
}

var (
	ErrBadTree   = errors.New("nexum: workflow tree invalid")
	ErrNoPath    = errors.New("nexum: no path given facts")
	ErrWalkLoop  = errors.New("nexum: workflow loop")
	ErrEmptyFact = errors.New("nexum: facts required to walk")
	// ErrFactsUnverified means a receipt claimed host facts were proved.
	// A deterministic walk only commits the facts it was given.
	ErrFactsUnverified = errors.New("nexum: workflow facts are not verified")
)

// OpenWorkflow records the tree. Walk happens at Execute.
// New workflows use format v2. Require and Next are copied.
func OpenWorkflow(id string, actor Party, root string, nodes map[string]Node, meter Meter, now time.Time) (*Workflow, error) {
	return openWorkflow(FormatV2, id, actor, root, nodes, meter, now)
}

func openWorkflow(format int, id string, actor Party, root string, nodes map[string]Node, meter Meter, now time.Time) (*Workflow, error) {
	if !validSiblingFormat(format) {
		return nil, ErrInvalid
	}
	if actor == "" {
		return nil, ErrMissingParty
	}
	cleaned, rootID, err := normalizeWorkflow(format, root, nodes)
	if err != nil {
		return nil, err
	}
	if !validMeterNumbers(meter) {
		return nil, ErrInvalid
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 64
	}
	if meter.MaxSteps > 128 {
		return nil, ErrInvalid
	}
	w := &Workflow{
		ID:        id,
		Kind:      KindWorkflow,
		Root:      rootID,
		Nodes:     cleaned,
		Status:    StatusOpen,
		Meter:     meter,
		CreatedAt: now.UTC(),
		Actor:     actor,
		Format:    format,
	}
	note, err := w.openNote()
	if err != nil {
		return nil, err
	}
	if err := w.append(actor, "open", note, now); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Workflow) openNote() (string, error) {
	if w.Format != FormatV2 {
		return "workflow opened", nil
	}
	return encodeSiblingEvent(siblingEvent{
		V:      FormatV2,
		Ledger: ledgerWorkflow,
		Action: "open",
		Actor:  string(w.Actor),
	})
}

// normalizeWorkflow copies the tree. Map keys must equal the trimmed
// node IDs. Duplicate normalized IDs are rejected. Child names are
// resolved in that normalized graph, not in the caller's key set.
func normalizeWorkflow(format int, root string, nodes map[string]Node) (map[string]Node, string, error) {
	if strings.TrimSpace(root) == "" || len(nodes) == 0 {
		return nil, "", ErrBadTree
	}
	cleaned := make(map[string]Node, len(nodes))
	for key, n := range nodes {
		id, err := normalizedNodeID(key, n.ID)
		if err != nil {
			return nil, "", err
		}
		if format == FormatV2 && invalidV2NodeID(id) {
			return nil, "", fmt.Errorf("%w: invalid node id %q", ErrBadTree, id)
		}
		if _, exists := cleaned[id]; exists {
			return nil, "", fmt.Errorf("%w: duplicate node %s", ErrBadTree, id)
		}
		if n.Kind != "gate" && n.Kind != "action" {
			return nil, "", fmt.Errorf("%w: node %s kind %q", ErrBadTree, id, n.Kind)
		}
		next := make([]string, len(n.Next))
		for i, ch := range n.Next {
			next[i] = strings.TrimSpace(ch)
			if next[i] == "" {
				return nil, "", fmt.Errorf("%w: %s → empty child", ErrBadTree, id)
			}
		}
		if n.Kind == "action" && len(next) != 0 {
			return nil, "", fmt.Errorf("%w: action %s has children", ErrBadTree, id)
		}
		if n.Kind == "gate" && len(next) == 0 {
			return nil, "", fmt.Errorf("%w: gate %s has no children", ErrBadTree, id)
		}
		copied := n
		copied.ID = id
		copied.Require = append([]string(nil), n.Require...)
		if len(next) == 0 {
			copied.Next = nil
		} else {
			copied.Next = next
		}
		cleaned[id] = copied
	}
	for id, n := range cleaned {
		for _, ch := range n.Next {
			if _, ok := cleaned[ch]; !ok {
				return nil, "", fmt.Errorf("%w: %s → missing %s", ErrBadTree, id, ch)
			}
		}
	}
	rootID := strings.TrimSpace(root)
	if _, ok := cleaned[rootID]; !ok {
		return nil, "", fmt.Errorf("%w: missing root %s", ErrBadTree, root)
	}
	return cleaned, rootID, nil
}

func normalizedNodeID(key, id string) (string, error) {
	nk := strings.TrimSpace(key)
	ni := strings.TrimSpace(id)
	if ni == "" {
		ni = nk
	}
	if nk == "" || ni == "" || nk != ni {
		return "", fmt.Errorf("%w: node key %q and id %q disagree", ErrBadTree, key, id)
	}
	return ni, nil
}

func invalidV2NodeID(id string) bool {
	return len(strings.Fields(id)) != 1 || strings.ContainsAny(id, "[]")
}

func validateWorkflowGraph(w *Workflow) error {
	if w == nil || w.Actor == "" || strings.TrimSpace(w.Root) == "" || len(w.Nodes) == 0 {
		return ErrBadTree
	}
	for key, n := range w.Nodes {
		if key != n.ID || strings.TrimSpace(key) != key || key == "" {
			return fmt.Errorf("%w: node key %q and id %q disagree", ErrBadTree, key, n.ID)
		}
		if w.Format == FormatV2 && invalidV2NodeID(key) {
			return fmt.Errorf("%w: invalid node id %q", ErrBadTree, key)
		}
		if n.Kind != "gate" && n.Kind != "action" {
			return fmt.Errorf("%w: node %s kind %q", ErrBadTree, key, n.Kind)
		}
		if n.Kind == "action" && len(n.Next) != 0 {
			return fmt.Errorf("%w: action %s has children", ErrBadTree, key)
		}
		if n.Kind == "gate" && len(n.Next) == 0 {
			return fmt.Errorf("%w: gate %s has no children", ErrBadTree, key)
		}
		for _, ch := range n.Next {
			if _, ok := w.Nodes[ch]; !ok {
				return fmt.Errorf("%w: %s → missing %s", ErrBadTree, key, ch)
			}
		}
	}
	if _, ok := w.Nodes[w.Root]; !ok {
		return fmt.Errorf("%w: missing root %s", ErrBadTree, w.Root)
	}
	return nil
}

// Walk is the pure deterministic walk. First matching child in Next
// order whose Require facts are all true (empty Require always matches).
// The result selects a branch of the supplied facts. It does not prove
// those facts are true of the host.
func (w *Workflow) Walk(facts map[string]bool) (path []string, action string, err error) {
	if w == nil || len(w.Nodes) == 0 {
		return nil, "", ErrBadTree
	}
	seen := map[string]bool{}
	cur := w.Root
	for {
		if seen[cur] {
			return nil, "", ErrWalkLoop
		}
		seen[cur] = true
		n, ok := w.Nodes[cur]
		if !ok {
			return nil, "", fmt.Errorf("%w: missing node %s", ErrBadTree, cur)
		}
		if !reqsMet(n.Require, facts) {
			return nil, "", ErrNoPath
		}
		path = append(path, cur)
		if n.Kind == "action" {
			return path, n.ID, nil
		}
		next := ""
		for _, ch := range n.Next {
			cn, ok := w.Nodes[ch]
			if !ok {
				return nil, "", fmt.Errorf("%w: missing node %s", ErrBadTree, ch)
			}
			if reqsMet(cn.Require, facts) {
				next = ch
				break
			}
		}
		if next == "" {
			return nil, "", ErrNoPath
		}
		cur = next
		if len(path) > len(w.Nodes)+1 {
			return nil, "", ErrWalkLoop
		}
	}
}

func reqsMet(req []string, facts map[string]bool) bool {
	for _, r := range req {
		if !facts[r] {
			return false
		}
	}
	return true
}

// Execute walks with facts and records the path. Terminal.
// FactsAssurance is FactsCommitted, never FactsVerified.
func (w *Workflow) Execute(actor Party, facts map[string]bool, now time.Time) error {
	if actor != w.Actor {
		return ErrWrongParty
	}
	ph, err := w.phase()
	if err != nil {
		return err
	}
	if ph == workflowExecuted {
		return ErrTakeback
	}
	if !phaseAllows(workflowPhaseTable, w.Format, "execute", w.Status) {
		return ErrBadState
	}
	if facts == nil {
		return ErrEmptyFact
	}
	path, action, err := w.Walk(facts)
	if err != nil {
		return err
	}
	return w.commit(func(n *Workflow) error {
		return n.recordExecution(actor, facts, path, action, FactsCommitted, "", now)
	})
}

// recordExecution appends an execute receipt.
// FactsCommitted re-walks the supplied facts.
// FactsCommitmentOnly records a commitment and a structurally legal path
// without the facts; that does not establish the branch selection.
func (w *Workflow) recordExecution(actor Party, facts map[string]bool, path []string, action, assurance, commitment string, now time.Time) error {
	if actor != w.Actor {
		return ErrWrongParty
	}
	ph, err := w.phase()
	if err != nil {
		return err
	}
	if ph == workflowExecuted {
		return ErrTakeback
	}
	if !phaseAllows(workflowPhaseTable, w.Format, "execute", w.Status) {
		return ErrBadState
	}
	if err := validateWorkflowPath(w, path, action); err != nil {
		return err
	}
	switch assurance {
	case FactsCommitted:
		if facts == nil {
			return ErrEmptyFact
		}
		got, act, err := w.Walk(facts)
		if err != nil {
			return err
		}
		if act != action || !sameStrings(got, path) {
			return ErrBadState
		}
		sum, err := commitFacts(facts)
		if err != nil {
			return err
		}
		commitment = sum
	case FactsCommitmentOnly:
		if facts != nil || !hexCommitment(commitment) {
			return ErrInvalid
		}
	default:
		return ErrFactsUnverified
	}
	note, err := w.executeNote(actor, facts, path, action, assurance, commitment)
	if err != nil {
		return err
	}
	if err := w.append(actor, "execute", note, now); err != nil {
		return err
	}
	t := now.UTC()
	w.ClosedAt = &t
	w.Path = append([]string(nil), path...)
	w.Action = action
	w.Status = StatusExecuted
	if w.Format == FormatV2 {
		w.FactsAssurance = assurance
	}
	return nil
}

func (w *Workflow) executeNote(actor Party, facts map[string]bool, path []string, action, assurance, commitment string) (string, error) {
	if w.Format != FormatV2 {
		return fmt.Sprintf("path=%v action=%s", path, action), nil
	}
	ev := siblingEvent{
		V:               FormatV2,
		Ledger:          ledgerWorkflow,
		Action:          "execute",
		Actor:           string(actor),
		FactsAssurance:  assurance,
		FactsCommitment: commitment,
		Path:            append([]string(nil), path...),
		Result:          action,
	}
	if assurance == FactsCommitted {
		ev.FactsPresent = true
		ev.Facts = facts
	}
	return encodeSiblingEvent(ev)
}

func validateWorkflowPath(w *Workflow, path []string, action string) error {
	if len(path) == 0 || path[0] != w.Root {
		return ErrBadTree
	}
	seen := map[string]bool{}
	for i, id := range path {
		if seen[id] {
			return ErrWalkLoop
		}
		seen[id] = true
		n, ok := w.Nodes[id]
		if !ok {
			return fmt.Errorf("%w: missing node %s", ErrBadTree, id)
		}
		last := i == len(path)-1
		if last {
			if n.Kind != "action" || id != action {
				return ErrNoPath
			}
			continue
		}
		if n.Kind != "gate" {
			return ErrBadTree
		}
		next := path[i+1]
		found := false
		for _, ch := range n.Next {
			if ch == next {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: %s → missing %s", ErrBadTree, id, next)
		}
	}
	return nil
}

func (w *Workflow) phase() (workflowPhase, error) {
	ph, ok := workflowPhaseOf(w.Status)
	if !ok {
		return "", ErrBadState
	}
	return ph, nil
}

func (w *Workflow) commit(fn func(*Workflow) error) error {
	next := w.clone()
	if err := fn(next); err != nil {
		return err
	}
	*w = *next
	return nil
}

func (w *Workflow) clone() *Workflow {
	next := *w
	next.Receipts = append([]Receipt(nil), w.Receipts...)
	next.Path = append([]string(nil), w.Path...)
	return &next
}

func (w *Workflow) ledger() receiptLedger {
	return receiptLedger{
		format:      w.Format,
		maxSteps:    w.Meter.MaxSteps,
		budget:      w.Meter.BudgetUSD,
		cost:        w.Meter.CostUSD,
		checkBudget: false, // step-only, including format v2
		steps:       &w.steps,
		receipts:    &w.Receipts,
		terms:       w.termsDigest,
		hashKind:    hashWorkflowReceipt,
		keys:        w.actorKeys,
	}
}

func (w *Workflow) append(actor Party, action, note string, now time.Time) error {
	return w.ledger().append(actor, action, note, now)
}

// VerifyReceipts checks the hash chain and replays the workflow snapshot.
// Format v2 replays the path from committed facts (or checks a facts
// commitment). Format 0 matches the execute note against legal simple
// walks in the committed graph. An empty receipt list cannot establish an
// executed workflow.
func (w *Workflow) VerifyReceipts() error {
	_, err := w.classify()
	return err
}

// ReceiptAssurance reports state-replay, path-replay (format 0 execute
// with a unique graph walk, without committed input facts),
// commitment-only, or legacy-chain-only (format 0 whitespace-colliding
// node IDs). State-replay of a walk still does not verify host facts.
func (w *Workflow) ReceiptAssurance() (string, error) {
	return w.classify()
}

func (w *Workflow) classify() (string, error) {
	if w == nil || len(w.Receipts) == 0 {
		return "", ErrInvalid
	}
	if !validSiblingFormat(w.Format) || w.Kind != KindWorkflow || !validMeterNumbers(w.Meter) {
		return "", ErrInvalid
	}
	if err := validateWorkflowGraph(w); err != nil {
		return "", err
	}
	if err := verifySiblingChain(w.Receipts, w.termsDigest(), hashWorkflowReceipt); err != nil {
		return "", err
	}
	if err := validateWorkflowGenesis(w); err != nil {
		return "", err
	}
	return replayWorkflow(w)
}

func validateWorkflowGenesis(w *Workflow) error {
	r := w.Receipts[0]
	if r.Action != "open" || r.Seq != 1 || r.Actor != w.Actor || !r.At.Equal(w.CreatedAt) {
		return fmt.Errorf("nexum: workflow genesis: %w", ErrBadState)
	}
	return nil
}

type workflowView struct {
	status           Status
	path             []string
	action           string
	assurance        string
	closed           *time.Time
	receiptAssurance string
}

type workflowWalk struct {
	path   []string
	action string
}

func replayWorkflow(w *Workflow) (string, error) {
	view := workflowView{status: StatusOpen}
	for i, r := range w.Receipts {
		if err := applyWorkflowReceipt(w, &view, r, i == 0); err != nil {
			return "", fmt.Errorf("nexum: receipt %d: %w", r.Seq, err)
		}
	}
	if view.status != w.Status || view.action != w.Action || view.assurance != w.FactsAssurance || !sameStrings(view.path, w.Path) || !sameReceiptTime(view.closed, w.ClosedAt) {
		return "", snapshotMismatch(ErrInvalid)
	}
	if _, ok := workflowPhaseOf(w.Status); !ok {
		return "", snapshotMismatch(ErrBadState)
	}
	if view.receiptAssurance != "" {
		return view.receiptAssurance, nil
	}
	return AssuranceStateReplay, nil
}

func applyWorkflowReceipt(w *Workflow, view *workflowView, r Receipt, genesis bool) error {
	if r.Actor != w.Actor {
		return ErrWrongParty
	}
	var ev siblingEvent
	if w.Format == FormatV2 {
		parsed, err := parseSiblingEvent(r.Note)
		if err != nil {
			return err
		}
		if err := eventMatchesReceipt(parsed, ledgerWorkflow, r); err != nil {
			return err
		}
		ev = parsed
	}
	if genesis {
		if r.Action != "open" {
			return ErrBadState
		}
		if w.Format == FormatV2 && (len(ev.Path) != 0 || ev.Result != "" || ev.FactsPresent || ev.FactsCommitment != "") {
			return ErrInvalid
		}
		return nil
	}
	if view.status == StatusExecuted {
		return ErrBadState
	}
	if !phaseAllows(workflowPhaseTable, w.Format, r.Action, view.status) {
		return ErrBadState
	}
	if r.Action != "execute" {
		return ErrInvalid
	}
	if w.Format != FormatV2 {
		return applyLegacyWorkflowExecute(w, view, r)
	}
	if ev.FactsAssurance == FactsVerified {
		return ErrFactsUnverified
	}
	path := append([]string(nil), ev.Path...)
	if err := validateWorkflowPath(w, path, ev.Result); err != nil {
		return err
	}
	switch ev.FactsAssurance {
	case FactsCommitted:
		if !ev.FactsPresent {
			return ErrInvalid
		}
		facts := ev.Facts
		if facts == nil {
			facts = map[string]bool{}
		}
		sum, err := commitFacts(facts)
		if err != nil {
			return err
		}
		if sum != ev.FactsCommitment {
			return ErrInvalid
		}
		got, action, err := w.Walk(facts)
		if err != nil {
			return err
		}
		if action != ev.Result || !sameStrings(got, path) {
			return ErrNoPath
		}
		view.receiptAssurance = AssuranceStateReplay
	case FactsCommitmentOnly:
		// The digest is recorded. Without the facts, or a proof this
		// kernel can check, the path is only a structural claim.
		if ev.FactsPresent || len(ev.Facts) != 0 || !hexCommitment(ev.FactsCommitment) {
			return ErrInvalid
		}
		view.receiptAssurance = AssuranceCommitmentOnly
	default:
		return ErrInvalid
	}
	t := r.At.UTC()
	view.closed = &t
	view.path = path
	view.action = ev.Result
	view.assurance = ev.FactsAssurance
	view.status = StatusExecuted
	return nil
}

func applyLegacyWorkflowExecute(w *Workflow, view *workflowView, r Receipt) error {
	matches, capped := matchLegacyWorkflowExecute(w, r.Note)
	if !capped && len(matches) == 0 {
		return ErrInvalid
	}
	t := r.At.UTC()
	if !capped && len(matches) == 1 {
		view.closed = &t
		view.path = matches[0].path
		view.action = matches[0].action
		view.assurance = ""
		view.status = StatusExecuted
		view.receiptAssurance = AssurancePathReplay
		return nil
	}
	if err := validateWorkflowPath(w, w.Path, w.Action); err != nil || fmt.Sprintf("path=%v action=%s", w.Path, w.Action) != r.Note {
		if len(matches) == 0 {
			return ErrInvalid
		}
		return snapshotMismatch(ErrInvalid)
	}
	view.closed = &t
	view.path = append([]string(nil), w.Path...)
	view.action = w.Action
	view.assurance = ""
	view.status = StatusExecuted
	view.receiptAssurance = AssuranceLegacyChain
	return nil
}

func matchLegacyWorkflowExecute(w *Workflow, note string) ([]workflowWalk, bool) {
	if !strings.HasPrefix(note, "path=[") {
		return nil, false
	}
	cleanTokens := true
	for id := range w.Nodes {
		if invalidV2NodeID(id) {
			cleanTokens = false
			break
		}
	}
	if cleanTokens {
		rest := strings.TrimPrefix(note, "path=[")
		const sep = "] action="
		idx := strings.Index(rest, sep)
		if idx < 0 {
			return nil, false
		}
		candPath := strings.Fields(rest[:idx])
		act := rest[idx+len(sep):]
		if fmt.Sprintf("path=%v action=%s", candPath, act) != note {
			return nil, false
		}
		if err := validateWorkflowPath(w, candPath, act); err != nil {
			return nil, false
		}
		return []workflowWalk{{path: candPath, action: act}}, false
	}

	const maxLegacyWalkVisits = 4096
	visits := 0
	capped := false
	visited := make(map[string]bool, len(w.Nodes))
	path := make([]string, 0, len(w.Nodes))
	var matches []workflowWalk
	var dfs func(cur, prefix string)
	dfs = func(cur, prefix string) {
		if capped || len(matches) >= 2 {
			return
		}
		visits++
		if visits > maxLegacyWalkVisits {
			capped = true
			return
		}
		n, ok := w.Nodes[cur]
		if !ok {
			return
		}
		if n.Kind == "action" {
			if prefix+"] action="+cur == note {
				matches = append(matches, workflowWalk{
					path:   append([]string(nil), path...),
					action: cur,
				})
			}
			return
		}
		if len(path) >= len(w.Nodes) || !strings.HasPrefix(note, prefix+" ") {
			return
		}
		seenChild := make(map[string]bool, len(n.Next))
		for _, ch := range n.Next {
			if visited[ch] || seenChild[ch] {
				continue
			}
			seenChild[ch] = true
			visited[ch] = true
			path = append(path, ch)
			dfs(ch, prefix+" "+ch)
			path = path[:len(path)-1]
			delete(visited, ch)
			if capped || len(matches) >= 2 {
				return
			}
		}
	}
	visited[w.Root] = true
	path = append(path, w.Root)
	dfs(w.Root, "path=["+w.Root)
	return matches, capped
}

// termsDigest commits the workflow's immutable binding terms into every
// receipt hash. Excludes status and path: those advance as the workflow
// runs, and each step is itself a chained receipt. Format v2 binds the
// step-only meter policy. Format 0 does not, and does not gain a budget rule.
func (w *Workflow) termsDigest() string {
	if w.Format == FormatV2 {
		sum := sha256.Sum256(wireDigestV2("workflow-terms", struct {
			ID          string          `json:"id"`
			Kind        string          `json:"kind"`
			Root        string          `json:"root"`
			Nodes       map[string]Node `json:"nodes"`
			Actor       Party           `json:"actor"`
			CreatedAt   time.Time       `json:"created_at"`
			Format      int             `json:"format"`
			MeterPolicy string          `json:"meter_policy"`
		}{w.ID, w.Kind, w.Root, w.Nodes, w.Actor, w.CreatedAt, w.Format, meterPolicySteps}))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(wireDigest("workflow-terms", struct {
		ID        string          `json:"id"`
		Kind      string          `json:"kind"`
		Root      string          `json:"root"`
		Nodes     map[string]Node `json:"nodes"`
		Actor     Party           `json:"actor"`
		CreatedAt time.Time       `json:"created_at"`
	}{w.ID, w.Kind, w.Root, w.Nodes, w.Actor, w.CreatedAt}))
	return hex.EncodeToString(sum[:])
}
