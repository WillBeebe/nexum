package nexum

import (
	"errors"
	"fmt"
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
type Workflow struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	Root      string          `json:"root"`
	Nodes     map[string]Node `json:"nodes"`
	Status    Status          `json:"status"`
	Path      []string        `json:"path,omitempty"`
	Action    string          `json:"action,omitempty"`
	Meter     Meter           `json:"meter"`
	CreatedAt time.Time       `json:"created_at"`
	ClosedAt  *time.Time      `json:"closed_at,omitempty"`
	Receipts  []Receipt       `json:"receipts"`
	Actor     Party           `json:"actor"`
	steps     int
}

var (
	ErrBadTree   = errors.New("nexum: workflow tree invalid")
	ErrNoPath    = errors.New("nexum: no path given facts")
	ErrWalkLoop  = errors.New("nexum: workflow loop")
	ErrEmptyFact = errors.New("nexum: facts required to walk")
)

// OpenWorkflow records the tree. Walk happens at Execute.
func OpenWorkflow(id string, actor Party, root string, nodes map[string]Node, meter Meter, now time.Time) (*Workflow, error) {
	if actor == "" {
		return nil, ErrMissingParty
	}
	if root == "" || len(nodes) == 0 {
		return nil, ErrBadTree
	}
	cleaned := map[string]Node{}
	for k, n := range nodes {
		if n.ID == "" {
			n.ID = k
		}
		if n.Kind != "gate" && n.Kind != "action" {
			return nil, fmt.Errorf("%w: node %s kind %q", ErrBadTree, n.ID, n.Kind)
		}
		if n.Kind == "action" && len(n.Next) != 0 {
			return nil, fmt.Errorf("%w: action %s has children", ErrBadTree, n.ID)
		}
		if n.Kind == "gate" && len(n.Next) == 0 {
			return nil, fmt.Errorf("%w: gate %s has no children", ErrBadTree, n.ID)
		}
		for _, ch := range n.Next {
			if _, ok := nodes[ch]; !ok {
				return nil, fmt.Errorf("%w: %s → missing %s", ErrBadTree, n.ID, ch)
			}
		}
		cleaned[n.ID] = n
	}
	if _, ok := cleaned[root]; !ok {
		return nil, fmt.Errorf("%w: missing root %s", ErrBadTree, root)
	}
	if meter.MaxSteps <= 0 {
		meter.MaxSteps = 64
	}
	w := &Workflow{
		ID:        id,
		Kind:      KindWorkflow,
		Root:      root,
		Nodes:     cleaned,
		Status:    StatusOpen,
		Meter:     meter,
		CreatedAt: now.UTC(),
		Actor:     actor,
	}
	if err := w.append(actor, "open", "workflow opened", now); err != nil {
		return nil, err
	}
	return w, nil
}

// Walk is the pure deterministic walk. First matching child in Next
// order whose Require facts are all true (empty Require always matches).
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
			cn := w.Nodes[ch]
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
func (w *Workflow) Execute(actor Party, facts map[string]bool, now time.Time) error {
	if actor != w.Actor {
		return ErrWrongParty
	}
	if w.Status != StatusOpen {
		return ErrTakeback
	}
	if facts == nil {
		return ErrEmptyFact
	}
	path, action, err := w.Walk(facts)
	if err != nil {
		return err
	}
	note := fmt.Sprintf("path=%v action=%s", path, action)
	if err := w.append(actor, "execute", note, now); err != nil {
		return err
	}
	t := now.UTC()
	w.ClosedAt = &t
	w.Path = path
	w.Action = action
	w.Status = StatusExecuted
	return nil
}

func (w *Workflow) append(actor Party, action, note string, now time.Time) error {
	w.steps++
	if w.steps > w.Meter.MaxSteps {
		return ErrDoS
	}
	prev := ""
	if n := len(w.Receipts); n > 0 {
		prev = w.Receipts[n-1].Hash
	}
	r := Receipt{
		Seq:      len(w.Receipts) + 1,
		At:       now.UTC(),
		Action:   action,
		Actor:    actor,
		Note:     note,
		PrevHash: prev,
	}
	r.Hash = hashReceipt(w.ID, r)
	w.Receipts = append(w.Receipts, r)
	return nil
}

// VerifyReceipts checks the hash chain.
func (w *Workflow) VerifyReceipts() error {
	var prev string
	for i, r := range w.Receipts {
		if r.Seq != i+1 {
			return fmt.Errorf("nexum: receipt seq %d want %d", r.Seq, i+1)
		}
		if r.PrevHash != prev {
			return fmt.Errorf("nexum: receipt %d broken prev", r.Seq)
		}
		if r.Hash != hashReceipt(w.ID, r) {
			return fmt.Errorf("nexum: receipt %d rewritten", r.Seq)
		}
		prev = r.Hash
	}
	return nil
}
