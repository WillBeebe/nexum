package message

import (
	"fmt"
	"time"
)

type SendOptions struct {
	KeySuite       string `json:"key_suite,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
	ReplyTo        string `json:"reply_to,omitempty"`
	// ReplyChain is the envelope hash of the message this one answers, when
	// the sender already holds it. It gives the conversation ordering
	// evidence the relay cannot forge: a gap or reorder in a drained
	// conversation is detectable against the committed chain. Optional and
	// backwards compatible.
	ReplyChain string     `json:"reply_chain,omitempty"`
	Trade      *TradeLink `json:"trade,omitempty"`
}

// ReplyChainHash is the expected ReplyChain value for replying to parent:
// its signed envelope hash.
func ReplyChainHash(parent Record) string { return parent.Offer.Hash() }

// TradeLink reveals the operation and ordering, but commits to salted,
// encrypted terms. A message is the trade operation, not a notification of one.
// Parent and ReplyTo thread an existing attempt. They are not a versioned
// authorization to restart a blocked head.
type TradeLink struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Parent     string `json:"parent,omitempty"`
	Commitment string `json:"commitment"`
}

func (t TradeLink) Validate() error {
	if !validID(t.ID) || !validID(t.Commitment) {
		return ErrInvalid
	}
	switch t.Action {
	case "request":
		if t.Parent != "" {
			return ErrInvalid
		}
	case "offer", "counteroffer", "accept", "reject", "fulfill", "settle":
		if !validID(t.Parent) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type Obligation struct {
	Description string    `json:"description"`
	Units       int64     `json:"units,omitempty"`
	Unit        string    `json:"unit,omitempty"`
	Budget      int64     `json:"budget,omitempty"`
	Deadline    time.Time `json:"deadline,omitempty"`
}
type TradePayload struct {
	Version       int          `json:"version"`
	TradeID       string       `json:"trade_id"`
	Action        string       `json:"action"`
	Parent        string       `json:"parent,omitempty"`
	Salt          []byte       `json:"salt"`
	Text          string       `json:"text"`
	Obligations   []Obligation `json:"obligations,omitempty"`
	SettlementRef string       `json:"settlement_ref,omitempty"`
}

func (p TradePayload) Commitment() string { return digest("trade-terms", p) }
func (p TradePayload) Validate(link TradeLink) error {
	if p.Version != 1 || len(p.Salt) != 32 || p.TradeID != link.ID || p.Action != link.Action || p.Parent != link.Parent || p.Commitment() != link.Commitment {
		return ErrInvalid
	}
	if len(p.Obligations) > 64 {
		return ErrInvalid
	}
	for _, obligation := range p.Obligations {
		if obligation.Description == "" || obligation.Units < 0 || obligation.Budget < 0 {
			return ErrInvalid
		}
	}
	if p.Action == "settle" && p.SettlementRef == "" {
		return fmt.Errorf("message: settlement evidence reference required")
	}
	return link.Validate()
}

// ValidateTradeSuccessor enforces turn ownership and the only legal sequence.
// The prior message must have been verified, agreed, and released before
// another operation can bind it; the receiving agent validates the decrypted
// payload before responding.
func ValidateTradeSuccessor(parent Record, child Offer) error {
	if err := parent.Verify(); err != nil {
		return err
	}
	if err := child.Verify(); err != nil {
		return err
	}
	p, c := parent.Offer.Terms.Trade, child.Terms.Trade
	if p == nil || c == nil || c.ID != p.ID || c.Parent != parent.Offer.Hash() ||
		child.Terms.ReplyTo != parent.Offer.Terms.ID ||
		parent.Offer.Terms.ConversationID == "" || child.Terms.ConversationID != parent.Offer.Terms.ConversationID ||
		(child.Terms.ReplyChain != "" && child.Terms.ReplyChain != ReplyChainHash(parent)) ||
		child.Terms.Sender.ID() != parent.Offer.Terms.Recipient.ID() ||
		child.Terms.Recipient.ID() != parent.Offer.Terms.Sender.ID() ||
		parent.Decision == nil || parent.Decision.Action != "agree" || parent.Release == nil {
		return ErrState
	}
	allowed := map[string][]string{"request": {"offer", "reject"}, "offer": {"counteroffer", "accept", "reject"}, "counteroffer": {"counteroffer", "accept", "reject"}, "accept": {"fulfill"}, "fulfill": {"settle"}}
	for _, action := range allowed[p.Action] {
		if action == c.Action {
			return nil
		}
	}
	return ErrState
}

// TradeAudit is local recovery metadata. It is not a signed envelope field and
// it does not admit a competing trade successor.
type TradeAudit struct {
	TradeID     string `json:"trade_id"`
	AttemptID   string `json:"attempt_id"`
	HeadHash    string `json:"head_hash"`
	Disposition string `json:"disposition"`
	PriorTrade  string `json:"prior_trade,omitempty"`
}

// NewTradeAudit validates and builds local recovery metadata linking a fresh
// trade ID beside a blocked head without altering relay reservations.
func NewTradeAudit(nextTradeID string, prior TradeAudit) (TradeAudit, error) {
	if !validID(nextTradeID) || !validID(prior.TradeID) || !validID(prior.AttemptID) || prior.HeadHash == "" || prior.Disposition == "" {
		return TradeAudit{}, ErrInvalid
	}
	return TradeAudit{
		TradeID:     nextTradeID,
		AttemptID:   prior.AttemptID,
		HeadHash:    prior.HeadHash,
		Disposition: prior.Disposition,
		PriorTrade:  prior.TradeID,
	}, nil
}

// SealWithReleaseBy seals an offer whose signed terms also commit to a sender
// key-release deadline after recipient acceptance.
func SealWithReleaseBy(i Identity, recipient Public, text []byte, invitation string, now, expiry, releaseBy time.Time, options SendOptions) (Offer, []byte, error) {
	o, key, err := SealWithOptions(i, recipient, text, invitation, now, expiry, options)
	if err != nil {
		return Offer{}, nil, err
	}
	rb := releaseBy.UTC()
	o.Terms.ReleaseBy = &rb
	o.Ciphertext, err = encrypt(key, text, wire("text", o.Terms))
	if err != nil {
		clear(key)
		return Offer{}, nil, err
	}
	o.Signature = sign(i, "offer", o.unsigned())
	if err := o.Verify(); err != nil {
		clear(key)
		return Offer{}, nil, err
	}
	return o, key, nil
}

// VerifyConversationOrder checks that replies in one conversation form the
// chain their senders committed to: all records must share one non-empty
// ConversationID without duplicates, every ReplyTo must resolve within the
// conversation without cycles, and every ReplyChain must point at the exact
// parent record identified by ReplyTo (no gaps, splicing, or mismatches).
// Records are in drain order; out-of-order delivery is fine but a missing link
// or cross-conversation splice is not.
func VerifyConversationOrder(records []Record) error {
	if len(records) == 0 {
		return nil
	}
	byHash := make(map[string]Record, len(records))
	byID := make(map[string]Record, len(records))
	convID := records[0].Offer.Terms.ConversationID
	if convID == "" {
		return fmt.Errorf("message: conversation id required: %w", ErrInvalid)
	}
	for i := range records {
		if err := records[i].Verify(); err != nil {
			return err
		}
		t := records[i].Offer.Terms
		if t.ConversationID != convID {
			return fmt.Errorf("message: conversation id mismatch: %w", ErrInvalid)
		}
		h := records[i].Offer.Hash()
		if _, dup := byHash[h]; dup {
			return fmt.Errorf("message: duplicate record %s: %w", h, ErrInvalid)
		}
		if _, dup := byID[t.ID]; dup {
			return fmt.Errorf("message: duplicate message id %s: %w", t.ID, ErrInvalid)
		}
		byHash[h] = records[i]
		byID[t.ID] = records[i]
	}
	for i := range records {
		t := records[i].Offer.Terms
		h := records[i].Offer.Hash()
		if t.ReplyTo != "" {
			if t.ReplyTo == t.ID {
				return fmt.Errorf("message: self-reply %s: %w", t.ID, ErrInvalid)
			}
			parent, ok := byID[t.ReplyTo]
			if !ok {
				return fmt.Errorf("message: conversation gap: reply target %s missing", t.ReplyTo)
			}
			if parent.Offer.Terms.ConversationID != convID {
				return fmt.Errorf("message: cross-conversation reply target %s: %w", t.ReplyTo, ErrInvalid)
			}
			if t.ReplyChain != "" && t.ReplyChain != ReplyChainHash(parent) {
				return fmt.Errorf("message: reply chain %s does not match reply target %s: %w", t.ReplyChain, t.ReplyTo, ErrInvalid)
			}
		}
		if t.ReplyChain != "" {
			if t.ReplyChain == h {
				return fmt.Errorf("message: self-reply chain %s: %w", h, ErrInvalid)
			}
			parent, ok := byHash[t.ReplyChain]
			if !ok {
				return fmt.Errorf("message: conversation gap: reply chain %s missing", t.ReplyChain)
			}
			if parent.Offer.Terms.ConversationID != convID || t.ReplyTo != parent.Offer.Terms.ID {
				return fmt.Errorf("message: reply chain %s does not match reply target %s: %w", t.ReplyChain, t.ReplyTo, ErrInvalid)
			}
		}
	}
	// Reject ReplyTo cycles (0 = unvisited, 1 = visiting, 2 = visited).
	state := make(map[string]uint8, len(records))
	for id := range byID {
		if state[id] != 0 {
			continue
		}
		cur := id
		for cur != "" && state[cur] == 0 {
			state[cur] = 1
			next := byID[cur].Offer.Terms.ReplyTo
			if next != "" && state[next] == 1 {
				return fmt.Errorf("message: reply cycle involving %s: %w", next, ErrInvalid)
			}
			cur = next
		}
		cur = id
		for cur != "" && state[cur] == 1 {
			state[cur] = 2
			cur = byID[cur].Offer.Terms.ReplyTo
		}
	}
	return nil
}
