package nexum

import (
	"time"
)

// Unit is the settlement token a Nexum may require when value has
// to move. Empty means untyped integer units (paper escrow).
// The product is still the obligation, not a ticker launch.
type Unit struct {
	Symbol string `json:"symbol,omitempty"`
}

// TokenNEX is the unit used when a contract needs transferable value
// across the GPU mesh.
const TokenNEX = "NEX"

// WithUnit denominates the amount before Lock, recording the unit as a
// chained receipt: a unit change is a material term, so it goes on the
// ledger like a deadline, not a silent struct write. An empty symbol
// clears the unit.
func (a *Agreement) WithUnit(symbol string) error {
	return a.WithUnitAt(symbol, a.CreatedAt)
}

// WithUnitAt is WithUnit with an explicit clock, matching the kernel's
// other transitions. The unit receipt precedes the struct write, and the
// terms digest reads the unit only after the receipt chain carries it.
func (a *Agreement) WithUnitAt(symbol string, now time.Time) error {
	if a == nil {
		return nil
	}
	if err := a.requireExecutableCustody(); err != nil {
		return err
	}
	if a.terminal() {
		return ErrTakeback
	}
	if a.Status != StatusOpen {
		return ErrBadState
	}
	if symbol == a.Unit.Symbol {
		return nil
	}
	// Append against the old terms and enforce the same metering checks as
	// every other transition before changing the denomination.
	if err := a.append(a.Buyer, "unit", symbol, now); err != nil {
		return err
	}
	a.Unit = Unit{Symbol: symbol}
	return nil
}

// RequiresToken reports whether this contract needs a transferable unit.
func (a *Agreement) RequiresToken() bool {
	return a != nil && a.Unit.Symbol != ""
}
