package nexum

// Unit is the settlement token a Nexum may require when value has
// to move. Empty means untyped integer units (paper escrow).
// The product is still the obligation, not a ticker launch.
type Unit struct {
	Symbol string `json:"symbol,omitempty"`
}

// TokenNEX is the unit used when a contract needs transferable value
// across the GPU mesh.
const TokenNEX = "NEX"

// WithUnit denominations the locked amount. Call before Lock.
func (a *Agreement) WithUnit(symbol string) *Agreement {
	if a == nil {
		return a
	}
	if symbol != "" {
		a.Unit = Unit{Symbol: symbol}
	}
	return a
}

// RequiresToken reports whether this contract needs a transferable unit.
func (a *Agreement) RequiresToken() bool {
	return a != nil && a.Unit.Symbol != ""
}
