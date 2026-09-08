package message

// The public baseline excludes experimental rekey implementation. These
// reserved types keep the shared envelope codec buildable without that code.
// Unsupported suites are rejected when verifying offers, before any decision.
const RekeySuite = "unsupported"
const rekeyCiphertextSize = -1

type RekeyPublic struct{}

func (RekeyPublic) Validate() error   { return ErrInvalid }
func supportedKeySuite(s string) bool { return s == "" || s == HPKESuite }
func wrapRekey(Identity, Offer, Decision, []byte) (Release, error) {
	return Release{}, ErrInvalid
}
