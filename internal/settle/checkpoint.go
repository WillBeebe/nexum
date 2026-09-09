package settle

import (
	"errors"
	"math/big"

	"github.com/WillBeebe/nexum/internal/he"
)

// PrivateState contains secrets. Persist only inside an authenticated encrypted
// checkpoint; blinding factors are as sensitive as the local key.
type PrivateState struct {
	Key        he.PrivateState
	Randomness [][]byte
}

func (l *EncryptedLedger) PrivateState() PrivateState {
	s := PrivateState{Key: l.p.PrivateState(), Randomness: make([][]byte, len(l.rs))}
	for i, r := range l.rs {
		s.Randomness[i] = r.Bytes()
	}
	return s
}

func RestorePrivate(s PrivateState) (*EncryptedLedger, error) {
	p, err := he.RestorePrivate(s.Key)
	if err != nil {
		return nil, err
	}
	if len(s.Randomness) > 128 {
		return nil, errors.New("settle: too many checkpoint locks")
	}
	l := &EncryptedLedger{p: p}
	n := p.N()
	for _, b := range s.Randomness {
		if len(b) > len(s.Key.N) {
			return nil, errors.New("settle: invalid checkpoint randomness")
		}
		r := new(big.Int).SetBytes(b)
		if r.Sign() <= 0 || r.Cmp(n) >= 0 || new(big.Int).GCD(nil, nil, r, n).Cmp(big.NewInt(1)) != 0 {
			return nil, errors.New("settle: invalid checkpoint randomness")
		}
		l.rs = append(l.rs, r)
	}
	return l, nil
}
