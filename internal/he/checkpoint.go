package he

import (
	"errors"
	"math/big"
)

// PrivateState contains secret Paillier key material. It is only for encrypted
// local checkpoints, never public receipts, logs or transport envelopes.
type PrivateState struct {
	N, Lambda, Mu []byte
}

func (p *Paillier) PrivateState() PrivateState {
	return PrivateState{p.n.Bytes(), p.lambda.Bytes(), p.mu.Bytes()}
}

func RestorePrivate(s PrivateState) (*Paillier, error) {
	bad := errors.New("he: invalid private checkpoint")
	if len(s.N) < 128 || len(s.N) > 1024 || len(s.Lambda) > len(s.N) || len(s.Mu) > len(s.N) {
		return nil, bad
	}
	n := new(big.Int).SetBytes(s.N)
	lambda := new(big.Int).SetBytes(s.Lambda)
	mu := new(big.Int).SetBytes(s.Mu)
	if n.Bit(0) == 0 || lambda.Sign() <= 0 || lambda.Cmp(n) >= 0 || mu.Sign() <= 0 || mu.Cmp(n) >= 0 {
		return nil, bad
	}
	inv := new(big.Int).ModInverse(lambda, n)
	if inv == nil || inv.Cmp(mu) != 0 {
		return nil, bad
	}
	return &Paillier{n: n, n2: new(big.Int).Mul(n, n), g: new(big.Int).Add(n, big.NewInt(1)), lambda: lambda, mu: mu}, nil
}
