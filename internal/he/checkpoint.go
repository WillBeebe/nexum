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
	if !isCanonicalPositive(s.N) || !isCanonicalPositive(s.Lambda) || !isCanonicalPositive(s.Mu) {
		return nil, bad
	}
	if len(s.Lambda) > len(s.N) || len(s.Mu) > len(s.N) {
		return nil, bad
	}
	pub, err := FromPublic(s.N)
	if err != nil {
		return nil, bad
	}
	n := pub.n
	one := big.NewInt(1)
	lambda := new(big.Int).SetBytes(s.Lambda)
	mu := new(big.Int).SetBytes(s.Mu)
	if lambda.Cmp(one) <= 0 || lambda.Cmp(n) >= 0 || mu.Sign() <= 0 || mu.Cmp(n) >= 0 {
		return nil, bad
	}
	if new(big.Int).GCD(nil, nil, n, lambda).Cmp(one) != 0 {
		return nil, bad
	}
	// Verify Paillier decryption identity: L((1+N)^lambda mod N^2) * mu == 1 (mod N).
	x := new(big.Int).Exp(pub.g, lambda, pub.n2)
	L, rem := new(big.Int).QuoRem(new(big.Int).Sub(x, one), n, new(big.Int))
	if rem.Sign() != 0 {
		return nil, bad
	}
	check := new(big.Int).Mul(L, mu)
	check.Mod(check, n)
	if check.Cmp(one) != 0 {
		return nil, bad
	}
	// Verify Carmichael exponent property on coprime bases (N has no prime factors <= 65537).
	for _, base := range []int64{2, 3, 5} {
		if new(big.Int).Exp(big.NewInt(base), lambda, n).Cmp(one) != 0 {
			return nil, bad
		}
	}
	p := &Paillier{n: n, n2: pub.n2, g: pub.g, lambda: lambda, mu: mu}
	probe := big.NewInt(12345)
	ct, err := p.Encrypt(probe)
	if err != nil {
		return nil, bad
	}
	got, err := p.Decrypt(ct)
	if err != nil || got.Cmp(probe) != 0 {
		return nil, bad
	}
	return p, nil
}
