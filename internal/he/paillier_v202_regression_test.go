package he

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"
)

// buildPrimePowerModulus constructs N = 3^650 (1031 bits, 129 bytes, odd),
// which violates Paillier's requirement gcd(N, phi(N)) == 1 so g^3 = (1+N)^3
// is an N-th power mod N^2.
func buildPrimePowerModulus() (n, w *big.Int) {
	n = new(big.Int).Exp(big.NewInt(3), big.NewInt(650), nil)
	n2 := new(big.Int).Mul(n, n)
	y := new(big.Int).Exp(big.NewInt(4), n, n2)
	l := new(big.Int).Div(new(big.Int).Sub(y, big.NewInt(1)), n)
	u := new(big.Int).Div(l, big.NewInt(3))
	uInv := new(big.Int).ModInverse(u, n)
	w = new(big.Int).Exp(big.NewInt(4), uInv, n)
	return n, w
}

// buildLargePrimePowerModulus constructs N = p^65 with prime p = 65539 > 65537.
// N is 1041 bits, odd, composite, non-square, and has NO prime factor <= 65537,
// so it passes cheap modulus filters and directly exercises the GMR coprimality NIZK.
func buildLargePrimePowerModulus(t *testing.T) (p, n, w *big.Int) {
	t.Helper()
	p = big.NewInt(65539)
	if !p.ProbablyPrime(20) {
		t.Fatal("65539 must be prime")
	}
	n = new(big.Int).Exp(p, big.NewInt(65), nil)
	n2 := new(big.Int).Mul(n, n)
	// By LTE, (1+p)^N = (1+p)^(p^65) == 1 + p*u*N (mod N^2) with u == 1 (mod p),
	// so gcd(u, N) == 1 and w = (1+p)^(u^-1 mod N) mod N satisfies w^N == 1 + p*N == g^p (mod N^2).
	base := new(big.Int).Add(p, big.NewInt(1))
	y := new(big.Int).Exp(base, n, n2)
	l, lRem := new(big.Int).QuoRem(new(big.Int).Sub(y, big.NewInt(1)), n, new(big.Int))
	if lRem.Sign() != 0 {
		t.Fatal("expected (1+p)^N == 1 (mod N)")
	}
	u, uRem := new(big.Int).QuoRem(l, p, new(big.Int))
	if uRem.Sign() != 0 {
		t.Fatal("expected L((1+p)^N) divisible by p")
	}
	uInv := new(big.Int).ModInverse(u, n)
	if uInv == nil {
		t.Fatal("expected gcd(u, N) == 1")
	}
	w = new(big.Int).Exp(base, uInv, n)
	// Sanity-check the equivocation identity w^N == g^p (mod N^2).
	g := new(big.Int).Add(n, big.NewInt(1))
	if new(big.Int).Exp(w, n, n2).Cmp(new(big.Int).Exp(g, p, n2)) != 0 {
		t.Fatal("w^N != g^p (mod N^2)")
	}
	return p, n, w
}

// TestV202_FromPublicRejectsPrimePowerAndInvalidModuli verifies BUG-01:
// FromPublic rejects prime-power moduli with small prime factors (3^650, 3^651, 65537*q),
// leading-zero encodings, probable primes, exact squares, even moduli, and short moduli.
func TestV202_FromPublicRejectsPrimePowerAndInvalidModuli(t *testing.T) {
	n3Pow650, _ := buildPrimePowerModulus()
	if _, err := FromPublic(n3Pow650.Bytes()); err == nil {
		t.Fatal("FromPublic accepted prime-power modulus N=3^650")
	}

	// Non-square odd prime power with small prime factor.
	n3Pow651 := new(big.Int).Exp(big.NewInt(3), big.NewInt(651), nil)
	if _, err := FromPublic(n3Pow651.Bytes()); err == nil {
		t.Fatal("FromPublic accepted prime-power modulus N=3^651")
	}

	// Boundary small prime factor 65537 * 1024-bit prime.
	bigPrime, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromPublic(bigPrime.Bytes()); err == nil {
		t.Fatal("FromPublic accepted probable prime modulus")
	}
	with65537 := new(big.Int).Mul(big.NewInt(65537), bigPrime)
	if _, err := FromPublic(with65537.Bytes()); err == nil {
		t.Fatal("FromPublic accepted modulus divisible by 65537")
	}

	// Exact square p^2 of a 512-bit prime (no prime factor <= 65537, composite, odd, >= 1024 bits).
	p512, err := rand.Prime(rand.Reader, 513)
	if err != nil {
		t.Fatal(err)
	}
	squareMod := new(big.Int).Mul(p512, p512)
	if _, err := FromPublic(squareMod.Bytes()); err == nil {
		t.Fatal("FromPublic accepted exact square modulus p^2")
	}

	// Leading-zero non-canonical encoding of a valid modulus.
	valid, err := NewPaillier(1024)
	if err != nil {
		t.Fatal(err)
	}
	padded := append([]byte{0x00}, valid.N().Bytes()...)
	if _, err := FromPublic(padded); err == nil {
		t.Fatal("FromPublic accepted leading-zero non-canonical modulus")
	}
}

// TestV202_GMRCoprimalityNIZKRejectsPrimePowerAboveTrialBound verifies BUG-01:
// even for a composite prime-power modulus N = 65539^65 whose sole prime factor is
// strictly above the 65537 trial-division bound (and non-square), the Gennaro-Micciancio-Rabin
// coprimality NIZK in ProveEqual/VerifyEqual prevents equivocation.
func TestV202_GMRCoprimalityNIZKRejectsPrimePowerAboveTrialBound(t *testing.T) {
	p, n, w := buildLargePrimePowerModulus(t)
	pub, err := FromPublic(n.Bytes())
	if err != nil {
		t.Fatalf("expected N=65539^65 (all factors > 65537, composite, non-square) to pass FromPublic, got %v", err)
	}

	// Verify ProveEqual refuses both public-only key and non-coprime private key (gcd(N, lambda) = p != 1).
	ct := []byte{1}
	wInv := new(big.Int).ModInverse(w, n)
	r1 := new(big.Int).Mod(wInv, n)
	if _, err := pub.ProveEqual(ct, p, r1); err == nil {
		t.Fatal("ProveEqual succeeded on verification-only FromPublic key")
	}
	phi := new(big.Int).Mul(new(big.Int).Exp(p, big.NewInt(64), nil), new(big.Int).Sub(p, big.NewInt(1)))
	badPriv := &Paillier{n: n, n2: pub.n2, g: pub.g, lambda: phi, mu: big.NewInt(1)}
	if _, err := badPriv.ProveEqual(ct, p, r1); err == nil {
		t.Fatal("ProveEqual succeeded when gcd(N, lambda) != 1")
	}

	// Verify mathematically that the deterministic GMR challenges for N=65539^65 have NO N-th root mod N
	// (an element y in Z_{p^65}^* is a p-th power only if y^(p-1) == 1 mod p^2).
	ys, err := coprimeChallenges(n)
	if err != nil {
		t.Fatal(err)
	}
	p2 := new(big.Int).Mul(p, p)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	unsolvable := 0
	for _, y := range ys {
		if new(big.Int).Exp(y, pMinus1, p2).Cmp(big.NewInt(1)) != 0 {
			unsolvable++
		}
	}
	if unsolvable == 0 {
		t.Fatal("expected at least one GMR challenge to have no N-th root mod 65539^65")
	}

	// Forge a valid Schnorr (A, Z) tuple for ct=[]byte{1} claiming BOTH p and 1000*p,
	// and verify VerifyEqual rejects missing, short, and forged R.
	for _, mult := range []int64{1, 1000} {
		claimed := new(big.Int).Mul(p, big.NewInt(mult))
		r := new(big.Int).Exp(wInv, big.NewInt(mult), n)
		s := big.NewInt(7)
		a := new(big.Int).Exp(s, n, pub.n2)
		e := zkChallenge(ct, claimed.Bytes(), a.Bytes(), n)
		z := new(big.Int).Exp(r, e, n)
		z.Mul(z, s)
		z.Mod(z, n)

		// Confirm the forged Schnorr equation itself closes without GMR (proving GMR alone stops it).
		lhs := new(big.Int).Exp(z, n, pub.n2)
		gm := new(big.Int).Exp(pub.g, claimed, pub.n2)
		gminv := new(big.Int).ModInverse(gm, pub.n2)
		rhs := new(big.Int).Exp(gminv, e, pub.n2)
		rhs.Mul(rhs, a)
		rhs.Mod(rhs, pub.n2)
		if lhs.Cmp(rhs) != 0 {
			t.Fatalf("forged Schnorr equation did not close for mult=%d", mult)
		}

		badRs := [][][]byte{
			nil,
			make([][]byte, coprimeChallengeCount-1),
			func() [][]byte {
				rs := make([][]byte, coprimeChallengeCount)
				for i, y := range ys {
					rs[i] = y.Bytes()
				}
				return rs
			}(),
			func() [][]byte {
				rs := make([][]byte, coprimeChallengeCount)
				for i := range rs {
					rs[i] = []byte{2}
				}
				return rs
			}(),
		}
		for idx, fakeR := range badRs {
			raw, err := json.Marshal(zkProof{A: a.Bytes(), Z: z.Bytes(), R: fakeR})
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := pub.VerifyEqual(ct, claimed, raw); err != nil || ok {
				t.Fatalf("VerifyEqual accepted forged GMR proof case %d for mult=%d on N=65539^65", idx, mult)
			}
		}
	}

	// On a real 2048-bit key, missing/tampered/non-canonical R must also be rejected.
	realKey, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	m := big.NewInt(42)
	r := big.NewInt(1337)
	realCT, err := realKey.EncryptWithR(m, r)
	if err != nil {
		t.Fatal(err)
	}
	realProof, err := realKey.ProveEqual(realCT, m, r)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := realKey.VerifyEqual(realCT, m, realProof); err != nil || !ok {
		t.Fatalf("honest 2048-bit proof rejected: ok=%v err=%v", ok, err)
	}
	var pf zkProof
	if err := json.Unmarshal(realProof, &pf); err != nil {
		t.Fatal(err)
	}
	if len(pf.R) != coprimeChallengeCount {
		t.Fatalf("expected %d coprimality roots, got %d", coprimeChallengeCount, len(pf.R))
	}
	// Missing R.
	noR, _ := json.Marshal(zkProof{A: pf.A, Z: pf.Z})
	if ok, _ := realKey.VerifyEqual(realCT, m, noR); ok {
		t.Fatal("VerifyEqual accepted proof with missing R")
	}
	// Tampered R[0].
	tamperedR := append([][]byte(nil), pf.R...)
	tamperedR[0] = append([]byte(nil), pf.R[0]...)
	tamperedR[0][len(tamperedR[0])-1] ^= 0x01
	badRJSON, _ := json.Marshal(zkProof{A: pf.A, Z: pf.Z, R: tamperedR})
	if ok, _ := realKey.VerifyEqual(realCT, m, badRJSON); ok {
		t.Fatal("VerifyEqual accepted proof with tampered R[0]")
	}
	// Leading-zero non-canonical R[0].
	paddedR := append([][]byte(nil), pf.R...)
	paddedR[0] = append([]byte{0x00}, pf.R[0]...)
	paddedRJSON, _ := json.Marshal(zkProof{A: pf.A, Z: pf.Z, R: paddedR})
	if ok, _ := realKey.VerifyEqual(realCT, m, paddedRJSON); ok {
		t.Fatal("VerifyEqual accepted proof with non-canonical leading-zero R[0]")
	}
}

// TestV202_ZKChallengeFramingBindingAndNonMalleability verifies BUG-29:
// (1) zkChallenge length-frames ct, m, commit and binds canonical modulus N;
// (2) VerifyEqual rejects leading-zero A/Z/R, unknown JSON fields, and trailing bytes;
// (3) ProveEqual and VerifyEqual reject leading-zero non-canonical ct.
func TestV202_ZKChallengeFramingBindingAndNonMalleability(t *testing.T) {
	p1, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}

	e1 := zkChallenge([]byte{0x01, 0x02}, []byte{0x03}, []byte{0x04}, p1.n)
	e2 := zkChallenge([]byte{0x01}, []byte{0x02, 0x03}, []byte{0x04}, p1.n)
	if e1.Cmp(e2) == 0 {
		t.Fatal("zkChallenge collided across (ct, m) boundary")
	}
	e3 := zkChallenge([]byte{0x01}, []byte{0x02, 0x03}, []byte{0x04}, p1.n)
	e4 := zkChallenge([]byte{0x01}, []byte{0x02}, []byte{0x03, 0x04}, p1.n)
	if e3.Cmp(e4) == 0 {
		t.Fatal("zkChallenge collided across (m, commit) boundary")
	}
	eKey1 := zkChallenge([]byte{0x01}, []byte{0x02}, []byte{0x03}, p1.n)
	eKey2 := zkChallenge([]byte{0x01}, []byte{0x02}, []byte{0x03}, p2.n)
	if eKey1.Cmp(eKey2) == 0 {
		t.Fatal("zkChallenge did not bind public modulus N")
	}

	m := big.NewInt(42)
	r := big.NewInt(1337)
	ct, err := p1.EncryptWithR(m, r)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := p1.ProveEqual(ct, m, r)
	if err != nil {
		t.Fatal(err)
	}
	var pf zkProof
	if err := json.Unmarshal(proof, &pf); err != nil {
		t.Fatal(err)
	}

	// Leading-zero A.
	padA, _ := json.Marshal(zkProof{A: append([]byte{0x00}, pf.A...), Z: pf.Z, R: pf.R})
	if ok, _ := p1.VerifyEqual(ct, m, padA); ok {
		t.Fatal("VerifyEqual accepted non-canonical leading-zero A")
	}
	// Leading-zero Z.
	padZ, _ := json.Marshal(zkProof{A: pf.A, Z: append([]byte{0x00}, pf.Z...), R: pf.R})
	if ok, _ := p1.VerifyEqual(ct, m, padZ); ok {
		t.Fatal("VerifyEqual accepted non-canonical leading-zero Z")
	}
	// Unknown JSON field.
	extraField, _ := json.Marshal(struct {
		A     []byte   `json:"a"`
		Z     []byte   `json:"z"`
		R     [][]byte `json:"r"`
		Extra string   `json:"extra"`
	}{A: pf.A, Z: pf.Z, R: pf.R, Extra: "malleated"})
	if ok, _ := p1.VerifyEqual(ct, m, extraField); ok {
		t.Fatal("VerifyEqual accepted proof with unknown JSON field")
	}
	// Trailing JSON tokens / bytes.
	if ok, _ := p1.VerifyEqual(ct, m, append(bytes.Clone(proof), []byte("{}")...)); ok {
		t.Fatal("VerifyEqual accepted proof with trailing JSON object")
	}
	if ok, _ := p1.VerifyEqual(ct, m, append(bytes.Clone(proof), ' ')); ok {
		t.Fatal("VerifyEqual accepted proof with trailing whitespace")
	}

	// Non-canonical leading-zero ciphertext rejected everywhere.
	ctPadded := append([]byte{0x00}, ct...)
	if _, err := p1.ProveEqual(ctPadded, m, r); err == nil {
		t.Fatal("ProveEqual accepted leading-zero non-canonical ciphertext")
	}
	if ok, _ := p1.VerifyEqual(ctPadded, m, proof); ok {
		t.Fatal("VerifyEqual accepted leading-zero non-canonical ciphertext")
	}
	if _, err := p1.Add(ctPadded, ct); err == nil {
		t.Fatal("Add accepted leading-zero non-canonical ciphertext")
	}
	if _, err := p1.Decrypt(ctPadded); err == nil {
		t.Fatal("Decrypt accepted leading-zero non-canonical ciphertext")
	}
}

// TestV202_RestorePrivateRejectsWeakModulusAndBogusLambda verifies BUG-30:
// RestorePrivate rejects leading-zero padded 4-bit N=15, prime-power/prime/square moduli,
// bogus lambda=1/mu=1, and bogus lambda=3 with valid modular inverse, while accepting
// genuine key checkpoints.
func TestV202_RestorePrivateRejectsWeakModulusAndBogusLambda(t *testing.T) {
	padded15 := make([]byte, 128)
	padded15[127] = 15
	if _, err := RestorePrivate(PrivateState{
		N:      padded15,
		Lambda: []byte{4},
		Mu:     []byte{4},
	}); err == nil {
		t.Fatal("RestorePrivate accepted 4-bit leading-zero padded N=15")
	}

	realKey, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	state := realKey.PrivateState()

	// Genuine checkpoint restores cleanly and round-trips encrypt/decrypt/prove/verify.
	restored, err := RestorePrivate(state)
	if err != nil {
		t.Fatalf("RestorePrivate rejected valid checkpoint: %v", err)
	}
	ct, err := restored.Encrypt(big.NewInt(12345))
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.Decrypt(ct)
	if err != nil || got.Cmp(big.NewInt(12345)) != 0 {
		t.Fatalf("restored key decrypt mismatch: got=%v err=%v", got, err)
	}

	// Fake lambda=1, mu=1 on valid 2048-bit N.
	if _, err := RestorePrivate(PrivateState{
		N:      state.N,
		Lambda: []byte{1},
		Mu:     []byte{1},
	}); err == nil {
		t.Fatal("RestorePrivate accepted fake lambda=1, mu=1")
	}

	// Fake lambda=3 with valid modular inverse mu=3^-1 mod N (fails Carmichael exponent check).
	mu3 := new(big.Int).ModInverse(big.NewInt(3), realKey.N())
	if _, err := RestorePrivate(PrivateState{
		N:      state.N,
		Lambda: []byte{3},
		Mu:     mu3.Bytes(),
	}); err == nil {
		t.Fatal("RestorePrivate accepted bogus lambda=3")
	}

	// Leading-zero padded N / Lambda / Mu.
	if _, err := RestorePrivate(PrivateState{
		N:      append([]byte{0x00}, state.N...),
		Lambda: state.Lambda,
		Mu:     state.Mu,
	}); err == nil {
		t.Fatal("RestorePrivate accepted leading-zero N")
	}
	if _, err := RestorePrivate(PrivateState{
		N:      state.N,
		Lambda: append([]byte{0x00}, state.Lambda...),
		Mu:     state.Mu,
	}); err == nil {
		t.Fatal("RestorePrivate accepted leading-zero Lambda")
	}
	if _, err := RestorePrivate(PrivateState{
		N:      state.N,
		Lambda: state.Lambda,
		Mu:     append([]byte{0x00}, state.Mu...),
	}); err == nil {
		t.Fatal("RestorePrivate accepted leading-zero Mu")
	}
}
