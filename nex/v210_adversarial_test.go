package nex

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/WillBeebe/nexum/v2/internal/he"
)

// ---------------------------------------------------------------------------
// Helpers for forging/tampering 8-round CDS94 OR-proofs and Paillier GMR proofs
// ---------------------------------------------------------------------------

const testBitORRounds = 8

type rawBitORRound struct {
	A0 []byte `json:"a0"`
	A1 []byte `json:"a1"`
	E0 []byte `json:"e0"`
	E1 []byte `json:"e1"`
	Z0 []byte `json:"z0"`
	Z1 []byte `json:"z1"`
}

type rawBitORProof struct {
	Rounds []rawBitORRound `json:"rounds"`
}

type rawZKProof struct {
	A []byte   `json:"a"`
	Z []byte   `json:"z"`
	R [][]byte `json:"r"`
}

func testWriteLenFramed(h *bytes.Buffer, b []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
	h.Write(lenBuf[:])
	h.Write(b)
}

func testBitORChallengesV2(mod *big.Int, domain, ct []byte, a0s, a1s [][]byte) [testBitORRounds][sha256.Size]byte {
	const dom = "nexum/he/bit-or-v2\x00"
	var buf bytes.Buffer
	buf.WriteString(dom)
	testWriteLenFramed(&buf, mod.Bytes())
	testWriteLenFramed(&buf, domain)
	testWriteLenFramed(&buf, ct)
	for i := 0; i < testBitORRounds; i++ {
		testWriteLenFramed(&buf, a0s[i])
		testWriteLenFramed(&buf, a1s[i])
	}
	root := sha256.Sum256(buf.Bytes())

	var out [testBitORRounds][sha256.Size]byte
	var idxBuf [4]byte
	for i := 0; i < testBitORRounds; i++ {
		binary.BigEndian.PutUint32(idxBuf[:], uint32(i))
		h := sha256.New()
		h.Write([]byte(dom))
		h.Write(root[:])
		h.Write(idxBuf[:])
		copy(out[i][:], h.Sum(nil))
	}
	return out
}

// buildSmallFactorRSAModulus constructs a deterministic 1024-bit RSA modulus
// N = p * q where p = 65539 (smallest prime strictly above maxTrialPrime=65537)
// and q is a 1009-bit prime with gcd(N, phi(N)) == 1.
func buildSmallFactorRSAModulus(t *testing.T) (p, q, n *big.Int) {
	t.Helper()
	p = big.NewInt(65539)
	one := big.NewInt(1)
	two := big.NewInt(2)
	q = new(big.Int).Lsh(one, 1008)
	q.Add(q, one)
	for {
		if q.ProbablyPrime(20) {
			qMinus1 := new(big.Int).Sub(q, one)
			if new(big.Int).Rem(qMinus1, p).Sign() != 0 {
				n = new(big.Int).Mul(p, q)
				if n.BitLen() >= 1024 {
					pMinus1 := new(big.Int).Sub(p, one)
					g := new(big.Int).GCD(nil, nil, pMinus1, qMinus1)
					lambda := new(big.Int).Div(new(big.Int).Mul(pMinus1, qMinus1), g)
					if new(big.Int).GCD(nil, nil, n, lambda).Cmp(one) == 0 {
						return p, q, n
					}
				}
			}
		}
		q.Add(q, two)
	}
}

// forgeSingleRoundORForQ attempts to forge round 0 of an 8-round CDS94 proof
// for non-bit ct = E(q; r) on N = 65539 * q by grinding only round 0's commitment
// (leaving rounds 1..7 simulated with mismatched e0). With 8 jointly-bound rounds,
// the verifier MUST reject because rounds 1..7 cannot simultaneously satisfy e0_i % p == 0.
func forgeSingleRoundORForQ(t *testing.T, p, n, ct, r *big.Int, domain []byte) []byte {
	t.Helper()
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, big.NewInt(1))
	gInv := new(big.Int).ModInverse(g, n2)
	u1 := new(big.Int).Mod(new(big.Int).Mul(ct, gInv), n2)
	u1Inv := new(big.Int).ModInverse(u1, n2)

	z1 := big.NewInt(7)
	var e1Bytes [sha256.Size]byte
	e1Bytes[0] = 0x5a
	e1Bytes[31] = 0xa5
	e1 := new(big.Int).SetBytes(e1Bytes[:])
	a1 := new(big.Int).Exp(u1Inv, e1, n2)
	a1.Mul(a1, new(big.Int).Exp(z1, n, n2))
	a1.Mod(a1, n2)
	a1Bytes := a1.Bytes()

	ctBytes := ct.Bytes()
	step := new(big.Int).Exp(big.NewInt(2), n, n2)
	a0s := make([][]byte, testBitORRounds)
	a1s := make([][]byte, testBitORRounds)
	for i := 0; i < testBitORRounds; i++ {
		a0s[i] = step.Bytes()
		a1s[i] = a1Bytes
	}

	a0 := new(big.Int).Set(step)
	var e0Bytes [sha256.Size]byte
	e0Int := new(big.Int)
	rem := new(big.Int)
	var prefixBuf bytes.Buffer
	const dom = "nexum/he/bit-or-v2\x00"
	prefixBuf.WriteString(dom)
	testWriteLenFramed(&prefixBuf, n.Bytes())
	testWriteLenFramed(&prefixBuf, domain)
	testWriteLenFramed(&prefixBuf, ctBytes)
	prefix := prefixBuf.Bytes()

	var suffixBuf bytes.Buffer
	testWriteLenFramed(&suffixBuf, a1s[0])
	for i := 1; i < testBitORRounds; i++ {
		testWriteLenFramed(&suffixBuf, a0s[i])
		testWriteLenFramed(&suffixBuf, a1s[i])
	}
	suffix := suffixBuf.Bytes()

	hRoot := sha256.New()
	hRound := sha256.New()
	var lenBuf [8]byte
	var zeroIdx [4]byte
	var rootSum [sha256.Size]byte
	var ch0 [sha256.Size]byte

	for k := int64(1); k <= 20*65539; k++ {
		a0b := a0.Bytes()
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(a0b)))
		hRoot.Reset()
		hRoot.Write(prefix)
		hRoot.Write(lenBuf[:])
		hRoot.Write(a0b)
		hRoot.Write(suffix)
		hRoot.Sum(rootSum[:0])

		hRound.Reset()
		hRound.Write([]byte(dom))
		hRound.Write(rootSum[:])
		hRound.Write(zeroIdx[:])
		hRound.Sum(ch0[:0])

		for j := range e0Bytes {
			e0Bytes[j] = ch0[j] ^ e1Bytes[j]
		}
		e0Int.SetBytes(e0Bytes[:])
		rem.Rem(e0Int, p)
		if rem.Sign() == 0 {
			a0s[0] = a0b
			chs := testBitORChallengesV2(n, domain, ctBytes, a0s, a1s)
			w0 := new(big.Int).Exp(big.NewInt(2), big.NewInt(k), n)
			z0 := new(big.Int).Exp(r, e0Int, n)
			z0.Mul(z0, w0)
			z0.Mod(z0, n)

			rounds := make([]rawBitORRound, testBitORRounds)
			rounds[0] = rawBitORRound{
				A0: a0s[0], A1: a1Bytes,
				E0: slices.Clone(e0Bytes[:]), E1: slices.Clone(e1Bytes[:]),
				Z0: z0.Bytes(), Z1: z1.Bytes(),
			}
			for i := 1; i < testBitORRounds; i++ {
				e0i := make([]byte, sha256.Size)
				for j := range e0i {
					e0i[j] = chs[i][j] ^ e1Bytes[j]
				}
				z0i := new(big.Int).Exp(r, new(big.Int).SetBytes(e0i), n)
				z0i.Mul(z0i, big.NewInt(2))
				z0i.Mod(z0i, n)
				rounds[i] = rawBitORRound{
					A0: a0s[i], A1: a1Bytes,
					E0: e0i, E1: slices.Clone(e1Bytes[:]),
					Z0: z0i.Bytes(), Z1: z1.Bytes(),
				}
			}
			raw, err := json.Marshal(rawBitORProof{Rounds: rounds})
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		a0.Mul(a0, step)
		a0.Mod(a0, n2)
	}
	t.Fatalf("failed to forge single round 0 within bound")
	return nil
}

// ---------------------------------------------------------------------------
// Surface 1: CDS94 OR-proofs & Sealed-Ballot Paillier Accords
// ---------------------------------------------------------------------------

func TestV210Adversarial_ORProofBoundaryCanonicalAndReplay(t *testing.T) {
	priv, err := he.NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := he.FromPublic(priv.N().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	n := priv.N()
	n2 := new(big.Int).Mul(n, n)
	domain := []byte("v210/adv/domain")

	ct1, r1, err := pub.EncryptBitWithR(1)
	if err != nil {
		t.Fatal(err)
	}
	proof1, err := pub.ProveBit(new(big.Int).SetBytes(ct1), r1, 1, domain)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.VerifyBit(ct1, proof1, domain); err != nil {
		t.Fatalf("honest 8-round VerifyBit(1) failed: %v", err)
	}

	// Non-bit encryptions (2 and N-1 representing -1 mod N) must never be provable as {0,1}.
	for _, badPlain := range []*big.Int{big.NewInt(2), new(big.Int).Sub(n, big.NewInt(1))} {
		r := big.NewInt(19)
		ctBad, err := pub.EncryptWithR(badPlain, r)
		if err != nil {
			t.Fatal(err)
		}
		for _, claimed := range []int{-1, 0, 1, 2} {
			if _, err := pub.ProveBit(new(big.Int).SetBytes(ctBad), r, claimed, domain); err == nil {
				t.Fatalf("ProveBit accepted non-bit plaintext %s with claimed=%d", badPlain, claimed)
			}
		}
	}

	// Out-of-range / non-canonical ciphertexts: >= N^2, N^2+1, N, 0, leading zero.
	badCTs := [][]byte{
		nil,
		{},
		{0},
		append([]byte{0}, ct1...),
		n.Bytes(),
		n2.Bytes(),
		new(big.Int).Add(n2, big.NewInt(1)).Bytes(),
		new(big.Int).Mul(big.NewInt(2), n).Bytes(),
	}
	for i, badCT := range badCTs {
		if err := pub.VerifyBit(badCT, proof1, domain); err == nil {
			t.Fatalf("VerifyBit accepted bad ciphertext case %d", i)
		}
		if _, err := pub.Scale(badCT, 2); err == nil {
			t.Fatalf("Scale accepted bad ciphertext case %d", i)
		}
	}

	var pf rawBitORProof
	if err := json.Unmarshal(proof1, &pf); err != nil {
		t.Fatal(err)
	}
	if len(pf.Rounds) != testBitORRounds {
		t.Fatalf("expected %d rounds, got %d", testBitORRounds, len(pf.Rounds))
	}
	clonePF := func() rawBitORProof {
		out := rawBitORProof{Rounds: make([]rawBitORRound, len(pf.Rounds))}
		for i, rd := range pf.Rounds {
			out.Rounds[i] = rawBitORRound{
				A0: slices.Clone(rd.A0), A1: slices.Clone(rd.A1),
				E0: slices.Clone(rd.E0), E1: slices.Clone(rd.E1),
				Z0: slices.Clone(rd.Z0), Z1: slices.Clone(rd.Z1),
			}
		}
		return out
	}

	mutatedProofs := []struct {
		name string
		raw  []byte
	}{
		{"a0_ge_n2", func() []byte {
			c := clonePF()
			c.Rounds[0].A0 = new(big.Int).Add(n2, big.NewInt(1)).Bytes()
			b, _ := json.Marshal(c)
			return b
		}()},
		{"a1_eq_n2", func() []byte { c := clonePF(); c.Rounds[3].A1 = n2.Bytes(); b, _ := json.Marshal(c); return b }()},
		{"z0_ge_n", func() []byte {
			c := clonePF()
			c.Rounds[5].Z0 = new(big.Int).Add(n, big.NewInt(1)).Bytes()
			b, _ := json.Marshal(c)
			return b
		}()},
		{"z1_eq_n", func() []byte { c := clonePF(); c.Rounds[7].Z1 = n.Bytes(); b, _ := json.Marshal(c); return b }()},
		{"swapped_branches_round_0", func() []byte {
			c := clonePF()
			r0 := c.Rounds[0]
			c.Rounds[0] = rawBitORRound{A0: r0.A1, A1: r0.A0, E0: r0.E1, E1: r0.E0, Z0: r0.Z1, Z1: r0.Z0}
			b, _ := json.Marshal(c)
			return b
		}()},
		{"forged_challenge_split_zero_e0", func() []byte {
			c := clonePF()
			c.Rounds[2].E0 = make([]byte, sha256.Size)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"truncated_7_rounds", func() []byte {
			c := clonePF()
			c.Rounds = c.Rounds[:testBitORRounds-1]
			b, _ := json.Marshal(c)
			return b
		}()},
		{"extra_9_rounds", func() []byte {
			c := clonePF()
			c.Rounds = append(c.Rounds, c.Rounds[0])
			b, _ := json.Marshal(c)
			return b
		}()},
		{"replayed_round_0_all_8", func() []byte {
			c := clonePF()
			for i := 1; i < testBitORRounds; i++ {
				c.Rounds[i] = c.Rounds[0]
			}
			b, _ := json.Marshal(c)
			return b
		}()},
		{"oversized_proof_gt_128kib", append(append([]byte(`{"rounds":[{"a0":"`), bytes.Repeat([]byte("A"), 129<<10)...), []byte(`"}]}`)...)},
	}
	for _, tc := range mutatedProofs {
		if err := pub.VerifyBit(ct1, tc.raw, domain); err == nil {
			t.Fatalf("VerifyBit accepted mutated proof %s", tc.name)
		}
	}

	// Caller big.Int arguments must not be mutated by ProveBit.
	ctBig := new(big.Int).SetBytes(ct1)
	ctBigOrig := new(big.Int).Set(ctBig)
	r1Orig := new(big.Int).Set(r1)
	if _, err := pub.ProveBit(ctBig, r1, 1, domain); err != nil {
		t.Fatal(err)
	}
	if ctBig.Cmp(ctBigOrig) != 0 || r1.Cmp(r1Orig) != 0 {
		t.Fatal("ProveBit mutated caller big.Int arguments")
	}
}

// Regression test for Defect #3: 8-round jointly-bound CDS94 OR-proofs defeat
// single-round Fiat-Shamir forgery on small-factor RSA modulus N = 65539 * q.
func TestV210Adversarial_SmallFactorModulusMultiRoundSoundness(t *testing.T) {
	p, q, n := buildSmallFactorRSAModulus(t)
	pub, err := he.FromPublic(n.Bytes())
	if err != nil {
		t.Fatalf("FromPublic(N=65539*q): %v", err)
	}

	// Honest 0/1 bits still prove & verify under 8-round CDS94.
	domain := []byte("v210/soundness/8round")
	for _, bit := range []int{0, 1} {
		ct, r, err := pub.EncryptBitWithR(bit)
		if err != nil {
			t.Fatal(err)
		}
		pf, err := pub.ProveBit(new(big.Int).SetBytes(ct), r, bit, domain)
		if err != nil {
			t.Fatal(err)
		}
		if err := pub.VerifyBit(ct, pf, domain); err != nil {
			t.Fatalf("honest VerifyBit(%d) failed: %v", bit, err)
		}
	}

	// Attempting to forge ct = E(q; r=3) by grinding round 0 MUST fail VerifyBit!
	r := big.NewInt(3)
	ctQ, err := pub.EncryptWithR(q, r)
	if err != nil {
		t.Fatalf("EncryptWithR(q): %v", err)
	}
	forgedSingleRound := forgeSingleRoundORForQ(t, p, n, new(big.Int).SetBytes(ctQ), r, domain)
	if err := pub.VerifyBit(ctQ, forgedSingleRound, domain); err == nil {
		t.Fatal("8-round VerifyBit accepted forged E(q) proof on N=65539*q")
	}

	// Replicating round 0 across all 8 slots MUST also fail VerifyBit (joint + round-indexed binding)!
	var parsed rawBitORProof
	if err := json.Unmarshal(forgedSingleRound, &parsed); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < testBitORRounds; i++ {
		parsed.Rounds[i] = parsed.Rounds[0]
	}
	dupRounds, _ := json.Marshal(parsed)
	if err := pub.VerifyBit(ctQ, dupRounds, domain); err == nil {
		t.Fatal("8-round VerifyBit accepted duplicated forged round 0 on N=65539*q")
	}

	// Submitting a forged E(q) sealed ballot into a live Accord MUST fail with ErrAccordEvidence!
	dummyKey, err := NewSealedTallyKey(1024)
	if err != nil {
		t.Fatal(err)
	}
	sf := newSealedAccordFixture(t, dummyKey)
	sf.fx.spec.SealedTally.PublicKey = n.Bytes()
	sf.fx.spec.Rules.BallotMode = BallotApproval
	a, err := NewAccord(sf.fx.spec)
	if err != nil {
		t.Fatal(err)
	}
	aid := a.View().ID
	actorID := sf.fx.sre.pub.ID()
	ballot, err := EncryptSealedBallot(a.Bundle().Spec, aid, actorID, map[string]BallotPosition{}, Hash("poison"))
	if err != nil {
		t.Fatal(err)
	}
	opt0 := ballot.Options[0].OptionID
	ballot.Options[0].ApproveCT = ctQ
	ballot.Options[0].ApproveProof = forgeSingleRoundORForQ(t, p, n, new(big.Int).SetBytes(ctQ), r, sealedProofDomain(aid, actorID, opt0, sealedSlotApprove))
	accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "poison-ballot", 2, ErrAccordEvidence, func(c *AccordCommand) {
		c.Vote = &VotePayload{Sealed: ballot}
	})
}

// Regression test for Defect #4: Veto-dissent opening prevents vote+veto equivocation
// in BOTH orders (veto-then-vote and vote-then-veto) without leaking non-vetoed options.
func TestV210Adversarial_SealedVoteAndVetoEquivocationBlocked(t *testing.T) {
	sharedKey, err := NewSealedTallyKey(1024)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("veto_then_vote_equivocation_and_honest_opening", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		sf.fx.spec.Rules.Veto = VetoPolicy{
			Mode:               VetoOverridable,
			MaxVetoesPerActor:  1,
			OverrideWeight:     5,
			AllowedDomainRoles: []string{"safety"},
		}
		sf.fx.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}}
		sf.fx.spec.Rules.MinApprovalCount = 2
		sf.fx.spec.Rules.MinApprovalWeight = 3
		sf.fx.spec.Rules.MinApprovalMarginWeight = 0

		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		spec := a.Bundle().Spec
		aid := a.View().ID

		// Helper rejects invalid vetoedOptions directly.
		if _, err := EncryptSealedBallotWithVetoes(spec, aid, sf.fx.safety.pub.ID(), map[string]BallotPosition{"full-rollout": BallotApprove}, []string{"full-rollout"}, Hash("eq")); !errors.Is(err, ErrAccordEquivocation) {
			t.Fatalf("EncryptSealedBallotWithVetoes allowed approve on vetoed option: %v", err)
		}
		if _, err := EncryptSealedBallotWithVetoes(spec, aid, sf.fx.safety.pub.ID(), map[string]BallotPosition{"full-rollout": BallotAbstain}, []string{"full-rollout"}, Hash("eq")); !errors.Is(err, ErrAccordEquivocation) {
			t.Fatalf("EncryptSealedBallotWithVetoes allowed abstain on vetoed option: %v", err)
		}
		if _, err := EncryptSealedBallotWithVetoes(spec, aid, sf.fx.safety.pub.ID(), map[string]BallotPosition{"full-rollout": BallotDissent}, []string{"unknown-opt"}, Hash("bad")); !errors.Is(err, ErrAccordSpec) {
			t.Fatalf("EncryptSealedBallotWithVetoes allowed undeclared vetoed option: %v", err)
		}

		// Extraneous DissentRandomness on a veto BEFORE any sealed ballot -> ErrAccordSpec.
		accordReject(t, a, sf.fx.safety, "safety-vote", "veto", "veto-extra-rand", 2, ErrAccordSpec, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("block"), DissentRandomness: []byte{7}}
		})

		// Honest veto on full-rollout.
		accordMustApply(t, a, sf.fx.safety, "safety-vote", "veto", "saf-veto", 2, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("block-full")}
		})

		// 1. Sealed approve on vetoed full-rollout (missing DissentRandomness) -> ErrAccordEquivocation!
		badApprove, err := EncryptSealedBallot(spec, aid, sf.fx.safety.pub.ID(), map[string]BallotPosition{"full-rollout": BallotApprove}, Hash("sneaky"))
		if err != nil {
			t.Fatal(err)
		}
		accordReject(t, a, sf.fx.safety, "safety-vote", "vote", "saf-equiv-approve", 3, ErrAccordEquivocation, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: badApprove}
		})

		// 2. Sealed abstain on vetoed full-rollout with bogus DissentRandomness -> ErrAccordEquivocation!
		badAbstain, err := EncryptSealedBallot(spec, aid, sf.fx.safety.pub.ID(), map[string]BallotPosition{"full-rollout": BallotAbstain}, Hash("abstain"))
		if err != nil {
			t.Fatal(err)
		}
		for i := range badAbstain.Options {
			if badAbstain.Options[i].OptionID == "full-rollout" {
				badAbstain.Options[i].DissentRandomness = []byte{11}
			}
		}
		accordReject(t, a, sf.fx.safety, "safety-vote", "vote", "saf-equiv-abstain", 3, ErrAccordEquivocation, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: badAbstain}
		})

		// 3. Honest dissent with non-canonical leading-zero DissentRandomness -> ErrAccordEquivocation!
		honestBallot, err := EncryptSealedBallotWithVetoes(spec, aid, sf.fx.safety.pub.ID(), map[string]BallotPosition{
			"canary-rollout": BallotApprove,
			"full-rollout":   BallotDissent,
		}, []string{"full-rollout"}, Hash("honest"))
		if err != nil {
			t.Fatal(err)
		}
		nonCanon := cloneSealedBallotPayload(honestBallot)
		for i := range nonCanon.Options {
			if nonCanon.Options[i].OptionID == "full-rollout" {
				nonCanon.Options[i].DissentRandomness = append([]byte{0}, nonCanon.Options[i].DissentRandomness...)
			}
		}
		accordReject(t, a, sf.fx.safety, "safety-vote", "vote", "saf-leading-zero", 3, ErrAccordEquivocation, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: nonCanon}
		})

		// 4. Extraneous DissentRandomness on NON-vetoed option -> ErrAccordSpec!
		extraRand := cloneSealedBallotPayload(honestBallot)
		for i := range extraRand.Options {
			if extraRand.Options[i].OptionID == "canary-rollout" {
				extraRand.Options[i].DissentRandomness = []byte{9}
			}
		}
		accordReject(t, a, sf.fx.safety, "safety-vote", "vote", "saf-extra-rand", 3, ErrAccordSpec, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: extraRand}
		})

		// 5. Honest veto-then-vote with DissentRandomness opening succeeds & verifies offline!
		accordMustApply(t, a, sf.fx.safety, "safety-vote", "vote", "saf-honest-vote", 3, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: honestBallot}
		})
		// Caller mutating DissentRandomness after Apply must not corrupt Accord bundle!
		for i := range honestBallot.Options {
			if len(honestBallot.Options[i].DissentRandomness) > 0 {
				honestBallot.Options[i].DissentRandomness[0] ^= 0xff
			}
		}
		castSealedVote(t, a, sf.fx.sre, "sre-vote", 4, "v-sre", map[string]BallotPosition{"canary-rollout": BallotApprove}, "sre")
		finalHead := resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res")
		if _, err := VerifyAccordBundle(a.Bundle(), aid, finalHead); err != nil {
			t.Fatalf("VerifyAccordBundle after honest veto-then-vote failed: %v", err)
		}
	})

	t.Run("vote_then_veto_equivocation_and_honest_opening", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		sf.fx.spec.Rules.Veto = VetoPolicy{
			Mode:               VetoBlocking,
			MaxVetoesPerActor:  2,
			AllowedDomainRoles: []string{"safety"},
		}
		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		spec := a.Bundle().Spec
		aid := a.View().ID

		// Safety votes FIRST: approves canary-rollout, dissents full-rollout, abstains hold-release.
		ballot, openings, err := EncryptSealedBallotWithOpenings(spec, aid, sf.fx.safety.pub.ID(), map[string]BallotPosition{
			"canary-rollout": BallotApprove,
			"full-rollout":   BallotDissent,
			"hold-release":   BallotAbstain,
		}, nil, Hash("saf-first"))
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, a, sf.fx.safety, "safety-vote", "vote", "saf-vote-first", 2, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: ballot}
		})

		// 1. Veto without DissentRandomness after sealed vote -> ErrAccordEquivocation!
		accordReject(t, a, sf.fx.safety, "safety-vote", "veto", "veto-no-open", 3, ErrAccordEquivocation, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("no-open")}
		})

		// 2. Veto on APPROVED option (canary-rollout) with bogus or full-rollout's opening -> ErrAccordEquivocation!
		accordReject(t, a, sf.fx.safety, "safety-vote", "veto", "veto-approved", 3, ErrAccordEquivocation, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "canary-rollout", ReasonHash: Hash("equiv"), DissentRandomness: openings["full-rollout"]}
		})

		// 3. Veto on ABSTAINED option (hold-release) -> ErrAccordEquivocation!
		accordReject(t, a, sf.fx.safety, "safety-vote", "veto", "veto-abstained", 3, ErrAccordEquivocation, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "hold-release", ReasonHash: Hash("equiv"), DissentRandomness: []byte{13}}
		})

		// 4. Non-canonical leading-zero opening on full-rollout -> ErrAccordEquivocation!
		accordReject(t, a, sf.fx.safety, "safety-vote", "veto", "veto-leading-zero", 3, ErrAccordEquivocation, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("pad"), DissentRandomness: append([]byte{0}, openings["full-rollout"]...)}
		})

		// 5. Honest vote-then-veto with exact opening succeeds, resists caller slice mutation, and verifies offline!
		openCopy := slices.Clone(openings["full-rollout"])
		accordMustApply(t, a, sf.fx.safety, "safety-vote", "veto", "veto-honest", 4, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("honest-veto"), DissentRandomness: openCopy}
		})
		openCopy[0] ^= 0xff // mutate caller slice after Apply

		castSealedVote(t, a, sf.fx.sre, "sre-vote", 5, "v-sre", map[string]BallotPosition{"canary-rollout": BallotApprove}, "sre")
		castSealedVote(t, a, sf.fx.security, "security-vote", 5, "v-sec", map[string]BallotPosition{"canary-rollout": BallotApprove}, "sec")
		finalHead := resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res")
		if _, err := VerifyAccordBundle(a.Bundle(), aid, finalHead); err != nil {
			t.Fatalf("VerifyAccordBundle after honest vote-then-veto failed: %v", err)
		}

		// 6. Plaintext Accord rejects DissentRandomness on VetoPayload with ErrAccordSpec.
		pubFx := newAccordFixture(t)
		pubAccord, err := NewAccord(pubFx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordReject(t, pubAccord, pubFx.safety, "safety-vote", "veto", "plain-extra-rand", 2, ErrAccordSpec, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("r"), DissentRandomness: []byte{5}}
		})
	})
}

func TestV210Adversarial_SealedAccordTallyModulusAliasingAnd32Options(t *testing.T) {
	sharedKey, err := NewSealedTallyKey(1024)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("malicious_moduli_in_sealed_spec_and_p2q_gmr", func(t *testing.T) {
		p512, err := rand.Prime(rand.Reader, 513)
		if err != nil {
			t.Fatal(err)
		}
		p350, err := rand.Prime(rand.Reader, 350)
		if err != nil {
			t.Fatal(err)
		}
		q350, err := rand.Prime(rand.Reader, 350)
		if err != nil {
			t.Fatal(err)
		}
		p1024, err := rand.Prime(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		evenMod := new(big.Int).Lsh(big.NewInt(1), 1024)

		badModuli := []struct {
			name string
			mod  []byte
		}{
			{"even_1024", evenMod.Bytes()},
			{"prime_1024", p1024.Bytes()},
			{"exact_square", new(big.Int).Mul(p512, p512).Bytes()},
			{"small_512bit", new(big.Int).Mul(p350, big.NewInt(3)).Bytes()},
			{"prime_power_3_650", new(big.Int).Exp(big.NewInt(3), big.NewInt(650), nil).Bytes()},
			{"factor_65537", new(big.Int).Mul(big.NewInt(65537), p1024).Bytes()},
			{"oversized_gt_1024_bytes", bytes.Repeat([]byte{0xff}, 1025)},
		}
		for _, tc := range badModuli {
			sf := newSealedAccordFixture(t, sharedKey)
			sf.fx.spec.SealedTally.PublicKey = tc.mod
			if err := sf.fx.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("AccordSpec.Validate accepted malicious modulus %s: %v", tc.name, err)
			}
		}

		// Non-square-free N = p^2 * q (all prime factors > 65537, >1024 bit, odd, non-square):
		// passes cheap FromPublic checks, MUST be rejected by GMR VerifyEqual at resolve time!
		nP2Q := new(big.Int).Mul(new(big.Int).Mul(p350, p350), q350)
		sfP2Q := newSealedAccordFixture(t, sharedKey)
		sfP2Q.fx.spec.SealedTally.PublicKey = nP2Q.Bytes()
		sfP2Q.fx.spec.Rules.MandatoryRoles = nil
		sfP2Q.fx.spec.Rules.MinParticipationCount = 0
		sfP2Q.fx.spec.Rules.MinParticipationWeight = 0
		aP2Q, err := NewAccord(sfP2Q.fx.spec)
		if err != nil {
			t.Fatalf("NewAccord(p^2*q): %v", err)
		}
		fakeGMR, _ := json.Marshal(rawZKProof{A: []byte{1}, Z: []byte{1}, R: [][]byte{{2}, {2}, {2}, {2}, {2}, {2}, {2}, {2}}})
		opts := slices.Clone(sfP2Q.fx.spec.Options)
		slices.SortFunc(opts, func(a, b AccordOption) int { return strings.Compare(a.ID, b.ID) })
		fakeTally := &SealedTallyProof{Options: make([]SealedOptionTallyProof, len(opts))}
		for i, o := range opts {
			fakeTally.Options[i] = SealedOptionTallyProof{
				OptionID:           o.ID,
				ApproveCountProof:  fakeGMR,
				ApproveWeightProof: fakeGMR,
				DissentCountProof:  fakeGMR,
				DissentWeightProof: fakeGMR,
			}
		}
		accordReject(t, aP2Q, sfP2Q.tally, "tally-resolve", "resolve", "p2q-gmr", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("p2q"), SealedTally: fakeTally}
		})
	})

	t.Run("mismatched_gmr_proof_replay_missing_role_and_aliasing", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		sf.fx.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}}
		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}

		// Caller mutates spec.SealedTally.PublicKey after NewAccord -> internal state unaffected.
		origPK := slices.Clone(sf.fx.spec.SealedTally.PublicKey)
		sf.fx.spec.SealedTally.PublicKey[0] ^= 0xff
		if !bytes.Equal(a.Bundle().Spec.SealedTally.PublicKey, origPK) {
			t.Fatal("NewAccord aliased caller SealedTally.PublicKey")
		}
		sf.fx.spec.SealedTally.PublicKey = origPK

		// Cast ballots and immediately mutate caller's SealedBallotPayload slices after Apply!
		bSpec := a.Bundle().Spec
		ballotSafety, err := EncryptSealedBallot(bSpec, a.View().ID, sf.fx.safety.pub.ID(), map[string]BallotPosition{"canary-rollout": BallotApprove}, Hash("saf"))
		if err != nil {
			t.Fatal(err)
		}
		cmdSaf := a.Prepare(sf.fx.safety.pub.ID(), "safety-vote", sf.fx.spec.Scope, "vote", "v-saf", 2)
		cmdSaf.Vote = &VotePayload{Sealed: ballotSafety}
		sigSaf, err := SignAccordCommand(sf.fx.safety.id, cmdSaf)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Apply(cmdSaf, sigSaf, 2); err != nil {
			t.Fatal(err)
		}
		ballotSafety.Options[0].ApproveCT[0] ^= 0xff
		ballotSafety.Options[0].ApproveProof[0] ^= 0xff
		ballotSafety.Options[0].DissentCT[0] ^= 0xff
		ballotSafety.Options[0].ExclusiveProof[0] ^= 0xff

		vMid := a.View()
		vMid.SealedBallots[0].Options[0].ApproveCT[0] ^= 0xff
		vMid.SealedBallots[0].DomainRoles[0] = "evil-role"

		castSealedVote(t, a, sf.fx.sre, "sre-vote", 3, "v-sre", map[string]BallotPosition{"canary-rollout": BallotApprove}, "sre")
		castSealedVote(t, a, sf.fx.security, "security-vote", 4, "v-sec", map[string]BallotPosition{"canary-rollout": BallotApprove}, "sec")

		honestTally, err := sharedKey.TallyAccord(a.Bundle())
		if err != nil {
			t.Fatalf("TallyAccord failed after caller aliasing mutations: %v", err)
		}

		// 1. Missing mandatory role proof -> ErrAccordEvidence.
		missingRole := cloneSealedTallyProof(honestTally)
		missingRole.Options[0].RoleTallies = nil
		accordReject(t, a, sf.tally, "tally-resolve", "resolve", "missing-role", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r"), SealedTally: missingRole}
		})

		// 2. Wrong role name in RoleTallies -> ErrAccordEvidence.
		wrongRole := cloneSealedTallyProof(honestTally)
		wrongRole.Options[0].RoleTallies[0].Role = "sre"
		accordReject(t, a, sf.tally, "tally-resolve", "resolve", "wrong-role", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r"), SealedTally: wrongRole}
		})

		// 3. Mismatched GMR ProveEqual replay across different ciphertexts of value 0.
		replayedGMR := cloneSealedTallyProof(honestTally)
		replayedGMR.Options[0].DissentCountProof = slices.Clone(honestTally.Options[1].DissentCountProof)
		accordReject(t, a, sf.tally, "tally-resolve", "resolve", "replayed-gmr", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r"), SealedTally: replayedGMR}
		})

		// 4. Out-of-order options in SealedTallyProof -> ErrAccordEvidence.
		swappedOpts := cloneSealedTallyProof(honestTally)
		swappedOpts.Options[0], swappedOpts.Options[1] = swappedOpts.Options[1], swappedOpts.Options[0]
		accordReject(t, a, sf.tally, "tally-resolve", "resolve", "swapped-opts", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("r"), SealedTally: swappedOpts}
		})

		// 5. Commit honest tally, then mutate caller's SealedTallyProof slices after Apply -> Bundle still verifies!
		resCmd := a.Prepare(sf.tally.pub.ID(), "tally-resolve", sf.fx.spec.Scope, "resolve", "res-ok", 10)
		resCmd.Resolve = &ResolvePayload{ReasonHash: Hash("ok"), SealedTally: honestTally}
		resSig, err := SignAccordCommand(sf.tally.id, resCmd)
		if err != nil {
			t.Fatal(err)
		}
		finalHead, err := a.Apply(resCmd, resSig, 10)
		if err != nil {
			t.Fatal(err)
		}
		honestTally.Options[0].ApproveCountProof[0] ^= 0xff
		honestTally.Options[0].RoleTallies[0].ApproveWeightProof[0] ^= 0xff

		if _, err := VerifyAccordBundle(a.Bundle(), a.View().ID, finalHead); err != nil {
			t.Fatalf("VerifyAccordBundle failed after caller mutated submitted SealedTallyProof: %v", err)
		}
	})

	t.Run("max_32_options_sealed_vote_and_tally_within_4mib_cap", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		sf.fx.spec.Rules.BallotMode = BallotSingleChoice
		sf.fx.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}}
		sf.fx.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
		sf.fx.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
		sf.fx.spec.Rules.MinParticipationCount = 1
		sf.fx.spec.Rules.MinParticipationWeight = 1
		sf.fx.spec.Rules.MinApprovalCount = 1
		sf.fx.spec.Rules.MinApprovalWeight = 1
		sf.fx.spec.Rules.MinApprovalMarginWeight = 0
		sf.fx.spec.Options = make([]AccordOption, maxAccordOptions)
		for i := 0; i < maxAccordOptions; i++ {
			sf.fx.spec.Options[i] = AccordOption{
				ID:       fmt.Sprintf("opt-%02d", i),
				Title:    fmt.Sprintf("Option %d", i),
				Priority: uint32(i + 1),
				Binding:  OptionBinding{Kind: BindingDisposition, Disposition: "hold", ActionHash: Hash(fmt.Sprintf("act-%d", i))},
			}
		}
		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		castSealedVote(t, a, sf.fx.sre, "sre-vote", 2, "v-32", map[string]BallotPosition{"opt-17": BallotApprove}, "pick-17")
		finalHead := resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res-32")
		if a.View().Outcome.WinningOptionID != "opt-17" {
			t.Fatalf("unexpected 32-option winner: %+v", a.View().Outcome)
		}
		if _, err := VerifyAccordBundle(a.Bundle(), a.View().ID, finalHead); err != nil {
			t.Fatalf("VerifyAccordBundle(32 options): %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Surface 2: SQL Checkpoint Stores (Cross-namespace, Cross-ID, Cache, Races)
// ---------------------------------------------------------------------------

func TestV210Adversarial_SQLCrossNamespaceAndCrossIDTransplants(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		db, backing := newTestSQLDB(t, dialect)
		key := randomTestKey(t)

		protoStore, err := OpenSQLProtocolStore(ctx, db, dialect, "protocol", key)
		if err != nil {
			t.Fatal(err)
		}
		accordStore, err := OpenSQLAccordStore(ctx, db, dialect, "accord", key)
		if err != nil {
			t.Fatal(err)
		}
		goalStore, err := OpenSQLGoalStore(ctx, db, dialect, "goal", key)
		if err != nil {
			t.Fatal(err)
		}
		coordStore, err := OpenSQLCoordinationStore(ctx, db, dialect, "coordination", key, goalStore, protoStore)
		if err != nil {
			t.Fatal(err)
		}
		contractStore, err := OpenSQLStore(ctx, db, dialect, "contract", key)
		if err != nil {
			t.Fatal(err)
		}

		// Create a genuine protocol record in "protocol" namespace.
		pf := newProtocolFixture(t)
		pid, err := protoStore.Create(pf.spec)
		if err != nil {
			t.Fatal(err)
		}
		ver, protoRow, ok := backing.rawRow("protocol", pid)
		if !ok {
			t.Fatal("missing protocol row")
		}

		// 1. Copy encrypted protocol row verbatim into accord, coordination, goal, and contract namespaces (same key, same id).
		backing.setRawRow("accord", pid, ver, protoRow)
		if _, err := accordStore.View(pid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("protocol->accord transplant got %v, want ErrCorruptStore", err)
		}
		backing.setRawRow("coordination", pid, ver, protoRow)
		if _, err := coordStore.Current(Hash("g"), pid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("protocol->coordination transplant got %v, want ErrCorruptStore", err)
		}
		backing.setRawRow("goal", pid, ver, protoRow)
		if _, err := goalStore.View(pid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("protocol->goal transplant got %v, want ErrCorruptStore", err)
		}
		backing.setRawRow("contract", pid, ver, protoRow)
		if _, err := contractStore.View(pid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("protocol->contract transplant got %v, want ErrCorruptStore", err)
		}

		// 2. Copy encrypted accord row into protocol & coordination namespaces.
		fx := newAccordFixture(t)
		aid, err := accordStore.Create(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		aVer, accordRow, ok := backing.rawRow("accord", aid)
		if !ok {
			t.Fatal("missing accord row")
		}
		backing.setRawRow("protocol", aid, aVer, accordRow)
		if _, err := protoStore.View(aid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("accord->protocol transplant got %v, want ErrCorruptStore", err)
		}
		backing.setRawRow("coordination", aid, aVer, accordRow)
		if _, err := coordStore.Current(Hash("g"), aid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("accord->coordination transplant got %v, want ErrCorruptStore", err)
		}

		// 3. Cross-ID row transplant within the same namespace (protocol, accord, goal).
		otherID := Hash("transplanted-other-id")
		backing.setRawRow("protocol", otherID, ver, protoRow)
		if _, err := protoStore.View(otherID); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("protocol cross-ID transplant got %v, want ErrCorruptStore", err)
		}
		backing.setRawRow("accord", otherID, aVer, accordRow)
		if _, err := accordStore.View(otherID); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("accord cross-ID transplant got %v, want ErrCorruptStore", err)
		}
		owner := protocolPublic(pf.owner)
		gid, err := goalStore.Create(GoalSpec{
			Nonce: "xid-goal", Purpose: "Cross-ID goal test",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		gVer, goalRow, ok := backing.rawRow("goal", gid)
		if !ok {
			t.Fatal("missing goal row")
		}
		backing.setRawRow("goal", otherID, gVer, goalRow)
		if _, err := goalStore.View(otherID); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("goal cross-ID transplant got %v, want ErrCorruptStore", err)
		}
	})
}

// Regression test for Defect #2: GoalStore.Task & GoalStore.Gate authenticate current
// checkpoint bytes before serving cached entries, catching in-place SQL corruption
// while still hitting cache (skipping replay) on valid warm reads!
func TestV210Adversarial_SQLGoalStoreAuthenticatedWarmCache(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		key := randomTestKey(t)

		goalsA, err := OpenSQLGoalStore(ctx, dbA, dialect, "goals", key)
		if err != nil {
			t.Fatal(err)
		}
		attemptsA, err := OpenSQLProtocolStore(ctx, dbA, dialect, "attempts", key)
		if err != nil {
			t.Fatal(err)
		}
		goalsB, err := OpenSQLGoalStore(ctx, dbB, dialect, "goals", key)
		if err != nil {
			t.Fatal(err)
		}
		attemptsB, err := OpenSQLProtocolStore(ctx, dbB, dialect, "attempts", key)
		if err != nil {
			t.Fatal(err)
		}
		tasksB, err := OpenSQLCoordinationStore(ctx, dbB, dialect, "tasks", key, goalsB, attemptsB)
		if err != nil {
			t.Fatal(err)
		}
		_ = attemptsA

		pf := newProtocolFixture(t)
		owner := protocolPublic(pf.owner)
		goalID, err := goalsA.Create(GoalSpec{
			Nonce: "goal-auth-cache", Purpose: "Test GoalStore authenticated warm cache",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		fx := newAccordFixture(t)
		gate1 := AccordGate{ID: "g1", GoalID: goalID, AccordID: fx.spec.ID(), Purpose: "Gate 1"}
		task1 := makeBranchTask(goalID, "t1", pf, owner, nil, TaskGateDependency{
			GateID: "g1", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout",
		})
		rev1 := PlanRevision{
			GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1",
			Gates: []AccordGate{gate1}, Tasks: []TaskSpec{task1},
		}
		head1, err := goalsA.Apply(rev1, Sign(pf.owner, PlanSignatureDomain, rev1))
		if err != nil {
			t.Fatal(err)
		}

		// Warm Pod B cache on Task + Gate and verify warm cache hits authenticate without replay.
		if _, err := goalsB.Task(goalID, task1.ID()); err != nil {
			t.Fatal(err)
		}
		before := goalsB.Stats()
		if _, err := goalsB.Gate(goalID, "g1"); err != nil {
			t.Fatal(err)
		}
		after := goalsB.Stats()
		if after.CacheHits != before.CacheHits+1 || after.AuthDecryptOps != before.AuthDecryptOps+1 || after.ReplayValidationOps != before.ReplayValidationOps {
			t.Fatalf("expected authenticated GoalStore cache hit without replay: before=%+v after=%+v", before, after)
		}

		// Pod A appends rev2 with gate2 & task2 -> Pod B immediately sees them (cache miss on bumped SQL version).
		gate2 := AccordGate{ID: "g2", GoalID: goalID, AccordID: fx.spec.ID(), Purpose: "Gate 2"}
		task2 := makeBranchTask(goalID, "t2", pf, owner, nil, TaskGateDependency{
			GateID: "g2", RequiredPhase: AccordPhaseExpired,
		})
		rev2 := PlanRevision{
			GoalID: goalID, Head: head1, Planner: owner.ID(), RequestID: "r2",
			Gates: []AccordGate{gate2}, Tasks: []TaskSpec{task2},
		}
		if _, err := goalsA.Apply(rev2, Sign(pf.owner, PlanSignatureDomain, rev2)); err != nil {
			t.Fatal(err)
		}
		if _, err := goalsB.Gate(goalID, "g2"); err != nil {
			t.Fatalf("Pod B Gate(g2) after Pod A rev2: %v", err)
		}
		if _, err := goalsB.Task(goalID, task2.ID()); err != nil {
			t.Fatalf("Pod B Task(t2) after Pod A rev2: %v", err)
		}

		// Corrupt SQL row in-place at the SAME SQL version while Pod B's cache is warm!
		origVer, origPayload, ok := backing.rawRow("goals", goalID)
		if !ok {
			t.Fatal("missing goals SQL row")
		}
		tampered := bytes.Clone(origPayload)
		tampered[len(tampered)-1] ^= 0xff
		backing.setRawRow("goals", goalID, origVer, tampered)

		if _, err := goalsB.View(goalID); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("GoalStore.View on corrupt row got %v, want ErrCorruptStore", err)
		}
		if _, err := goalsB.Task(goalID, task1.ID()); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("GoalStore.Task on corrupt row (warm cache) got %v, want ErrCorruptStore", err)
		}
		if _, err := goalsB.Gate(goalID, "g1"); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("GoalStore.Gate on corrupt row (warm cache) got %v, want ErrCorruptStore", err)
		}
		if _, err := tasksB.GateStatus(goalID, "g1"); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("CoordinationStore.GateStatus on corrupt GoalStore row got %v, want ErrCorruptStore", err)
		}
		sp, rq, sg := makeClaimForTask(t, pf, goalID, task1, "claim-corrupt-goal", 1, 50)
		if _, err := tasksB.Claim(rq, sg, sp, 11); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("CoordinationStore.Claim on corrupt GoalStore row got %v, want ErrCorruptStore", err)
		}

		// Restore row -> recovery succeeds cleanly.
		backing.setRawRow("goals", goalID, origVer, origPayload)
		if _, err := goalsB.Gate(goalID, "g1"); err != nil {
			t.Fatalf("GoalStore.Gate recovery after restore failed: %v", err)
		}
	})
}

func TestV210Adversarial_SQLWarmCacheSameVersionReencryptedMutation(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		key := randomTestKey(t)

		// Even if an attacker re-encrypts DIFFERENT corrupt plaintext with the SAME key
		// and restores the EXACT SAME SQL version number, warm caches on ProtocolStore,
		// AccordStore, GoalStore, and CoordinationStore (task + gate) detect plainDigest
		// mismatch and fail closed with ErrCorruptStore!
		accA, _ := OpenSQLAccordStore(ctx, dbA, dialect, "acc-plain", key)
		accB, _ := OpenSQLAccordStore(ctx, dbB, dialect, "acc-plain", key)
		fx := newAccordFixture(t)
		aid, err := accA.Create(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accB.View(aid); err != nil {
			t.Fatal(err)
		}
		origVer, _, ok := backing.rawRow("acc-plain", aid)
		if !ok {
			t.Fatal("missing accord row")
		}
		if err := accA.store.withLocked(aid, func(tx checkpointTx) error {
			return accA.store.writeWith(tx, aid, storedAccord{Version: accordStoreVersion, Head: Hash("corrupt-head")})
		}); err != nil {
			t.Fatal(err)
		}
		_, badPayload, _ := backing.rawRow("acc-plain", aid)
		backing.setRawRow("acc-plain", aid, origVer, badPayload)
		if _, err := accB.View(aid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("AccordStore warm cache did not detect same-version re-encrypted corrupt payload: %v", err)
		}

		// Same attack on ProtocolStore warm cache.
		protoA, _ := OpenSQLProtocolStore(ctx, dbA, dialect, "proto-plain", key)
		protoB, _ := OpenSQLProtocolStore(ctx, dbB, dialect, "proto-plain", key)
		pf := newProtocolFixture(t)
		pid, err := protoA.Create(pf.spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := protoB.View(pid); err != nil {
			t.Fatal(err)
		}
		pOrigVer, _, _ := backing.rawRow("proto-plain", pid)
		if err := protoA.store.withLocked(pid, func(tx checkpointTx) error {
			return protoA.store.writeWith(tx, pid, storedProtocol{Version: protocolStoreVersion, Head: Hash("corrupt-proto")})
		}); err != nil {
			t.Fatal(err)
		}
		_, badProtoPayload, _ := backing.rawRow("proto-plain", pid)
		backing.setRawRow("proto-plain", pid, pOrigVer, badProtoPayload)
		if _, err := protoB.View(pid); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("ProtocolStore warm cache did not detect same-version re-encrypted corrupt payload: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Surface 3: AccordGate Conditional DAGs & Fail-Closed Consistency
// ---------------------------------------------------------------------------

// Regression test for Defect #1: DiscoverGoal, GateStatus, Claim, and RecordAccord
// ALL fail closed with ErrCorruptStore on mismatched AccordID, disallowed WinningOptionID,
// invalid TaskGateDependency, and dangling gate references.
func TestV210Adversarial_GateCheckpointFailClosedConsistency(t *testing.T) {
	_, _, goals, _, tasks, accords := gateTestStores(t)
	pf := newProtocolFixture(t)
	owner := protocolPublic(pf.owner)
	fx := newAccordFixture(t)
	pinnedAccordID := fx.spec.ID()

	goalID, err := goals.Create(GoalSpec{
		Nonce: "defect1-gate-consistency", Purpose: "Verify gate checkpoint AccordID & AllowedOptions fail-closed",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	gate := AccordGate{
		ID:             "release-gate",
		GoalID:         goalID,
		AccordID:       pinnedAccordID,
		Purpose:        "Pinned release gate",
		AllowedOptions: []string{"canary-rollout", "full-rollout"},
	}
	canaryCommit := fx.spec.Options[1].Binding.Commitment()
	canaryTask := makeBranchTask(goalID, "canary-task", pf, owner, nil, TaskGateDependency{
		GateID:             "release-gate",
		RequiredPhase:      AccordPhaseDecided,
		OptionID:           "canary-rollout",
		ExpectedCommitment: canaryCommit,
	})
	rev := PlanRevision{
		GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1",
		Gates: []AccordGate{gate}, Tasks: []TaskSpec{canaryTask},
	}
	if _, err := goals.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}
	honestHead, honestBundle := driveAccordInStore(t, accords, fx, "canary-rollout", nil, accordActor{})
	gateKey := gateRecordKey(goalID, "release-gate")

	// Case A: Persisted gateCheckpoint has mismatched AccordID -> ALL 4 entrypoints return ErrCorruptStore!
	badAccordCP := gateCheckpoint{
		Version: gateCheckpointVersion,
		Resolution: GateResolution{
			GoalID:            goalID,
			GateID:            "release-gate",
			AccordID:          Hash("rogue-unpinned-accord"),
			Head:              Hash("rogue-head"),
			Phase:             AccordPhaseDecided,
			WinningOptionID:   "canary-rollout",
			WinningCommitment: canaryCommit,
			OutcomeHash:       Hash("rogue-outcome"),
			ResolvedAtHeight:  10,
		},
	}
	if err := tasks.store.write(gateKey, badAccordCP); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("DiscoverGoal on mismatched AccordID got %v, want ErrCorruptStore", err)
	}
	if _, err := tasks.GateStatus(goalID, "release-gate"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("GateStatus on mismatched AccordID got %v, want ErrCorruptStore", err)
	}
	sp, rq, sg := makeClaimForTask(t, pf, goalID, canaryTask, "claim-rogue-gate", 1, 50)
	if _, err := tasks.Claim(rq, sg, sp, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("Claim on mismatched AccordID got %v, want ErrCorruptStore", err)
	}
	if _, err := tasks.RecordAccord(goalID, "release-gate", honestBundle, honestHead); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("RecordAccord on mismatched AccordID got %v, want ErrCorruptStore", err)
	}

	// Case B: Persisted gateCheckpoint has pinned AccordID but WinningOptionID outside gate.AllowedOptions -> ALL 4 return ErrCorruptStore!
	disallowedCP := gateCheckpoint{
		Version: gateCheckpointVersion,
		Resolution: GateResolution{
			GoalID:            goalID,
			GateID:            "release-gate",
			AccordID:          pinnedAccordID,
			Head:              Hash("disallowed-head"),
			Phase:             AccordPhaseDecided,
			WinningOptionID:   "hold-release", // NOT in AllowedOptions!
			WinningCommitment: fx.spec.Options[2].Binding.Commitment(),
			OutcomeHash:       Hash("disallowed-outcome"),
			ResolvedAtHeight:  10,
		},
	}
	if err := tasks.store.write(gateKey, disallowedCP); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("DiscoverGoal on disallowed WinningOptionID got %v, want ErrCorruptStore", err)
	}
	if _, err := tasks.GateStatus(goalID, "release-gate"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("GateStatus on disallowed WinningOptionID got %v, want ErrCorruptStore", err)
	}
	if _, err := tasks.Claim(rq, sg, sp, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("Claim on disallowed WinningOptionID got %v, want ErrCorruptStore", err)
	}
	if _, err := tasks.RecordAccord(goalID, "release-gate", honestBundle, honestHead); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("RecordAccord on disallowed WinningOptionID got %v, want ErrCorruptStore", err)
	}

	// Case C: Tampered goalRecord with invalid TaskGateDependency (RequiredPhase="open") -> DiscoverGoal returns ErrCorruptStore!
	_ = os.Remove(tasks.store.path(gateKey))
	rawGoal, err := goals.store.readEncrypted(goalID)
	if err != nil {
		t.Fatal(err)
	}
	var gr goalRecord
	if err := json.Unmarshal(rawGoal, &gr); err != nil {
		t.Fatal(err)
	}
	gr.Plan.Revisions[0].Revision.Tasks[0].GateDependencies[0].RequiredPhase = AccordPhaseOpen
	if err := goals.store.write(goalID, gr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("DiscoverGoal on invalid persisted TaskGateDependency got %v, want ErrCorruptStore", err)
	}
}

func TestV210Adversarial_AccordGateCorruptPlanAndSwappedCheckpoints(t *testing.T) {
	_, _, goals, _, tasks, accords := gateTestStores(t)
	pf := newProtocolFixture(t)
	owner := protocolPublic(pf.owner)
	fx := newAccordFixture(t)
	accordID := fx.spec.ID()

	goalID, err := goals.Create(GoalSpec{
		Nonce: "gate-corrupt-matrix", Purpose: "Verify DiscoverGoal fail-closed on swapped/corrupt checkpoints",
		ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
	})
	if err != nil {
		t.Fatal(err)
	}
	gate1 := AccordGate{ID: "gate-1", GoalID: goalID, AccordID: accordID, Purpose: "Gate 1", AllowedOptions: []string{"canary-rollout"}}
	gate2 := AccordGate{ID: "gate-2", GoalID: goalID, AccordID: accordID, Purpose: "Gate 2", AllowedOptions: []string{"canary-rollout"}}
	task1 := makeBranchTask(goalID, "task-multi-gate", pf, owner, nil,
		TaskGateDependency{GateID: "gate-1", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout"},
		TaskGateDependency{GateID: "gate-2", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout"},
	)
	rev := PlanRevision{
		GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1",
		Gates: []AccordGate{gate1, gate2}, Tasks: []TaskSpec{task1},
	}
	if _, err := goals.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev)); err != nil {
		t.Fatal(err)
	}

	// Resolve gate-1 only -> multi-gate task still blocked (ErrTaskDependency).
	winHead, winBundle := driveAccordInStore(t, accords, fx, "canary-rollout", nil, accordActor{})
	if _, err := tasks.RecordAccord(goalID, "gate-1", winBundle, winHead); err != nil {
		t.Fatal(err)
	}
	sp, rq, sg := makeClaimForTask(t, pf, goalID, task1, "multi-claim-1", 1, 50)
	if _, err := tasks.Claim(rq, sg, sp, 11); !errors.Is(err, ErrTaskDependency) {
		t.Fatalf("Claim with 1/2 gates resolved got %v, want ErrTaskDependency", err)
	}

	// Copy raw encrypted file from gate-1 key to gate-2 key -> AEAD AAD mismatch -> ErrCorruptStore!
	key1 := gateRecordKey(goalID, "gate-1")
	key2 := gateRecordKey(goalID, "gate-2")
	raw1, err := os.ReadFile(tasks.store.path(key1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tasks.store.path(key2), raw1, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("swapped gate record file got %v, want ErrCorruptStore", err)
	}
	if _, err := tasks.GateStatus(goalID, "gate-2"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("GateStatus on swapped gate file got %v, want ErrCorruptStore", err)
	}

	// Re-encrypt gate-1's checkpoint JSON under gate-2's key (AAD passes, GateID mismatch -> ErrCorruptStore!).
	res1, err := tasks.GateStatus(goalID, "gate-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := tasks.store.write(key2, gateCheckpoint{Version: gateCheckpointVersion, Resolution: res1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("re-encrypted mismatched GateID checkpoint got %v, want ErrCorruptStore", err)
	}
	if _, err := tasks.GateStatus(goalID, "gate-2"); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("GateStatus on mismatched GateID checkpoint got %v, want ErrCorruptStore", err)
	}

	// Clean up gate-2, record validly, and verify multi-gate Claim now succeeds!
	if err := os.Remove(tasks.store.path(key2)); err != nil {
		t.Fatal(err)
	}
	if _, err := tasks.RecordAccord(goalID, "gate-2", winBundle, winHead); err != nil {
		t.Fatal(err)
	}
	if _, err := tasks.Claim(rq, sg, sp, 11); err != nil {
		t.Fatalf("Claim after both gates resolved failed: %v", err)
	}

	// Swap task checkpoint JSON into gate-2's key -> ErrCorruptStore!
	rawTask, err := tasks.store.readEncrypted(task1.ID())
	if err != nil {
		t.Fatal(err)
	}
	var tcp taskCheckpoint
	if err := json.Unmarshal(rawTask, &tcp); err != nil {
		t.Fatal(err)
	}
	if err := tasks.store.write(key2, tcp); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("task checkpoint written to gate key got %v, want ErrCorruptStore", err)
	}
	// Restore gate-2 validly before testing undeclared gate ref in goalRecord.
	if err := os.Remove(tasks.store.path(key2)); err != nil {
		t.Fatal(err)
	}
	if _, err := tasks.RecordAccord(goalID, "gate-2", winBundle, winHead); err != nil {
		t.Fatal(err)
	}

	// Tamper goalRecord on disk to reference an undeclared gate -> DiscoverGoal returns ErrCorruptStore!
	rawGoal, err := goals.store.readEncrypted(goalID)
	if err != nil {
		t.Fatal(err)
	}
	var gr goalRecord
	if err := json.Unmarshal(rawGoal, &gr); err != nil {
		t.Fatal(err)
	}
	gr.Plan.Revisions[0].Revision.Tasks[0].GateDependencies = append(
		gr.Plan.Revisions[0].Revision.Tasks[0].GateDependencies,
		TaskGateDependency{GateID: "ghost-gate", RequiredPhase: AccordPhaseExpired},
	)
	if err := goals.store.write(goalID, gr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tasks.DiscoverGoal(goalID, 11); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("DiscoverGoal on undeclared gate reference got %v, want ErrCorruptStore", err)
	}
}

func TestV210Adversarial_SQLMultiPodSealedAccordAndGateRace(t *testing.T) {
	sharedKey, err := NewSealedTallyKey(1024)
	if err != nil {
		t.Fatal(err)
	}

	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		if dialect == SQLDialectSQLite {
			dbA.SetMaxOpenConns(1)
			dbB.SetMaxOpenConns(1)
		}
		key := randomTestKey(t)

		goalsA, _ := OpenSQLGoalStore(ctx, dbA, dialect, "adv-goals", key)
		attemptsA, _ := OpenSQLProtocolStore(ctx, dbA, dialect, "adv-attempts", key)
		tasksA, _ := OpenSQLCoordinationStore(ctx, dbA, dialect, "adv-tasks", key, goalsA, attemptsA)
		accordsA, _ := OpenSQLAccordStore(ctx, dbA, dialect, "adv-accords", key)

		goalsB, _ := OpenSQLGoalStore(ctx, dbB, dialect, "adv-goals", key)
		attemptsB, _ := OpenSQLProtocolStore(ctx, dbB, dialect, "adv-attempts", key)
		tasksB, _ := OpenSQLCoordinationStore(ctx, dbB, dialect, "adv-tasks", key, goalsB, attemptsB)
		accordsB, _ := OpenSQLAccordStore(ctx, dbB, dialect, "adv-accords", key)

		sf := newSealedAccordFixture(t, sharedKey)
		aid, err := accordsA.Create(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := accordsB.View(aid); err != nil {
			t.Fatal(err)
		}
		castOn := func(st *AccordStore, actor accordActor, grant, reqID string, h uint64, choices map[string]BallotPosition) {
			b, err := st.Export(aid)
			if err != nil {
				t.Fatal(err)
			}
			sb, err := EncryptSealedBallot(b.Spec, aid, actor.pub.ID(), choices, Hash(reqID))
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := st.Prepare(aid, actor.pub.ID(), grant, sf.fx.spec.Scope, "vote", reqID, h)
			if err != nil {
				t.Fatal(err)
			}
			cmd.Vote = &VotePayload{Sealed: sb}
			sig, err := SignAccordCommand(actor.id, cmd)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Apply(aid, cmd, sig, h); err != nil {
				t.Fatalf("Apply(%s): %v", reqID, err)
			}
		}
		castOn(accordsA, sf.fx.safety, "safety-vote", "sv1", 2, map[string]BallotPosition{"canary-rollout": BallotApprove})
		castOn(accordsB, sf.fx.sre, "sre-vote", "sv2", 3, map[string]BallotPosition{"canary-rollout": BallotApprove})
		castOn(accordsA, sf.fx.security, "security-vote", "sv3", 4, map[string]BallotPosition{"canary-rollout": BallotApprove})

		expB, err := accordsB.Export(aid)
		if err != nil {
			t.Fatal(err)
		}
		tallyProof, err := sharedKey.TallyAccord(expB)
		if err != nil {
			t.Fatal(err)
		}
		resCmd, err := accordsB.Prepare(aid, sf.tally.pub.ID(), "tally-resolve", sf.fx.spec.Scope, "resolve", "sres", 10)
		if err != nil {
			t.Fatal(err)
		}
		resCmd.Resolve = &ResolvePayload{ReasonHash: Hash("sealed-sql"), SealedTally: tallyProof}
		resSig, err := SignAccordCommand(sf.tally.id, resCmd)
		if err != nil {
			t.Fatal(err)
		}
		finalHead, err := accordsB.Apply(aid, resCmd, resSig, 10)
		if err != nil {
			t.Fatal(err)
		}
		vA, err := accordsA.View(aid)
		if err != nil || vA.Phase != AccordPhaseDecided || vA.Head != finalHead {
			t.Fatalf("Pod A stale sealed accord view: %+v err=%v", vA, err)
		}
		bundle, err := accordsA.Export(aid)
		if err != nil {
			t.Fatal(err)
		}

		pf := newProtocolFixture(t)
		owner := protocolPublic(pf.owner)
		goalID, err := goalsA.Create(GoalSpec{
			Nonce: "sql-sealed-dag-race", Purpose: "Multi-pod sealed gate race",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		})
		if err != nil {
			t.Fatal(err)
		}
		gate := AccordGate{ID: "sealed-gate", GoalID: goalID, AccordID: aid, Purpose: "Sealed gate", AllowedOptions: []string{"canary-rollout", "full-rollout"}}
		canTask := makeBranchTask(goalID, "can", pf, owner, nil, TaskGateDependency{
			GateID: "sealed-gate", RequiredPhase: AccordPhaseDecided, OptionID: "canary-rollout",
			ExpectedCommitment: sf.fx.spec.Options[1].Binding.Commitment(),
		})
		rev := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "r1", Gates: []AccordGate{gate}, Tasks: []TaskSpec{canTask}}
		if _, err := goalsA.Apply(rev, Sign(pf.owner, PlanSignatureDomain, rev)); err != nil {
			t.Fatal(err)
		}

		// Warm Pod B gate & task caches before RecordAccord, then record on Pod A and race 6 pods!
		if _, _, err := tasksB.DiscoverGoal(goalID, 11); err != nil {
			t.Fatal(err)
		}
		if _, err := tasksA.RecordAccord(goalID, "sealed-gate", bundle, finalHead); err != nil {
			t.Fatal(err)
		}
		discB, _, err := tasksB.DiscoverGoal(goalID, 11)
		if err != nil || len(discB) != 1 || !discB[0].GatesReady {
			t.Fatalf("Pod B warm cache did not observe Pod A RecordAccord: %+v err=%v", discB, err)
		}

		const workers = 6
		var wg sync.WaitGroup
		start := make(chan struct{})
		claimErrs := make(chan error, workers)
		for i := 0; i < workers; i++ {
			peerDB := openPeerSQLDB(t, backing)
			if dialect == SQLDialectSQLite {
				peerDB.SetMaxOpenConns(1)
			}
			gP, _ := OpenSQLGoalStore(ctx, peerDB, dialect, "adv-goals", key)
			aP, _ := OpenSQLProtocolStore(ctx, peerDB, dialect, "adv-attempts", key)
			tP, _ := OpenSQLCoordinationStore(ctx, peerDB, dialect, "adv-tasks", key, gP, aP)
			sp, rq, sg := makeClaimForTask(t, pf, goalID, canTask, fmt.Sprintf("race-c-%d", i), 1, 50)
			wg.Add(1)
			go func(cs *CoordinationStore, r ClaimRequest, s []byte, p ProtocolSpec) {
				defer wg.Done()
				<-start
				_, _, _ = cs.DiscoverGoal(goalID, 11)
				_, _ = cs.GateStatus(goalID, "sealed-gate")
				_, err := cs.Claim(r, s, p, 11)
				claimErrs <- err
			}(tP, rq, sg, sp)
		}
		close(start)
		wg.Wait()
		close(claimErrs)

		wins, stales := 0, 0
		for err := range claimErrs {
			if err == nil {
				wins++
			} else if errors.Is(err, ErrTaskStale) {
				stales++
			} else {
				t.Fatalf("unexpected concurrent gated Claim error: %v", err)
			}
		}
		if wins != 1 || stales != workers-1 {
			t.Fatalf("concurrent gated Claim race: wins=%d stales=%d want 1/%d", wins, stales, workers-1)
		}
	})
}
