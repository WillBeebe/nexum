package he

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
)

func TestORProofHonestAndPublicKeyOnly(t *testing.T) {
	priv, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := FromPublic(priv.N().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	domain := []byte("accord-1|voter-1|opt-a|approve")
	for _, bit := range []int{0, 1} {
		ct, r, err := pub.EncryptBitWithR(bit)
		if err != nil {
			t.Fatalf("EncryptBitWithR(%d): %v", bit, err)
		}
		proof, err := pub.ProveBit(new(big.Int).SetBytes(ct), r, bit, domain)
		if err != nil {
			t.Fatalf("ProveBit(%d): %v", bit, err)
		}
		if err := pub.VerifyBit(ct, proof, domain); err != nil {
			t.Fatalf("VerifyBit(%d): %v", bit, err)
		}
		dec, err := priv.Decrypt(ct)
		if err != nil || dec.Int64() != int64(bit) {
			t.Fatalf("Decrypt(%d) = %v, %v", bit, dec, err)
		}
	}

	// Wrong claimed bit or invalid bit fails in both EncryptBitWithR and ProveBit.
	if _, _, err := pub.EncryptBitWithR(2); err == nil {
		t.Fatal("EncryptBitWithR accepted bit=2")
	}
	if _, _, err := pub.EncryptBitWithR(-1); err == nil {
		t.Fatal("EncryptBitWithR accepted bit=-1")
	}
	ct0, r0, err := pub.EncryptBitWithR(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pub.ProveBit(new(big.Int).SetBytes(ct0), r0, 1, domain); err == nil {
		t.Fatal("ProveBit accepted mismatched bit=1 for bit=0 ciphertext")
	}
}

func TestORProofRejectsNonBitsNonUnitsMalleationAndDomainReplay(t *testing.T) {
	priv, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := FromPublic(priv.N().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("accord-1|voter-1|opt-a|approve")

	// Encrypt 2 (e.g. approve+dissent=2) — ProveBit must reject and forged proof must fail.
	rA := big.NewInt(11)
	rD := big.NewInt(17)
	ctA, err := pub.EncryptWithR(big.NewInt(1), rA)
	if err != nil {
		t.Fatal(err)
	}
	ctD, err := pub.EncryptWithR(big.NewInt(1), rD)
	if err != nil {
		t.Fatal(err)
	}
	ctSum, err := pub.Add(ctA, ctD)
	if err != nil {
		t.Fatal(err)
	}
	rProd := pub.MulUnits(rA, rD)
	for _, claimed := range []int{0, 1, 2} {
		if _, err := pub.ProveBit(new(big.Int).SetBytes(ctSum), rProd, claimed, domain); err == nil {
			t.Fatalf("ProveBit succeeded on sum=2 for claimed=%d", claimed)
		}
	}

	// Valid proof fails on different domain, tampered ciphertext, or tampered proof fields.
	ct1, r1, err := pub.EncryptBitWithR(1)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := pub.ProveBit(new(big.Int).SetBytes(ct1), r1, 1, domain)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.VerifyBit(ct1, proof, []byte("accord-1|voter-2|opt-a|approve")); err == nil {
		t.Fatal("VerifyBit accepted cross-domain replay")
	}

	// Non-canonical leading-zero ciphertext and non-units rejected.
	if err := pub.VerifyBit(append([]byte{0}, ct1...), proof, domain); err == nil {
		t.Fatal("VerifyBit accepted leading-zero ciphertext")
	}
	for _, badCT := range [][]byte{nil, {}, {0}, priv.N().Bytes(), priv.n2.Bytes()} {
		if err := pub.VerifyBit(badCT, proof, domain); err == nil {
			t.Fatalf("VerifyBit accepted bad ciphertext %x", badCT)
		}
	}

	var pf bitORProof
	if err := json.Unmarshal(proof, &pf); err != nil {
		t.Fatal(err)
	}
	malformed := []struct {
		name string
		raw  []byte
	}{
		{"leading_space", append([]byte{' '}, proof...)},
		{"trailing_space", append(bytes.Clone(proof), ' ')},
		{"trailing_obj", append(bytes.Clone(proof), []byte("{}")...)},
		{"unknown_field", func() []byte {
			b, _ := json.Marshal(struct {
				bitORProof
				Extra string `json:"extra"`
			}{bitORProof: pf, Extra: "x"})
			return b
		}()},
		{"leading_zero_a0", func() []byte {
			c := pf
			c.A0 = append([]byte{0}, pf.A0...)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"leading_zero_a1", func() []byte {
			c := pf
			c.A1 = append([]byte{0}, pf.A1...)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"leading_zero_z0", func() []byte {
			c := pf
			c.Z0 = append([]byte{0}, pf.Z0...)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"leading_zero_z1", func() []byte {
			c := pf
			c.Z1 = append([]byte{0}, pf.Z1...)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"nonunit_a0_modulus", func() []byte {
			c := pf
			c.A0 = priv.N().Bytes()
			b, _ := json.Marshal(c)
			return b
		}()},
		{"nonunit_z0_zero", func() []byte {
			c := pf
			c.Z0 = []byte{0}
			b, _ := json.Marshal(c)
			return b
		}()},
		{"short_e0", func() []byte {
			c := pf
			c.E0 = pf.E0[:31]
			b, _ := json.Marshal(c)
			return b
		}()},
		{"long_e1", func() []byte {
			c := pf
			c.E1 = append(bytes.Clone(pf.E1), 0x01)
			b, _ := json.Marshal(c)
			return b
		}()},
		{"flipped_e0", func() []byte {
			c := pf
			c.E0 = bytes.Clone(pf.E0)
			c.E0[0] ^= 0x01
			b, _ := json.Marshal(c)
			return b
		}()},
	}
	for _, tc := range malformed {
		if err := pub.VerifyBit(ct1, tc.raw, domain); err == nil {
			t.Fatalf("VerifyBit accepted malformed proof %s", tc.name)
		}
	}

	// Length-framing collision test on bitORChallenge.
	c1 := bitORChallenge(priv.n, []byte("ab"), []byte("cd"), pf.A0, pf.A1)
	c2 := bitORChallenge(priv.n, []byte("a"), []byte("bcd"), pf.A0, pf.A1)
	if c1 == c2 {
		t.Fatal("bitORChallenge collided across (domain, ct) boundary")
	}
}

func TestScaleAndDecryptAndProve(t *testing.T) {
	priv, err := NewPaillier(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := FromPublic(priv.N().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	ct1, _, err := pub.EncryptBitWithR(1)
	if err != nil {
		t.Fatal(err)
	}
	ct0, _, err := pub.EncryptBitWithR(0)
	if err != nil {
		t.Fatal(err)
	}

	// Scale by 0 -> canonical []byte{1} (E(0)).
	zeroScaled, err := pub.Scale(ct1, 0)
	if err != nil {
		t.Fatalf("Scale(0): %v", err)
	}
	if !bytes.Equal(zeroScaled, []byte{1}) {
		t.Fatalf("Scale(0) = %x, want [01]", zeroScaled)
	}

	// Weighted sum: 7*1 + 5*0 = 7.
	s1, err := pub.Scale(ct1, 7)
	if err != nil {
		t.Fatal(err)
	}
	s0, err := pub.Scale(ct0, 5)
	if err != nil {
		t.Fatal(err)
	}
	agg, err := pub.Add(s1, s0)
	if err != nil {
		t.Fatal(err)
	}
	m, eqProof, err := priv.DecryptAndProve(agg)
	if err != nil {
		t.Fatalf("DecryptAndProve: %v", err)
	}
	if m.Uint64() != 7 {
		t.Fatalf("decrypted weighted sum = %s, want 7", m)
	}
	if ok, err := pub.VerifyEqual(agg, m, eqProof); err != nil || !ok {
		t.Fatalf("VerifyEqual(agg, 7): ok=%v err=%v", ok, err)
	}

	// 0-ballot canonical []byte{1} decrypts & proves 0 cleanly.
	m0, eqProof0, err := priv.DecryptAndProve([]byte{1})
	if err != nil {
		t.Fatalf("DecryptAndProve(1): %v", err)
	}
	if m0.Sign() != 0 {
		t.Fatalf("DecryptAndProve(1) = %s, want 0", m0)
	}
	if ok, err := pub.VerifyEqual([]byte{1}, big.NewInt(0), eqProof0); err != nil || !ok {
		t.Fatalf("VerifyEqual(1, 0): ok=%v err=%v", ok, err)
	}

	// Public-only key cannot DecryptAndProve.
	if _, _, err := pub.DecryptAndProve(agg); err == nil {
		t.Fatal("public-only key succeeded DecryptAndProve")
	}

	// Scale rejects non-canonical / non-unit inputs.
	if _, err := pub.Scale(append([]byte{0}, ct1...), 3); err == nil {
		t.Fatal("Scale accepted leading-zero ct")
	}
	if _, err := pub.Scale(priv.N().Bytes(), 3); err == nil {
		t.Fatal("Scale accepted non-unit N")
	}
}
