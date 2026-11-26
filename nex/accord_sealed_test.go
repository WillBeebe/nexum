package nex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/WillBeebe/nexum/v2/internal/he"
)

type sealedAccordFixture struct {
	fx       accordFixture
	tallyKey *SealedTallyKey
	tally    accordActor
}

func newSealedAccordFixture(t *testing.T, sharedKey *SealedTallyKey) sealedAccordFixture {
	t.Helper()
	fx := newAccordFixture(t)
	tally := newAccordActor(t)
	if sharedKey == nil {
		var err error
		sharedKey, err = NewSealedTallyKey(2048)
		if err != nil {
			t.Fatal(err)
		}
	}
	fx.spec.Participants = append(fx.spec.Participants, tally.pub)
	// Make release/security vote-only unless needed, and give dedicated tally authority resolve permission.
	fx.spec.Roles = []AccordRoleGrant{
		{
			ID: "release-vote", Actor: fx.release.pub.ID(), Scope: fx.spec.Scope,
			DomainRoles: []string{"release"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 2, ExpiresAtHeight: 15, LimitsHash: Hash("release-limits"),
		},
		{
			ID: "sre-vote", Actor: fx.sre.pub.ID(), Scope: fx.spec.Scope,
			DomainRoles: []string{"sre"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 2, ExpiresAtHeight: 15, LimitsHash: Hash("sre-limits"),
		},
		{
			ID: "safety-vote", Actor: fx.safety.pub.ID(), Scope: fx.spec.Scope,
			DomainRoles: []string{"safety"}, Permissions: []AccordPermission{AccordPermitVote, AccordPermitVeto},
			Weight: 2, ExpiresAtHeight: 15, LimitsHash: Hash("safety-limits"),
		},
		{
			ID: "security-vote", Actor: fx.security.pub.ID(), Scope: fx.spec.Scope,
			DomainRoles: []string{"security"}, Permissions: []AccordPermission{AccordPermitVote},
			Weight: 1, ExpiresAtHeight: 15, LimitsHash: Hash("security-limits"),
		},
		{
			ID: "tally-resolve", Actor: tally.pub.ID(), Scope: fx.spec.Scope,
			Permissions: []AccordPermission{AccordPermitResolve}, ExpiresAtHeight: 20, LimitsHash: Hash("tally-limits"),
		},
	}
	fx.spec.Rules.BallotPrivacy = BallotPrivacySealedPaillier
	fx.spec.Rules.RequireIndependentResolver = true
	fx.spec.SealedTally = &SealedTallyConfig{
		PublicKey:      sharedKey.PublicKey(),
		TallyAuthority: tally.pub.ID(),
	}
	return sealedAccordFixture{fx: fx, tallyKey: sharedKey, tally: tally}
}

func castSealedVote(
	t *testing.T,
	a *Accord,
	actor accordActor,
	grant string,
	height uint64,
	reqID string,
	choices map[string]BallotPosition,
	rationale string,
) string {
	t.Helper()
	b := a.Bundle()
	sealed, err := EncryptSealedBallot(b.Spec, a.View().ID, actor.pub.ID(), choices, Hash(rationale))
	if err != nil {
		t.Fatalf("EncryptSealedBallot(%s): %v", reqID, err)
	}
	return accordMustApply(t, a, actor, grant, "vote", reqID, height, func(c *AccordCommand) {
		c.Vote = &VotePayload{Sealed: sealed}
	})
}

func resolveSealedAccord(t *testing.T, a *Accord, tallyKey *SealedTallyKey, tallyActor accordActor, grant string, height uint64, reqID string) string {
	t.Helper()
	proof, err := tallyKey.TallyAccord(a.Bundle())
	if err != nil {
		t.Fatalf("TallyAccord: %v", err)
	}
	return accordMustApply(t, a, tallyActor, grant, "resolve", reqID, height, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("sealed-tally"), SealedTally: proof}
	})
}

func TestV202AccordSpecIDStability(t *testing.T) {
	fx := newAccordFixture(t)
	// Confirm defaults are "" and nil.
	if fx.spec.Rules.BallotPrivacy != "" || fx.spec.SealedTally != nil {
		t.Fatalf("unexpected non-zero defaults: privacy=%q tally=%v", fx.spec.Rules.BallotPrivacy, fx.spec.SealedTally)
	}
	raw, err := json.Marshal(struct {
		Domain string     `json:"domain"`
		Spec   AccordSpec `json:"spec"`
	}{AccordSpecHashDomain, fx.spec})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"ballot_privacy"`)) || bytes.Contains(raw, []byte(`"sealed_tally"`)) {
		t.Fatalf("v2.0.2 AccordSpec JSON unexpectedly serialized sealed fields: %s", raw)
	}

	// Verify exact parity with a legacy struct lacking BallotPrivacy and SealedTally.
	type legacyRules struct {
		BallotMode                 BallotMode        `json:"ballot_mode"`
		MinParticipationCount      uint64            `json:"min_participation_count,omitempty"`
		MinParticipationWeight     uint64            `json:"min_participation_weight,omitempty"`
		MinApprovalCount           uint64            `json:"min_approval_count"`
		MinApprovalWeight          uint64            `json:"min_approval_weight"`
		MinApprovalMarginWeight    uint64            `json:"min_approval_margin_weight,omitempty"`
		MandatoryRoles             []RoleRequirement `json:"mandatory_roles,omitempty"`
		Veto                       VetoPolicy        `json:"veto"`
		TieBreak                   TieBreakPolicy    `json:"tie_break"`
		RequireIndependentResolver bool              `json:"require_independent_resolver,omitempty"`
	}
	type legacySpec struct {
		Version          int               `json:"version"`
		Nonce            string            `json:"nonce"`
		Purpose          string            `json:"purpose"`
		Scope            string            `json:"scope"`
		PolicyHash       string            `json:"policy_hash"`
		Participants     []Public          `json:"participants"`
		Roles            []AccordRoleGrant `json:"roles"`
		Evidence         []EvidenceSlot    `json:"evidence,omitempty"`
		Options          []AccordOption    `json:"options,omitempty"`
		AllowProposals   bool              `json:"allow_proposals,omitempty"`
		ProposalByHeight uint64            `json:"proposal_by_height,omitempty"`
		VoteByHeight     uint64            `json:"vote_by_height"`
		ResolveByHeight  uint64            `json:"resolve_by_height"`
		Rules            legacyRules       `json:"rules"`
		MaxEvents        uint32            `json:"max_events"`
	}
	legacy := legacySpec{
		Version: fx.spec.Version, Nonce: fx.spec.Nonce, Purpose: fx.spec.Purpose, Scope: fx.spec.Scope,
		PolicyHash: fx.spec.PolicyHash, Participants: fx.spec.Participants, Roles: fx.spec.Roles,
		Evidence: fx.spec.Evidence, Options: fx.spec.Options, AllowProposals: fx.spec.AllowProposals,
		ProposalByHeight: fx.spec.ProposalByHeight, VoteByHeight: fx.spec.VoteByHeight,
		ResolveByHeight: fx.spec.ResolveByHeight, MaxEvents: fx.spec.MaxEvents,
		Rules: legacyRules{
			BallotMode: fx.spec.Rules.BallotMode, MinParticipationCount: fx.spec.Rules.MinParticipationCount,
			MinParticipationWeight: fx.spec.Rules.MinParticipationWeight, MinApprovalCount: fx.spec.Rules.MinApprovalCount,
			MinApprovalWeight: fx.spec.Rules.MinApprovalWeight, MinApprovalMarginWeight: fx.spec.Rules.MinApprovalMarginWeight,
			MandatoryRoles: fx.spec.Rules.MandatoryRoles, Veto: fx.spec.Rules.Veto,
			TieBreak: fx.spec.Rules.TieBreak, RequireIndependentResolver: fx.spec.Rules.RequireIndependentResolver,
		},
	}
	legacyID := Hash(struct {
		Domain string     `json:"domain"`
		Spec   legacySpec `json:"spec"`
	}{AccordSpecHashDomain, legacy})
	if fx.spec.ID() != legacyID {
		t.Fatalf("v2.0.2 AccordSpec.ID() drifted: got %s want %s", fx.spec.ID(), legacyID)
	}
}

func TestSealedAccordSpecValidation(t *testing.T) {
	key, err := NewSealedTallyKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("public_rejects_non_nil_sealed_tally", func(t *testing.T) {
		for _, priv := range []BallotPrivacy{"", BallotPrivacyPublic} {
			fx := newAccordFixture(t)
			fx.spec.Rules.BallotPrivacy = priv
			fx.spec.SealedTally = &SealedTallyConfig{
				PublicKey:      key.PublicKey(),
				TallyAuthority: fx.release.pub.ID(),
			}
			if err := fx.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("privacy=%q accepted non-nil SealedTally: %v", priv, err)
			}
		}
	})

	t.Run("invalid_privacy_mode", func(t *testing.T) {
		fx := newAccordFixture(t)
		fx.spec.Rules.BallotPrivacy = "homomorphic_magic"
		if err := fx.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
			t.Fatalf("got %v want ErrAccordSpec", err)
		}
	})

	cases := []struct {
		name   string
		mutate func(*sealedAccordFixture)
	}{
		{"nil_sealed_tally", func(sf *sealedAccordFixture) { sf.fx.spec.SealedTally = nil }},
		{"allow_proposals_true", func(sf *sealedAccordFixture) {
			sf.fx.spec.AllowProposals = true
			sf.fx.spec.ProposalByHeight = 5
		}},
		{"empty_options", func(sf *sealedAccordFixture) { sf.fx.spec.Options = nil }},
		{"weak_public_key_leading_zero", func(sf *sealedAccordFixture) {
			sf.fx.spec.SealedTally.PublicKey = append([]byte{0}, key.PublicKey()...)
		}},
		{"weak_public_key_short", func(sf *sealedAccordFixture) {
			sf.fx.spec.SealedTally.PublicKey = []byte{1, 2, 3, 4}
		}},
		{"tally_authority_not_participant", func(sf *sealedAccordFixture) {
			sf.fx.spec.SealedTally.TallyAuthority = newAccordActor(t).pub.ID()
		}},
		{"tally_authority_lacks_resolve", func(sf *sealedAccordFixture) {
			sf.fx.spec.SealedTally.TallyAuthority = sf.fx.sre.pub.ID()
		}},
		{"invalid_utf8_tally_authority", func(sf *sealedAccordFixture) {
			sf.fx.spec.SealedTally.TallyAuthority = "bad\xffactor"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sf := newSealedAccordFixture(t, key)
			tc.mutate(&sf)
			if err := sf.fx.spec.Validate(); !errors.Is(err, ErrAccordSpec) {
				t.Fatalf("%s: got %v want ErrAccordSpec", tc.name, err)
			}
		})
	}
}

func TestSealedAccordLifecycleDecidedPrivacyAndOfflineVerify(t *testing.T) {
	sharedKey, err := NewSealedTallyKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	sf := newSealedAccordFixture(t, sharedKey)
	sf.fx.spec.Options[1].ExtraMandatoryRoles = []RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}}

	a, err := NewAccord(sf.fx.spec)
	if err != nil {
		t.Fatalf("NewAccord: %v", err)
	}

	// Plaintext vote rejected on sealed accord.
	accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "plain-rejected", 2, ErrAccordSpec, func(c *AccordCommand) {
		c.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("plain")}
	})

	// Plaintext accord rejects sealed vote and sealed resolve.
	pubFx := newAccordFixture(t)
	pubAccord, err := NewAccord(pubFx.spec)
	if err != nil {
		t.Fatal(err)
	}
	dummySealed, err := EncryptSealedBallot(sf.fx.spec, a.View().ID, pubFx.sre.pub.ID(), map[string]BallotPosition{"canary-rollout": BallotApprove}, Hash("r"))
	if err != nil {
		t.Fatal(err)
	}
	accordReject(t, pubAccord, pubFx.sre, "sre-vote", "vote", "sealed-on-public", 2, ErrAccordSpec, func(c *AccordCommand) {
		c.Vote = &VotePayload{Sealed: dummySealed}
	})

	// Safety vetoes full-rollout AND votes approve on canary-rollout, dissent on full-rollout.
	accordMustApply(t, a, sf.fx.safety, "safety-vote", "veto", "safety-veto-full", 2, func(c *AccordCommand) {
		c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("unsafe")}
	})
	castSealedVote(t, a, sf.fx.safety, "safety-vote", 3, "v-safety", map[string]BallotPosition{
		"canary-rollout": BallotApprove,
		"full-rollout":   BallotDissent,
	}, "safety-ballot")
	castSealedVote(t, a, sf.fx.sre, "sre-vote", 4, "v-sre", map[string]BallotPosition{
		"canary-rollout": BallotApprove,
		"hold-release":   BallotDissent,
	}, "sre-ballot")
	castSealedVote(t, a, sf.fx.security, "security-vote", 5, "v-sec", map[string]BallotPosition{
		"canary-rollout": BallotApprove,
	}, "sec-ballot")
	castSealedVote(t, a, sf.fx.release, "release-vote", 6, "v-rel", map[string]BallotPosition{
		"canary-rollout": BallotDissent,
		"full-rollout":   BallotApprove,
	}, "rel-ballot")

	// Second sealed ballot from same actor -> ErrAccordEquivocation.
	dupBallot, err := EncryptSealedBallot(sf.fx.spec, a.View().ID, sf.fx.sre.pub.ID(), map[string]BallotPosition{"hold-release": BallotApprove}, Hash("dup"))
	if err != nil {
		t.Fatal(err)
	}
	accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "v-sre-dup", 6, ErrAccordEquivocation, func(c *AccordCommand) {
		c.Vote = &VotePayload{Sealed: dupBallot}
	})

	// During voting, individual choices stay hidden in View().
	midView := a.View()
	if len(midView.Votes) != 0 || len(midView.SealedBallots) != 4 {
		t.Fatalf("unexpected mid-voting view: votes=%d sealed=%d", len(midView.Votes), len(midView.SealedBallots))
	}

	// Wrong resolver (even if granted AccordPermitResolve) cannot resolve sealed accord!
	// Add a secondary closeout-only resolver to verify TallyAuthority enforcement.
	sf2 := newSealedAccordFixture(t, sharedKey)
	closeoutActor := newAccordActor(t)
	sf2.fx.spec.Participants = append(sf2.fx.spec.Participants, closeoutActor.pub)
	sf2.fx.spec.Roles = append(sf2.fx.spec.Roles, AccordRoleGrant{
		ID: "closeout-res", Actor: closeoutActor.pub.ID(), Scope: sf2.fx.spec.Scope,
		Permissions: []AccordPermission{AccordPermitResolve}, ExpiresAtHeight: 20, LimitsHash: Hash("closeout"),
	})
	aWrongRes, err := NewAccord(sf2.fx.spec)
	if err != nil {
		t.Fatal(err)
	}
	castSealedVote(t, aWrongRes, sf2.fx.safety, "safety-vote", 2, "v1", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r1")
	castSealedVote(t, aWrongRes, sf2.fx.sre, "sre-vote", 3, "v2", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r2")
	castSealedVote(t, aWrongRes, sf2.fx.security, "security-vote", 4, "v3", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r3")
	validTallyForWrongRes, err := sharedKey.TallyAccord(aWrongRes.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	accordReject(t, aWrongRes, closeoutActor, "closeout-res", "resolve", "wrong-authority", 10, ErrAccordAuthority, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("steal-resolve"), SealedTally: validTallyForWrongRes}
	})

	// Missing SealedTally on sealed accord -> ErrAccordEvidence.
	accordReject(t, a, sf.tally, "tally-resolve", "resolve", "missing-tally", 10, ErrAccordEvidence, func(c *AccordCommand) {
		c.Resolve = &ResolvePayload{ReasonHash: Hash("no-tally")}
	})

	// Honest resolve by TallyAuthority.
	finalHead := resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res-final")
	v := a.View()
	if v.Phase != AccordPhaseDecided || v.Outcome == nil || v.Outcome.WinningOptionID != "canary-rollout" {
		t.Fatalf("unexpected sealed outcome: %+v", v.Outcome)
	}
	if v.Outcome.WinningCommitment != Hash(sf.fx.canSpec) {
		t.Fatalf("commitment mismatch: got %s want %s", v.Outcome.WinningCommitment, Hash(sf.fx.canSpec))
	}
	if v.Outcome.ParticipatingCount != 4 || v.Outcome.ParticipatingWeight != 7 {
		t.Fatalf("unexpected participation: count=%d weight=%d", v.Outcome.ParticipatingCount, v.Outcome.ParticipatingWeight)
	}
	if len(v.Outcome.WinningOptionDissents) != 0 || len(v.Votes) != 0 {
		t.Fatalf("individual votes/dissents leaked after resolution: votes=%d dissents=%d", len(v.Votes), len(v.Outcome.WinningOptionDissents))
	}
	for _, tl := range v.Outcome.Tallies {
		if len(tl.Approvers) != 0 || len(tl.Dissenters) != 0 || len(tl.Abstainers) != 0 {
			t.Fatalf("tally %s leaked voter lists: %+v", tl.OptionID, tl)
		}
		if tl.OptionID == "canary-rollout" {
			// safety(2)+sre(2)+sec(1) = count 3, weight 5; release(2) dissented -> count 1, weight 2.
			if tl.ApproveCount != 3 || tl.ApproveWeight != 5 || tl.DissentCount != 1 || tl.DissentWeight != 2 || len(tl.MissingRoles) != 0 {
				t.Fatalf("unexpected canary tally: %+v", tl)
			}
		}
		if tl.OptionID == "full-rollout" {
			if !tl.VetoEffective || tl.ApproveCount != 1 || tl.ApproveWeight != 2 || tl.DissentCount != 1 || tl.DissentWeight != 2 {
				t.Fatalf("unexpected full-rollout tally: %+v", tl)
			}
		}
	}

	// Offline JSON round-trip verification with zero private keys + downstream protocol binding.
	rawBundle, err := json.Marshal(a.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	var received AccordBundle
	if err := json.Unmarshal(rawBundle, &received); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAccordBundle(received, v.ID, finalHead)
	if err != nil {
		t.Fatalf("VerifyAccordBundle: %v", err)
	}
	if verified.Outcome.Hash() != v.Outcome.Hash() {
		t.Fatalf("verified outcome hash mismatch")
	}
	if _, _, err := AuthorizeProtocolFromAccord(received, v.ID, finalHead, sf.fx.canSpec); err != nil {
		t.Fatalf("AuthorizeProtocolFromAccord: %v", err)
	}
	if _, _, err := AuthorizeProtocolFromAccord(received, v.ID, finalHead, sf.fx.fullSpec); !errors.Is(err, ErrAccordBinding) {
		t.Fatalf("expected ErrAccordBinding for full-rollout, got %v", err)
	}

	// Persist in AccordStore, reload from disk, and verify bundle offline.
	store, err := OpenAccordStore(filepath.Join(t.TempDir(), "sealed-accords"), bytes.Repeat([]byte{42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sid, err := store.Create(sf.fx.spec)
	if err != nil || sid != v.ID {
		t.Fatalf("store.Create: %s %v", sid, err)
	}
	for _, ev := range received.Events {
		if _, err := store.Apply(sid, ev.Command, ev.Signature, ev.Command.Height); err != nil {
			t.Fatalf("store.Apply(%s): %v", ev.Command.RequestID, err)
		}
	}
	exported, err := store.Export(sid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAccordBundle(exported, sid, finalHead); err != nil {
		t.Fatalf("VerifyAccordBundle(store export): %v", err)
	}
}

func TestSealedAccordRulesDeadlocksVetoesRolesAndZeroBallots(t *testing.T) {
	sharedKey, err := NewSealedTallyKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("zero_ballots_deadlock_quorum_and_threshold", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		head := resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res-0")
		out := a.View().Outcome
		if out.Phase != AccordPhaseDeadlocked || out.DeadlockReason != DeadlockNoQuorum || out.ParticipatingCount != 0 {
			t.Fatalf("expected DeadlockNoQuorum, got %+v", out)
		}
		if _, err := VerifyAccordBundle(a.Bundle(), a.View().ID, head); err != nil {
			t.Fatalf("VerifyAccordBundle(0 ballots): %v", err)
		}

		// With 0 quorum required, 0 ballots -> DeadlockNoThresholdMet.
		sf2 := newSealedAccordFixture(t, sharedKey)
		sf2.fx.spec.Rules.MinParticipationCount = 0
		sf2.fx.spec.Rules.MinParticipationWeight = 0
		a2, err := NewAccord(sf2.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		resolveSealedAccord(t, a2, sharedKey, sf2.tally, "tally-resolve", 10, "res-0-thresh")
		if a2.View().Outcome.DeadlockReason != DeadlockNoThresholdMet {
			t.Fatalf("expected DeadlockNoThresholdMet, got %+v", a2.View().Outcome)
		}
	})

	t.Run("overridable_veto_and_mandatory_role", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		sf.fx.spec.Rules.BallotMode = BallotSingleChoice
		sf.fx.spec.Rules.MinParticipationCount = 2
		sf.fx.spec.Rules.MinParticipationWeight = 2
		sf.fx.spec.Rules.MinApprovalCount = 2
		sf.fx.spec.Rules.MinApprovalWeight = 3
		sf.fx.spec.Rules.MinApprovalMarginWeight = 0
		sf.fx.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}}
		sf.fx.spec.Rules.Veto = VetoPolicy{
			Mode:               VetoOverridable,
			MaxVetoesPerActor:  2,
			OverrideWeight:     5,
			AllowedDomainRoles: []string{"safety"},
		}
		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordMustApply(t, a, sf.fx.safety, "safety-vote", "veto", "veto-full", 2, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "full-rollout", ReasonHash: Hash("risk")}
		})
		// Safety vetoes full-rollout, dissents on full-rollout, and approves hold-release.
		castSealedVote(t, a, sf.fx.safety, "safety-vote", 3, "v-saf", map[string]BallotPosition{
			"full-rollout": BallotDissent,
			"hold-release": BallotApprove,
		}, "r-saf")
		// release(2) + sre(2) + sec(1) = weight 5 overrides safety veto on full-rollout!
		castSealedVote(t, a, sf.fx.release, "release-vote", 3, "v-rel", map[string]BallotPosition{
			"full-rollout": BallotApprove,
		}, "r-rel")
		castSealedVote(t, a, sf.fx.sre, "sre-vote", 4, "v-sre", map[string]BallotPosition{
			"full-rollout": BallotApprove,
		}, "r-sre")
		castSealedVote(t, a, sf.fx.security, "security-vote", 4, "v-sec", map[string]BallotPosition{
			"full-rollout": BallotApprove,
		}, "r-sec")

		head := resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res-over")
		out := a.View().Outcome
		if out.Phase != AccordPhaseDecided || out.WinningOptionID != "full-rollout" || len(out.WinningOptionVetoes) != 1 {
			t.Fatalf("expected overridden veto win on full-rollout, got %+v", out)
		}
		if _, err := VerifyAccordBundle(a.Bundle(), a.View().ID, head); err != nil {
			t.Fatalf("VerifyAccordBundle(overridable veto): %v", err)
		}
	})

	t.Run("missing_mandatory_role_deadlocks_even_with_weight", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		sf.fx.spec.Rules.MinParticipationCount = 2
		sf.fx.spec.Rules.MinParticipationWeight = 3
		sf.fx.spec.Rules.MinApprovalCount = 2
		sf.fx.spec.Rules.MinApprovalWeight = 3
		sf.fx.spec.Rules.MinApprovalMarginWeight = 0
		sf.fx.spec.Rules.MandatoryRoles = []RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}}
		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		// release(2) + sre(2) = count 2 weight 4 approve, safety abstains -> missing mandatory safety role!
		castSealedVote(t, a, sf.fx.release, "release-vote", 2, "v1", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r1")
		castSealedVote(t, a, sf.fx.sre, "sre-vote", 3, "v2", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r2")
		castSealedVote(t, a, sf.fx.safety, "safety-vote", 4, "v3", map[string]BallotPosition{"canary-rollout": BallotAbstain}, "r3")

		resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res-missing-role")
		out := a.View().Outcome
		if out.Phase != AccordPhaseDeadlocked || out.DeadlockReason != DeadlockNoThresholdMet {
			t.Fatalf("expected DeadlockNoThresholdMet, got %+v", out)
		}
		for _, tl := range out.Tallies {
			if tl.OptionID == "canary-rollout" && !slices.Contains(tl.MissingRoles, "safety") {
				t.Fatalf("canary-rollout should miss safety role: %+v", tl)
			}
		}
	})

	t.Run("all_vetoed_and_tie_deadlock_and_expire", func(t *testing.T) {
		sf := newSealedAccordFixture(t, sharedKey)
		sf.fx.spec.Rules.MandatoryRoles = nil
		sf.fx.spec.Rules.MinParticipationCount = 2
		sf.fx.spec.Rules.MinParticipationWeight = 3
		sf.fx.spec.Rules.MinApprovalCount = 2
		sf.fx.spec.Rules.MinApprovalWeight = 3
		sf.fx.spec.Rules.MinApprovalMarginWeight = 0
		a, err := NewAccord(sf.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		castSealedVote(t, a, sf.fx.release, "release-vote", 2, "v1", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r1")
		castSealedVote(t, a, sf.fx.sre, "sre-vote", 3, "v2", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r2")
		accordMustApply(t, a, sf.fx.safety, "safety-vote", "veto", "vt", 4, func(c *AccordCommand) {
			c.Veto = &VetoPayload{OptionID: "canary-rollout", ReasonHash: Hash("block")}
		})
		resolveSealedAccord(t, a, sharedKey, sf.tally, "tally-resolve", 10, "res-vetoed")
		if a.View().Outcome.DeadlockReason != DeadlockAllVetoed {
			t.Fatalf("expected DeadlockAllVetoed, got %+v", a.View().Outcome)
		}

		// Tie deadlock + expire participation check.
		sfTie := newSealedAccordFixture(t, sharedKey)
		sfTie.fx.spec.Rules.MandatoryRoles = nil
		sfTie.fx.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
		sfTie.fx.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
		sfTie.fx.spec.Rules.MinParticipationCount = 2
		sfTie.fx.spec.Rules.MinParticipationWeight = 2
		sfTie.fx.spec.Rules.MinApprovalCount = 1
		sfTie.fx.spec.Rules.MinApprovalWeight = 2
		sfTie.fx.spec.Rules.MinApprovalMarginWeight = 0
		sfTie.fx.spec.Rules.TieBreak = TieBreakDeadlock
		aTie, err := NewAccord(sfTie.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		castSealedVote(t, aTie, sfTie.fx.release, "release-vote", 2, "v1", map[string]BallotPosition{"full-rollout": BallotApprove}, "r1")
		castSealedVote(t, aTie, sfTie.fx.sre, "sre-vote", 3, "v2", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r2")
		resolveSealedAccord(t, aTie, sharedKey, sfTie.tally, "tally-resolve", 10, "res-tie")
		outTie := aTie.View().Outcome
		if outTie.DeadlockReason != DeadlockTie || !slices.Equal(outTie.TiedOptionIDs, []string{"canary-rollout", "full-rollout"}) {
			t.Fatalf("expected DeadlockTie [canary-rollout, full-rollout], got %+v", outTie)
		}

		// Expire preserves sealed participation without fabricating tallies.
		aExp, err := NewAccord(sfTie.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		castSealedVote(t, aExp, sfTie.fx.release, "release-vote", 2, "v1", map[string]BallotPosition{"full-rollout": BallotApprove}, "r1")
		expHead := accordMustApply(t, aExp, sfTie.tally, "tally-resolve", "expire", "exp", 20, func(c *AccordCommand) {
			c.Expire = &ExpirePayload{ReasonHash: Hash("expired")}
		})
		expView := aExp.View()
		if expView.Phase != AccordPhaseExpired || expView.Outcome.ParticipatingCount != 1 || expView.Outcome.ParticipatingWeight != 2 || len(expView.Outcome.Tallies) != 0 {
			t.Fatalf("unexpected expired sealed view: %+v", expView.Outcome)
		}
		if _, err := VerifyAccordBundle(aExp.Bundle(), expView.ID, expHead); err != nil {
			t.Fatalf("VerifyAccordBundle(expired): %v", err)
		}
	})
}

func TestSealedAccordAdversarialProofAttacksAndReplay(t *testing.T) {
	sharedKey, err := NewSealedTallyKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := he.FromPublic(sharedKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	sf := newSealedAccordFixture(t, sharedKey)
	sf.fx.spec.Rules.BallotMode = BallotSingleChoice
	a, err := NewAccord(sf.fx.spec)
	if err != nil {
		t.Fatal(err)
	}
	accordID := a.View().ID
	actorID := sf.fx.sre.pub.ID()

	validBallot, err := EncryptSealedBallot(sf.fx.spec, accordID, actorID, map[string]BallotPosition{"canary-rollout": BallotApprove}, Hash("ok"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("forged_or_proof_and_tampered_ciphertext", func(t *testing.T) {
		bad := cloneSealedBallotPayload(validBallot)
		bad.Options[0].ApproveProof[len(bad.Options[0].ApproveProof)-2] ^= 0xff
		accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "bad-or", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: bad}
		})

		badCT := cloneSealedBallotPayload(validBallot)
		badCT.Options[0].ApproveCT[len(badCT.Options[0].ApproveCT)-1] ^= 0x01
		accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "bad-ct", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: badCT}
		})
	})

	t.Run("approve_and_dissent_simultaneous_attack", func(t *testing.T) {
		// Encrypt BOTH approve=1 and dissent=1 with valid individual proofs; ExclusiveProof MUST fail!
		bad := cloneSealedBallotPayload(validBallot)
		appCT, appR, err := pub.EncryptBitWithR(1)
		if err != nil {
			t.Fatal(err)
		}
		disCT, disR, err := pub.EncryptBitWithR(1)
		if err != nil {
			t.Fatal(err)
		}
		optID := bad.Options[0].OptionID
		bad.Options[0].ApproveCT = appCT
		bad.Options[0].ApproveProof, err = pub.ProveBit(new(big.Int).SetBytes(appCT), appR, 1, sealedProofDomain(accordID, actorID, optID, sealedSlotApprove))
		if err != nil {
			t.Fatal(err)
		}
		bad.Options[0].DissentCT = disCT
		bad.Options[0].DissentProof, err = pub.ProveBit(new(big.Int).SetBytes(disCT), disR, 1, sealedProofDomain(accordID, actorID, optID, sealedSlotDissent))
		if err != nil {
			t.Fatal(err)
		}
		// ProveBit cannot prove sum=2 as {0,1}; leave old ExclusiveProof -> must reject!
		exclCT, _ := pub.Add(appCT, disCT)
		if _, err := pub.ProveBit(new(big.Int).SetBytes(exclCT), pub.MulUnits(appR, disR), 1, sealedProofDomain(accordID, actorID, optID, sealedSlotExclusive)); err == nil {
			t.Fatal("ProveBit unexpectedly proved approve+dissent=2 as bit 1")
		}
		accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "both-app-dis", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: bad}
		})
	})

	t.Run("single_choice_double_approve_attack", func(t *testing.T) {
		if _, err := EncryptSealedBallot(sf.fx.spec, accordID, actorID, map[string]BallotPosition{
			"canary-rollout": BallotApprove,
			"full-rollout":   BallotApprove,
		}, Hash("double")); !errors.Is(err, ErrAccordEquivocation) {
			t.Fatalf("EncryptSealedBallot allowed double approve: %v", err)
		}

		// Manually assemble two valid option approvals (opts 0 and 1); SingleChoiceProof fails!
		bad := cloneSealedBallotPayload(validBallot)
		// Option 1 (full-rollout) set to Approve=1, Dissent=0 with valid per-option proofs.
		appCT, appR, _ := pub.EncryptBitWithR(1)
		disCT, disR, _ := pub.EncryptBitWithR(0)
		optID := bad.Options[1].OptionID
		bad.Options[1].ApproveCT = appCT
		bad.Options[1].ApproveProof, _ = pub.ProveBit(new(big.Int).SetBytes(appCT), appR, 1, sealedProofDomain(accordID, actorID, optID, sealedSlotApprove))
		bad.Options[1].DissentCT = disCT
		bad.Options[1].DissentProof, _ = pub.ProveBit(new(big.Int).SetBytes(disCT), disR, 0, sealedProofDomain(accordID, actorID, optID, sealedSlotDissent))
		exclCT, _ := pub.Add(appCT, disCT)
		bad.Options[1].ExclusiveProof, _ = pub.ProveBit(new(big.Int).SetBytes(exclCT), pub.MulUnits(appR, disR), 1, sealedProofDomain(accordID, actorID, optID, sealedSlotExclusive))
		accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "double-approve", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: bad}
		})
	})

	t.Run("cross_accord_voter_option_and_slot_replay", func(t *testing.T) {
		// Cross-accord replay: build second Accord with identical participants/options, different Nonce.
		sfB := newSealedAccordFixture(t, sharedKey)
		sfB.fx.spec.Nonce = "other-sealed-accord"
		sfB.fx.spec.Rules.BallotMode = BallotSingleChoice
		aB, err := NewAccord(sfB.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		accordReject(t, aB, sfB.fx.sre, "sre-vote", "vote", "cross-accord", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: cloneSealedBallotPayload(validBallot)}
		})

		// Cross-voter replay: release submits sre's sealed ballot.
		accordReject(t, a, sf.fx.release, "release-vote", "vote", "cross-voter", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: cloneSealedBallotPayload(validBallot)}
		})

		// Cross-option replay: swap canary-rollout and full-rollout ciphertexts/proofs (keep OptionIDs in sorted order).
		swapped := cloneSealedBallotPayload(validBallot)
		swapped.Options[0], swapped.Options[1] = swapped.Options[1], swapped.Options[0]
		swapped.Options[0].OptionID, swapped.Options[1].OptionID = swapped.Options[1].OptionID, swapped.Options[0].OptionID
		accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "cross-option", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: swapped}
		})

		// Cross-slot replay: copy ApproveCT+ApproveProof into DissentCT+DissentProof on option 0.
		slotReplay := cloneSealedBallotPayload(validBallot)
		slotReplay.Options[0].DissentCT = slices.Clone(slotReplay.Options[0].ApproveCT)
		slotReplay.Options[0].DissentProof = slices.Clone(slotReplay.Options[0].ApproveProof)
		accordReject(t, a, sf.fx.sre, "sre-vote", "vote", "cross-slot", 2, ErrAccordEvidence, func(c *AccordCommand) {
			c.Vote = &VotePayload{Sealed: slotReplay}
		})
	})

	t.Run("forged_tally_weight_inflation_and_offline_tamper", func(t *testing.T) {
		sfT := newSealedAccordFixture(t, sharedKey)
		aT, err := NewAccord(sfT.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		castSealedVote(t, aT, sfT.fx.safety, "safety-vote", 2, "v1", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r1")
		castSealedVote(t, aT, sfT.fx.sre, "sre-vote", 3, "v2", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r2")
		castSealedVote(t, aT, sfT.fx.security, "security-vote", 4, "v3", map[string]BallotPosition{"canary-rollout": BallotApprove}, "r3")

		honestTally, err := sharedKey.TallyAccord(aT.Bundle())
		if err != nil {
			t.Fatal(err)
		}

		// 1. Inflate ApproveWeight without changing proof (and within partWeight).
		inflated := cloneSealedTallyProof(honestTally)
		inflated.Options[0].ApproveWeight++
		accordReject(t, aT, sfT.tally, "tally-resolve", "resolve", "inflate-w", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("bad"), SealedTally: inflated}
		})

		// 2. Inflate ApproveCount.
		inflatedCnt := cloneSealedTallyProof(honestTally)
		inflatedCnt.Options[0].ApproveCount++
		accordReject(t, aT, sfT.tally, "tally-resolve", "resolve", "inflate-c", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("bad"), SealedTally: inflatedCnt}
		})

		// 3. Inflate RoleTallies weight.
		inflatedRole := cloneSealedTallyProof(honestTally)
		inflatedRole.Options[0].RoleTallies[0].ApproveWeight--
		accordReject(t, aT, sfT.tally, "tally-resolve", "resolve", "tamper-role", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("bad"), SealedTally: inflatedRole}
		})

		// 4. Missing option / extra role tally.
		missingOpt := cloneSealedTallyProof(honestTally)
		missingOpt.Options = missingOpt.Options[:2]
		accordReject(t, aT, sfT.tally, "tally-resolve", "resolve", "missing-opt", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("bad"), SealedTally: missingOpt}
		})

		extraRole := cloneSealedTallyProof(honestTally)
		extraRole.Options[0].RoleTallies = append(extraRole.Options[0].RoleTallies, extraRole.Options[0].RoleTallies[0])
		accordReject(t, aT, sfT.tally, "tally-resolve", "resolve", "extra-role", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("bad"), SealedTally: extraRole}
		})

		// Commit honest resolve, then tamper exported AccordBundle and ensure VerifyAccordBundle fails!
		finalHead := accordMustApply(t, aT, sfT.tally, "tally-resolve", "resolve", "res-honest", 10, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("ok"), SealedTally: honestTally}
		})
		bTampered := aT.Bundle()
		bTampered.Events[0].Command.Vote.Sealed.Options[0].ApproveCT[0] ^= 0x01
		if _, err := VerifyAccordBundle(bTampered, aT.View().ID, finalHead); err == nil {
			t.Fatal("VerifyAccordBundle accepted tampered sealed ballot ciphertext")
		}
	})

	t.Run("prime_power_modulus_rejected_by_gmr_on_resolve", func(t *testing.T) {
		// Construct N = 65539^65 (all factors > 65537, non-square) which passes FromPublic
		// but fails the 128-bit GMR coprimality NIZK in he.VerifyEqual at resolve time!
		p := big.NewInt(65539)
		nLarge := new(big.Int).Exp(p, big.NewInt(65), nil)
		sfGMR := newSealedAccordFixture(t, sharedKey)
		sfGMR.fx.spec.SealedTally.PublicKey = nLarge.Bytes()
		sfGMR.fx.spec.Rules.MandatoryRoles = nil
		sfGMR.fx.spec.Rules.MinParticipationCount = 0
		sfGMR.fx.spec.Rules.MinParticipationWeight = 0
		aGMR, err := NewAccord(sfGMR.fx.spec)
		if err != nil {
			t.Fatalf("NewAccord with N=65539^65: %v", err)
		}
		fakeProof, _ := json.Marshal(struct {
			A []byte   `json:"a"`
			Z []byte   `json:"z"`
			R [][]byte `json:"r"`
		}{A: []byte{1}, Z: []byte{1}, R: [][]byte{{2}, {2}, {2}, {2}, {2}, {2}, {2}, {2}}})
		fakeTally := &SealedTallyProof{Options: make([]SealedOptionTallyProof, len(sfGMR.fx.spec.Options))}
		sortedOpts := slices.Clone(sfGMR.fx.spec.Options)
		slices.SortFunc(sortedOpts, func(x, y AccordOption) int { return strings.Compare(x.ID, y.ID) })
		for i, o := range sortedOpts {
			fakeTally.Options[i] = SealedOptionTallyProof{
				OptionID:           o.ID,
				ApproveCountProof:  fakeProof,
				ApproveWeightProof: fakeProof,
				DissentCountProof:  fakeProof,
				DissentWeightProof: fakeProof,
			}
		}
		accordReject(t, aGMR, sfGMR.tally, "tally-resolve", "resolve", "gmr-forged", 10, ErrAccordEvidence, func(c *AccordCommand) {
			c.Resolve = &ResolvePayload{ReasonHash: Hash("gmr"), SealedTally: fakeTally}
		})
	})

	t.Run("size_caps_512kib_sealed_vs_64kib_plaintext_and_concurrency", func(t *testing.T) {
		// Build a 10-option sealed accord so vote + resolve exceed 64 KiB but remain <= 512 KiB.
		sfBig := newSealedAccordFixture(t, sharedKey)
		sfBig.fx.spec.Rules.MandatoryRoles = nil
		sfBig.fx.spec.Rules.Veto = VetoPolicy{Mode: VetoDisabled}
		sfBig.fx.spec.Roles[2].Permissions = []AccordPermission{AccordPermitVote}
		sfBig.fx.spec.Rules.MinParticipationCount = 1
		sfBig.fx.spec.Rules.MinParticipationWeight = 1
		sfBig.fx.spec.Rules.MinApprovalCount = 1
		sfBig.fx.spec.Rules.MinApprovalWeight = 1
		sfBig.fx.spec.Rules.MinApprovalMarginWeight = 0
		sfBig.fx.spec.Options = nil
		for i := 0; i < 10; i++ {
			sfBig.fx.spec.Options = append(sfBig.fx.spec.Options, AccordOption{
				ID: fmt.Sprintf("opt-%02d", i), Title: fmt.Sprintf("Option %d", i), Priority: uint32(i + 1),
				Binding: OptionBinding{Kind: BindingDisposition, Disposition: "hold", ActionHash: Hash(fmt.Sprintf("act-%d", i))},
			})
		}
		aBig, err := NewAccord(sfBig.fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		sealedBig, err := EncryptSealedBallot(sfBig.fx.spec, aBig.View().ID, sfBig.fx.sre.pub.ID(), map[string]BallotPosition{"opt-03": BallotApprove}, Hash("big"))
		if err != nil {
			t.Fatal(err)
		}
		voteCmd := aBig.Prepare(sfBig.fx.sre.pub.ID(), "sre-vote", sfBig.fx.spec.Scope, "vote", "big-v1", 2)
		voteCmd.Vote = &VotePayload{Sealed: sealedBig}
		voteBytes, _ := json.Marshal(voteCmd)
		if len(voteBytes) <= maxAccordCommandBytes || len(voteBytes) > maxSealedCommandBytes {
			t.Fatalf("unexpected 10-option sealed vote byte size: %d", len(voteBytes))
		}
		voteSig, err := SignAccordCommand(sfBig.fx.sre.id, voteCmd)
		if err != nil {
			t.Fatalf("SignAccordCommand(10-option sealed vote): %v", err)
		}
		if _, err := aBig.Apply(voteCmd, voteSig, 2); err != nil {
			t.Fatalf("Apply(10-option sealed vote): %v", err)
		}

		tallyBig, err := sharedKey.TallyAccord(aBig.Bundle())
		if err != nil {
			t.Fatal(err)
		}
		resCmd := aBig.Prepare(sfBig.tally.pub.ID(), "tally-resolve", sfBig.fx.spec.Scope, "resolve", "big-res", 10)
		resCmd.Resolve = &ResolvePayload{ReasonHash: Hash("big-res"), SealedTally: tallyBig}
		resBytes, _ := json.Marshal(resCmd)
		if len(resBytes) <= maxAccordCommandBytes || len(resBytes) > maxSealedCommandBytes {
			t.Fatalf("unexpected 10-option sealed resolve byte size: %d", len(resBytes))
		}
		resSig, err := SignAccordCommand(sfBig.tally.id, resCmd)
		if err != nil {
			t.Fatalf("SignAccordCommand(10-option sealed resolve): %v", err)
		}
		finalHead, err := aBig.Apply(resCmd, resSig, 10)
		if err != nil {
			t.Fatalf("Apply(10-option sealed resolve): %v", err)
		}
		if aBig.View().Outcome.WinningOptionID != "opt-03" {
			t.Fatalf("unexpected winner: %+v", aBig.View().Outcome)
		}

		// Plaintext vote command exceeding 64 KiB MUST still be rejected.
		pubBig, err := NewAccord(newAccordFixture(t).spec)
		if err != nil {
			t.Fatal(err)
		}
		oversizedPlain := pubBig.Prepare(sfBig.fx.sre.pub.ID(), "sre-vote", sfBig.fx.spec.Scope, "vote", strings.Repeat("r", 128), 2)
		oversizedPlain.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: strings.Repeat("a", maxAccordCommandBytes+100)}
		if _, err := SignAccordCommand(sfBig.fx.sre.id, oversizedPlain); !errors.Is(err, ErrAccordSpec) {
			t.Fatalf("SignAccordCommand accepted oversized plaintext vote: %v", err)
		}

		// Concurrent VerifyAccordBundle under -race.
		bundle := aBig.Bundle()
		aid := aBig.View().ID
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := VerifyAccordBundle(bundle, aid, finalHead); err != nil {
					t.Errorf("concurrent VerifyAccordBundle failed: %v", err)
				}
			}()
		}
		wg.Wait()
	})
}
