package nex

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"slices"
	"strings"

	"github.com/WillBeebe/nexum/v2/internal/he"
)

const (
	sealedProofDomainPrefix = "nexum/accord/sealed-proof/v1\x00"
	sealedSlotApprove       = "approve"
	sealedSlotDissent       = "dissent"
	sealedSlotExclusive     = "exclusive"
	sealedSlotSingleChoice  = "single_choice"
)

// SealedTallyConfig configures Paillier threshold/authority tallying for a
// BallotPrivacySealedPaillier Accord.
type SealedTallyConfig struct {
	PublicKey      []byte `json:"public_key"`
	TallyAuthority string `json:"tally_authority"`
}

// SealedOptionBallot carries one participant's encrypted {0,1} approve and
// dissent ciphertexts and CDS94 zero-knowledge proofs for a single option.
// When the voter has already publicly vetoed OptionID, DissentRandomness must
// open DissentCT == E(1; r) mod N^2, preventing vote+veto equivocation without
// revealing positions on non-vetoed options.
type SealedOptionBallot struct {
	OptionID          string `json:"option_id"`
	ApproveCT         []byte `json:"approve_ct"`
	ApproveProof      []byte `json:"approve_proof"`
	DissentCT         []byte `json:"dissent_ct"`
	DissentProof      []byte `json:"dissent_proof"`
	ExclusiveProof    []byte `json:"exclusive_proof"`
	DissentRandomness []byte `json:"dissent_randomness,omitempty"`
}

// SealedBallotPayload carries a participant's complete encrypted ballot across
// all genesis options plus an optional single-choice sum proof.
type SealedBallotPayload struct {
	Options           []SealedOptionBallot `json:"options"`
	SingleChoiceProof []byte               `json:"single_choice_proof,omitempty"`
	RationaleHash     string               `json:"rationale_hash"`
}

// RecordedSealedOption preserves one participant's verified encrypted approve
// and dissent ciphertexts for an option without revealing their position.
type RecordedSealedOption struct {
	OptionID  string `json:"option_id"`
	ApproveCT []byte `json:"approve_ct"`
	DissentCT []byte `json:"dissent_ct"`
}

// RecordedSealedBallot preserves one participant's verified encrypted ballot
// metadata and opaque ciphertexts on AccordView.
type RecordedSealedBallot struct {
	Actor         string                 `json:"actor"`
	GrantID       string                 `json:"grant_id"`
	Weight        uint64                 `json:"weight"`
	DomainRoles   []string               `json:"domain_roles,omitempty"`
	Options       []RecordedSealedOption `json:"options"`
	RationaleHash string                 `json:"rationale_hash"`
	Height        uint64                 `json:"height"`
	ReceiptHash   string                 `json:"receipt_hash"`
}

// SealedRoleTallyProof pairs decrypted mandatory-role approval totals for an
// option with GMR-backed Paillier equality proofs over the role's aggregate.
type SealedRoleTallyProof struct {
	Role               string `json:"role"`
	ApproveCount       uint64 `json:"approve_count"`
	ApproveCountProof  []byte `json:"approve_count_proof"`
	ApproveWeight      uint64 `json:"approve_weight"`
	ApproveWeightProof []byte `json:"approve_weight_proof"`
}

// SealedOptionTallyProof pairs decrypted option totals with GMR-backed
// Paillier equality proofs over the kernel-computed homomorphic aggregates.
type SealedOptionTallyProof struct {
	OptionID           string                 `json:"option_id"`
	ApproveCount       uint64                 `json:"approve_count"`
	ApproveCountProof  []byte                 `json:"approve_count_proof"`
	ApproveWeight      uint64                 `json:"approve_weight"`
	ApproveWeightProof []byte                 `json:"approve_weight_proof"`
	DissentCount       uint64                 `json:"dissent_count"`
	DissentCountProof  []byte                 `json:"dissent_count_proof"`
	DissentWeight      uint64                 `json:"dissent_weight"`
	DissentWeightProof []byte                 `json:"dissent_weight_proof"`
	RoleTallies        []SealedRoleTallyProof `json:"role_tallies,omitempty"`
}

// SealedTallyProof holds the decrypted aggregate totals and GMR-backed
// zero-knowledge equality proofs for every option in a sealed Accord.
type SealedTallyProof struct {
	Options []SealedOptionTallyProof `json:"options"`
}

// SealedTallyKey wraps the TallyAuthority's private Paillier key and decrypts
// only homomorphically aggregated tallies — never individual sealed ballots.
type SealedTallyKey struct {
	p *he.Paillier
}

// NewSealedTallyKey generates a fresh Paillier tally key of bit length bits.
func NewSealedTallyKey(bits int) (*SealedTallyKey, error) {
	p, err := he.NewPaillier(bits)
	if err != nil {
		return nil, err
	}
	return &SealedTallyKey{p: p}, nil
}

// PublicKey returns the canonical public Paillier modulus bytes.
func (k *SealedTallyKey) PublicKey() []byte {
	if k == nil || k.p == nil {
		return nil
	}
	return k.p.N().Bytes()
}

// EncryptSealedBallot encrypts a voter's per-option positions using only the
// Accord's public Paillier key and generates domain-separated CDS94 OR-proofs.
func EncryptSealedBallot(spec AccordSpec, accordID, actor string, choices map[string]BallotPosition, rationaleHash string) (*SealedBallotPayload, error) {
	return EncryptSealedBallotWithVetoes(spec, accordID, actor, choices, nil, rationaleHash)
}

// EncryptSealedBallotWithVetoes encrypts a voter's sealed ballot and attaches
// DissentRandomness openings on every option in vetoedOptions (which must have
// position BallotDissent in choices) so a voter who already vetoed those options
// proves non-equivocation without revealing choices on non-vetoed options.
func EncryptSealedBallotWithVetoes(spec AccordSpec, accordID, actor string, choices map[string]BallotPosition, vetoedOptions []string, rationaleHash string) (*SealedBallotPayload, error) {
	payload, _, err := EncryptSealedBallotWithOpenings(spec, accordID, actor, choices, vetoedOptions, rationaleHash)
	return payload, err
}

// EncryptSealedBallotWithOpenings behaves like EncryptSealedBallotWithVetoes
// and additionally returns the canonical per-option dissent randomness for
// every BallotDissent option so the voter can later supply
// VetoPayload.DissentRandomness if they veto a dissented option after voting.
func EncryptSealedBallotWithOpenings(spec AccordSpec, accordID, actor string, choices map[string]BallotPosition, vetoedOptions []string, rationaleHash string) (*SealedBallotPayload, map[string][]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, nil, err
	}
	if spec.Rules.BallotPrivacy != BallotPrivacySealedPaillier || spec.SealedTally == nil {
		return nil, nil, ErrAccordSpec
	}
	if !protocolHash(accordID) || accordID != spec.ID() {
		return nil, nil, ErrAccordStale
	}
	if !protocolHash(actor) || !protocolHash(rationaleHash) {
		return nil, nil, ErrAccordSpec
	}
	pub, err := he.FromPublic(spec.SealedTally.PublicKey)
	if err != nil {
		return nil, nil, ErrAccordSpec
	}

	opts := make([]AccordOption, len(spec.Options))
	for i, o := range spec.Options {
		opts[i] = cloneAccordOption(o)
	}
	slices.SortFunc(opts, func(a, b AccordOption) int {
		return strings.Compare(a.ID, b.ID)
	})
	declared := make(map[string]bool, len(opts))
	for _, o := range opts {
		declared[o.ID] = true
	}

	approveTotal := 0
	for optID, pos := range choices {
		if !declared[optID] || !allowedBallotPosition(pos) {
			return nil, nil, ErrAccordSpec
		}
		if pos == BallotApprove {
			approveTotal++
		}
	}
	if spec.Rules.BallotMode == BallotSingleChoice && approveTotal > 1 {
		return nil, nil, ErrAccordEquivocation
	}

	vetoed := make(map[string]bool, len(vetoedOptions))
	for _, optID := range vetoedOptions {
		if !declared[optID] || vetoed[optID] {
			return nil, nil, ErrAccordSpec
		}
		if choices[optID] != BallotDissent {
			return nil, nil, ErrAccordEquivocation
		}
		vetoed[optID] = true
	}

	outOpts := make([]SealedOptionBallot, len(opts))
	dissentOpenings := make(map[string][]byte)
	prodApproveCT := []byte{1}
	prodApproveR := big.NewInt(1)

	for i, opt := range opts {
		pos := BallotAbstain
		if chosen, ok := choices[opt.ID]; ok {
			pos = chosen
		}
		var appBit, disBit int
		switch pos {
		case BallotApprove:
			appBit = 1
		case BallotDissent:
			disBit = 1
		}

		appCT, appR, err := pub.EncryptBitWithR(appBit)
		if err != nil {
			return nil, nil, err
		}
		appProof, err := pub.ProveBit(new(big.Int).SetBytes(appCT), appR, appBit, sealedProofDomain(accordID, actor, opt.ID, sealedSlotApprove))
		if err != nil {
			return nil, nil, err
		}

		disCT, disR, err := pub.EncryptBitWithR(disBit)
		if err != nil {
			return nil, nil, err
		}
		disProof, err := pub.ProveBit(new(big.Int).SetBytes(disCT), disR, disBit, sealedProofDomain(accordID, actor, opt.ID, sealedSlotDissent))
		if err != nil {
			return nil, nil, err
		}

		exclCT, err := pub.Add(appCT, disCT)
		if err != nil {
			return nil, nil, err
		}
		exclR := pub.MulUnits(appR, disR)
		if exclR == nil {
			return nil, nil, ErrAccordSpec
		}
		exclProof, err := pub.ProveBit(new(big.Int).SetBytes(exclCT), exclR, appBit+disBit, sealedProofDomain(accordID, actor, opt.ID, sealedSlotExclusive))
		if err != nil {
			return nil, nil, err
		}

		if spec.Rules.BallotMode == BallotSingleChoice {
			prodApproveCT, err = pub.Add(prodApproveCT, appCT)
			if err != nil {
				return nil, nil, err
			}
			prodApproveR = pub.MulUnits(prodApproveR, appR)
			if prodApproveR == nil {
				return nil, nil, ErrAccordSpec
			}
		}

		var disRandBytes []byte
		if disBit == 1 {
			dissentOpenings[opt.ID] = disR.Bytes()
		}
		if vetoed[opt.ID] {
			disRandBytes = disR.Bytes()
		}

		outOpts[i] = SealedOptionBallot{
			OptionID:          opt.ID,
			ApproveCT:         appCT,
			ApproveProof:      appProof,
			DissentCT:         disCT,
			DissentProof:      disProof,
			ExclusiveProof:    exclProof,
			DissentRandomness: disRandBytes,
		}
	}

	var singleChoiceProof []byte
	if spec.Rules.BallotMode == BallotSingleChoice {
		singleChoiceProof, err = pub.ProveBit(
			new(big.Int).SetBytes(prodApproveCT),
			prodApproveR,
			approveTotal,
			sealedProofDomain(accordID, actor, "", sealedSlotSingleChoice),
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return &SealedBallotPayload{
		Options:           outOpts,
		SingleChoiceProof: singleChoiceProof,
		RationaleHash:     rationaleHash,
	}, dissentOpenings, nil
}

// TallyAccord replays bundle offline, homomorphically aggregates the sealed
// ballots per option and mandatory role, and decrypts ONLY the aggregated
// totals along with GMR-backed Paillier equality proofs.
func (k *SealedTallyKey) TallyAccord(bundle AccordBundle) (*SealedTallyProof, error) {
	if k == nil || k.p == nil {
		return nil, ErrAccordAuthority
	}
	if !validAccordBundleStrings(bundle) {
		return nil, ErrAccordSpec
	}
	expectedID := bundle.Spec.ID()
	expectedHead := expectedID
	if len(bundle.Events) > 0 {
		expectedHead = bundle.Events[len(bundle.Events)-1].ReceiptHash
	}
	a, err := replayAccordBundle(bundle, expectedID, expectedHead)
	if err != nil {
		return nil, err
	}
	if a.spec.Rules.BallotPrivacy != BallotPrivacySealedPaillier || a.spec.SealedTally == nil {
		return nil, ErrAccordSpec
	}
	if !bytes.Equal(a.spec.SealedTally.PublicKey, k.PublicKey()) {
		return nil, ErrAccordAuthority
	}

	aggs, err := computeSealedAggregates(a.spec, a.view)
	if err != nil {
		return nil, err
	}

	decryptUint64 := func(ct []byte) (uint64, []byte, error) {
		m, proof, err := k.p.DecryptAndProve(ct)
		if err != nil || !m.IsUint64() {
			return 0, nil, ErrAccordEvidence
		}
		return m.Uint64(), proof, nil
	}

	optProofs := make([]SealedOptionTallyProof, len(aggs))
	for i, agg := range aggs {
		appCnt, appCntProof, err := decryptUint64(agg.approveCountCT)
		if err != nil {
			return nil, err
		}
		appWt, appWtProof, err := decryptUint64(agg.approveWeightCT)
		if err != nil {
			return nil, err
		}
		disCnt, disCntProof, err := decryptUint64(agg.dissentCountCT)
		if err != nil {
			return nil, err
		}
		disWt, disWtProof, err := decryptUint64(agg.dissentWeightCT)
		if err != nil {
			return nil, err
		}

		var roleProofs []SealedRoleTallyProof
		if len(agg.requiredRoles) > 0 {
			roleProofs = make([]SealedRoleTallyProof, len(agg.requiredRoles))
			for j, req := range agg.requiredRoles {
				rCnt, rCntProof, err := decryptUint64(agg.roleCountCT[req.Role])
				if err != nil {
					return nil, err
				}
				rWt, rWtProof, err := decryptUint64(agg.roleWeightCT[req.Role])
				if err != nil {
					return nil, err
				}
				roleProofs[j] = SealedRoleTallyProof{
					Role:               req.Role,
					ApproveCount:       rCnt,
					ApproveCountProof:  rCntProof,
					ApproveWeight:      rWt,
					ApproveWeightProof: rWtProof,
				}
			}
		}

		optProofs[i] = SealedOptionTallyProof{
			OptionID:           agg.optionID,
			ApproveCount:       appCnt,
			ApproveCountProof:  appCntProof,
			ApproveWeight:      appWt,
			ApproveWeightProof: appWtProof,
			DissentCount:       disCnt,
			DissentCountProof:  disCntProof,
			DissentWeight:      disWt,
			DissentWeightProof: disWtProof,
			RoleTallies:        roleProofs,
		}
	}

	return &SealedTallyProof{Options: optProofs}, nil
}

func validateSealedAccordSpec(s AccordSpec, parties map[string]bool, actorPerms map[string]map[AccordPermission]bool) error {
	switch s.Rules.BallotPrivacy {
	case "", BallotPrivacyPublic:
		if s.SealedTally != nil {
			return ErrAccordSpec
		}
		return nil
	case BallotPrivacySealedPaillier:
		if s.AllowProposals || len(s.Options) < 1 || s.SealedTally == nil {
			return ErrAccordSpec
		}
		if _, err := he.FromPublic(s.SealedTally.PublicKey); err != nil {
			return ErrAccordSpec
		}
		if !parties[s.SealedTally.TallyAuthority] || !actorPerms[s.SealedTally.TallyAuthority][AccordPermitResolve] {
			return ErrAccordSpec
		}
		return nil
	default:
		return ErrAccordSpec
	}
}

func sealedProofDomain(accordID, actor, optionID, slotKind string) []byte {
	total := len(sealedProofDomainPrefix) + 4*8 + len(accordID) + len(actor) + len(optionID) + len(slotKind)
	buf := make([]byte, 0, total)
	buf = append(buf, sealedProofDomainPrefix...)
	appendField := func(s string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, s...)
	}
	appendField(accordID)
	appendField(actor)
	appendField(optionID)
	appendField(slotKind)
	return buf
}

func verifySealedDissentOpening(pub *he.Paillier, dissentCT, dissentRand []byte) bool {
	if pub == nil || len(dissentRand) == 0 || dissentRand[0] == 0 || len(dissentRand) > len(pub.N().Bytes()) {
		return false
	}
	r := new(big.Int).SetBytes(dissentRand)
	expectedCT, err := pub.EncryptWithR(big.NewInt(1), r)
	if err != nil {
		return false
	}
	return pub.Equal(expectedCT, dissentCT)
}

func (a *Accord) verifySealedVetoConsistency(v AccordView, actor, optionID string, dissentRand []byte) error {
	var priorBallot *RecordedSealedBallot
	for i := range v.SealedBallots {
		if v.SealedBallots[i].Actor == actor {
			priorBallot = &v.SealedBallots[i]
			break
		}
	}
	if priorBallot == nil {
		if len(dissentRand) != 0 {
			return ErrAccordSpec
		}
		return nil
	}
	if len(dissentRand) == 0 {
		return ErrAccordEquivocation
	}
	pub, err := he.FromPublic(a.spec.SealedTally.PublicKey)
	if err != nil {
		return ErrAccordSpec
	}
	for _, ob := range priorBallot.Options {
		if ob.OptionID == optionID {
			if !verifySealedDissentOpening(pub, ob.DissentCT, dissentRand) {
				return ErrAccordEquivocation
			}
			return nil
		}
	}
	return ErrAccordEquivocation
}

func (a *Accord) applySealedVote(v *AccordView, cmd AccordCommand, grant AccordRoleGrant, height uint64, receipt string) error {
	vp := cmd.Vote
	if vp.Sealed == nil || vp.OptionID != "" || vp.Position != "" {
		return ErrAccordSpec
	}
	if vp.RationaleHash != "" && vp.RationaleHash != vp.Sealed.RationaleHash {
		return ErrAccordSpec
	}
	if !protocolHash(vp.Sealed.RationaleHash) {
		return ErrAccordSpec
	}
	for _, existing := range v.SealedBallots {
		if existing.Actor == cmd.Actor {
			return ErrAccordEquivocation
		}
	}
	if len(vp.Sealed.Options) != len(v.Options) {
		return ErrAccordSpec
	}
	for i, ro := range v.Options {
		if vp.Sealed.Options[i].OptionID != ro.Option.ID {
			return ErrAccordSpec
		}
	}
	if a.spec.Rules.BallotMode != BallotSingleChoice && len(vp.Sealed.SingleChoiceProof) != 0 {
		return ErrAccordSpec
	}

	pub, err := he.FromPublic(a.spec.SealedTally.PublicKey)
	if err != nil {
		return ErrAccordSpec
	}

	vetoedByActor := make(map[string]bool)
	for _, vt := range v.Vetoes {
		if vt.Actor == cmd.Actor {
			vetoedByActor[vt.OptionID] = true
		}
	}

	prodApproveCT := []byte{1}
	recordedOpts := make([]RecordedSealedOption, len(vp.Sealed.Options))
	for i, ob := range vp.Sealed.Options {
		if vetoedByActor[ob.OptionID] {
			if !verifySealedDissentOpening(pub, ob.DissentCT, ob.DissentRandomness) {
				return ErrAccordEquivocation
			}
		} else if len(ob.DissentRandomness) != 0 {
			return ErrAccordSpec
		}
		if err := pub.VerifyBit(ob.ApproveCT, ob.ApproveProof, sealedProofDomain(v.ID, cmd.Actor, ob.OptionID, sealedSlotApprove)); err != nil {
			return ErrAccordEvidence
		}
		if err := pub.VerifyBit(ob.DissentCT, ob.DissentProof, sealedProofDomain(v.ID, cmd.Actor, ob.OptionID, sealedSlotDissent)); err != nil {
			return ErrAccordEvidence
		}
		exclCT, err := pub.Add(ob.ApproveCT, ob.DissentCT)
		if err != nil {
			return ErrAccordEvidence
		}
		if err := pub.VerifyBit(exclCT, ob.ExclusiveProof, sealedProofDomain(v.ID, cmd.Actor, ob.OptionID, sealedSlotExclusive)); err != nil {
			return ErrAccordEvidence
		}
		if a.spec.Rules.BallotMode == BallotSingleChoice {
			prodApproveCT, err = pub.Add(prodApproveCT, ob.ApproveCT)
			if err != nil {
				return ErrAccordEvidence
			}
		}
		recordedOpts[i] = RecordedSealedOption{
			OptionID:  ob.OptionID,
			ApproveCT: slices.Clone(ob.ApproveCT),
			DissentCT: slices.Clone(ob.DissentCT),
		}
	}

	if a.spec.Rules.BallotMode == BallotSingleChoice {
		if err := pub.VerifyBit(prodApproveCT, vp.Sealed.SingleChoiceProof, sealedProofDomain(v.ID, cmd.Actor, "", sealedSlotSingleChoice)); err != nil {
			return ErrAccordEvidence
		}
	}

	var roles []string
	if len(grant.DomainRoles) > 0 {
		roles = slices.Clone(grant.DomainRoles)
		slices.Sort(roles)
	}
	v.SealedBallots = append(v.SealedBallots, RecordedSealedBallot{
		Actor:         cmd.Actor,
		GrantID:       cmd.GrantID,
		Weight:        grant.Weight,
		DomainRoles:   roles,
		Options:       recordedOpts,
		RationaleHash: vp.Sealed.RationaleHash,
		Height:        height,
		ReceiptHash:   receipt,
	})
	sortRecordedSealedBallots(v.SealedBallots)
	return nil
}

type sealedOptionAggregates struct {
	optionID        string
	approveCountCT  []byte
	approveWeightCT []byte
	dissentCountCT  []byte
	dissentWeightCT []byte
	requiredRoles   []RoleRequirement
	roleCountCT     map[string][]byte
	roleWeightCT    map[string][]byte
}

func computeSealedAggregates(spec AccordSpec, view AccordView) ([]sealedOptionAggregates, error) {
	pub, err := he.FromPublic(spec.SealedTally.PublicKey)
	if err != nil {
		return nil, ErrAccordSpec
	}

	aggs := make([]sealedOptionAggregates, len(view.Options))
	for i, ro := range view.Options {
		reqs := mergeMandatoryRoles(spec.Rules.MandatoryRoles, ro.Option.ExtraMandatoryRoles)
		rc := make(map[string][]byte, len(reqs))
		rw := make(map[string][]byte, len(reqs))
		for _, r := range reqs {
			rc[r.Role] = []byte{1}
			rw[r.Role] = []byte{1}
		}
		aggs[i] = sealedOptionAggregates{
			optionID:        ro.Option.ID,
			approveCountCT:  []byte{1},
			approveWeightCT: []byte{1},
			dissentCountCT:  []byte{1},
			dissentWeightCT: []byte{1},
			requiredRoles:   reqs,
			roleCountCT:     rc,
			roleWeightCT:    rw,
		}
	}

	for _, ballot := range view.SealedBallots {
		if len(ballot.Options) != len(view.Options) {
			return nil, ErrAccordEvidence
		}
		for i, ob := range ballot.Options {
			if ob.OptionID != aggs[i].optionID {
				return nil, ErrAccordEvidence
			}
			agg := &aggs[i]
			agg.approveCountCT, err = pub.Add(agg.approveCountCT, ob.ApproveCT)
			if err != nil {
				return nil, ErrAccordEvidence
			}
			wApproveCT, err := pub.Scale(ob.ApproveCT, ballot.Weight)
			if err != nil {
				return nil, ErrAccordEvidence
			}
			agg.approveWeightCT, err = pub.Add(agg.approveWeightCT, wApproveCT)
			if err != nil {
				return nil, ErrAccordEvidence
			}

			agg.dissentCountCT, err = pub.Add(agg.dissentCountCT, ob.DissentCT)
			if err != nil {
				return nil, ErrAccordEvidence
			}
			wDissentCT, err := pub.Scale(ob.DissentCT, ballot.Weight)
			if err != nil {
				return nil, ErrAccordEvidence
			}
			agg.dissentWeightCT, err = pub.Add(agg.dissentWeightCT, wDissentCT)
			if err != nil {
				return nil, ErrAccordEvidence
			}

			for _, req := range agg.requiredRoles {
				if slices.Contains(ballot.DomainRoles, req.Role) {
					agg.roleCountCT[req.Role], err = pub.Add(agg.roleCountCT[req.Role], ob.ApproveCT)
					if err != nil {
						return nil, ErrAccordEvidence
					}
					agg.roleWeightCT[req.Role], err = pub.Add(agg.roleWeightCT[req.Role], wApproveCT)
					if err != nil {
						return nil, ErrAccordEvidence
					}
				}
			}
		}
	}

	return aggs, nil
}

func computeSealedParticipation(ballots []RecordedSealedBallot) (count uint64, weight uint64) {
	seen := make(map[string]struct{}, len(ballots))
	for _, b := range ballots {
		if _, ok := seen[b.Actor]; !ok {
			seen[b.Actor] = struct{}{}
			count++
			weight += b.Weight
		}
	}
	return count, weight
}

func (a *Accord) applySealedResolve(view AccordView, cmd AccordCommand, height uint64) (AccordOutcome, error) {
	if a.spec.SealedTally == nil || cmd.Actor != a.spec.SealedTally.TallyAuthority {
		return AccordOutcome{}, ErrAccordAuthority
	}
	st := cmd.Resolve.SealedTally
	if st == nil || len(st.Options) != len(view.Options) {
		return AccordOutcome{}, ErrAccordEvidence
	}

	pub, err := he.FromPublic(a.spec.SealedTally.PublicKey)
	if err != nil {
		return AccordOutcome{}, ErrAccordEvidence
	}
	aggs, err := computeSealedAggregates(a.spec, view)
	if err != nil {
		return AccordOutcome{}, err
	}

	partCount, partWeight := computeSealedParticipation(view.SealedBallots)
	facts := factsMapFromSlice(view.Evidence)
	vetoesByOption := make(map[string][]RecordedVeto, len(view.Options))
	for _, vt := range view.Vetoes {
		vetoesByOption[vt.OptionID] = append(vetoesByOption[vt.OptionID], vt)
	}

	verifyTally := func(ct []byte, val uint64, proof []byte) bool {
		ok, err := pub.VerifyEqual(ct, new(big.Int).SetUint64(val), proof)
		return err == nil && ok
	}

	tallies := make([]OptionTally, len(view.Options))
	passedWithoutVeto := make(map[string]bool, len(view.Options))

	for i, ro := range view.Options {
		opt := ro.Option
		optProof := st.Options[i]
		agg := aggs[i]
		if optProof.OptionID != opt.ID {
			return AccordOutcome{}, ErrAccordEvidence
		}
		if optProof.ApproveCount > partCount || optProof.DissentCount > partCount ||
			optProof.ApproveCount > partCount-optProof.DissentCount ||
			optProof.ApproveWeight > partWeight || optProof.DissentWeight > partWeight ||
			optProof.ApproveWeight > partWeight-optProof.DissentWeight {
			return AccordOutcome{}, ErrAccordEvidence
		}
		if !verifyTally(agg.approveCountCT, optProof.ApproveCount, optProof.ApproveCountProof) ||
			!verifyTally(agg.approveWeightCT, optProof.ApproveWeight, optProof.ApproveWeightProof) ||
			!verifyTally(agg.dissentCountCT, optProof.DissentCount, optProof.DissentCountProof) ||
			!verifyTally(agg.dissentWeightCT, optProof.DissentWeight, optProof.DissentWeightProof) {
			return AccordOutcome{}, ErrAccordEvidence
		}

		if len(optProof.RoleTallies) != len(agg.requiredRoles) {
			return AccordOutcome{}, ErrAccordEvidence
		}
		var missingRoles []string
		for j, req := range agg.requiredRoles {
			rt := optProof.RoleTallies[j]
			if rt.Role != req.Role || rt.ApproveCount > optProof.ApproveCount || rt.ApproveWeight > optProof.ApproveWeight {
				return AccordOutcome{}, ErrAccordEvidence
			}
			if !verifyTally(agg.roleCountCT[req.Role], rt.ApproveCount, rt.ApproveCountProof) ||
				!verifyTally(agg.roleWeightCT[req.Role], rt.ApproveWeight, rt.ApproveWeightProof) {
				return AccordOutcome{}, ErrAccordEvidence
			}
			if rt.ApproveCount < req.MinApprovals || rt.ApproveWeight < req.MinWeight {
				missingRoles = append(missingRoles, req.Role)
			}
		}
		slices.Sort(missingRoles)

		gs := evaluateOptionGuard(opt, facts)
		tally := OptionTally{
			OptionID:             opt.ID,
			Priority:             opt.Priority,
			GuardPassed:          gs.Passed,
			SatisfiedEvidenceIDs: gs.SatisfiedEvidenceIDs,
			FailedPredicates:     gs.FailedPredicates,
			ApproveCount:         optProof.ApproveCount,
			ApproveWeight:        optProof.ApproveWeight,
			DissentCount:         optProof.DissentCount,
			DissentWeight:        optProof.DissentWeight,
			MissingRoles:         missingRoles,
		}
		finalized, nonVetoOK := finalizeOptionTally(tally, vetoesByOption[opt.ID], a.spec.Rules)
		passedWithoutVeto[opt.ID] = nonVetoOK
		tallies[i] = finalized
	}

	return evaluateAccordOutcomeFromTallies(a.spec, view, partCount, partWeight, tallies, passedWithoutVeto, cmd.Actor, height, cmd.Resolve.ReasonHash), nil
}

func sortRecordedSealedBallots(ballots []RecordedSealedBallot) {
	slices.SortFunc(ballots, func(a, b RecordedSealedBallot) int {
		return strings.Compare(a.Actor, b.Actor)
	})
}

func validSealedTallyConfigStrings(cfg *SealedTallyConfig) bool {
	if cfg == nil {
		return true
	}
	return validUTF8NoControl(cfg.TallyAuthority)
}

func validSealedBallotStrings(s *SealedBallotPayload) bool {
	if s == nil {
		return true
	}
	if !validUTF8NoControl(s.RationaleHash) {
		return false
	}
	for _, ob := range s.Options {
		if !validUTF8NoControl(ob.OptionID) {
			return false
		}
	}
	return true
}

func validSealedTallyProofStrings(p *SealedTallyProof) bool {
	if p == nil {
		return true
	}
	for _, opt := range p.Options {
		if !validUTF8NoControl(opt.OptionID) {
			return false
		}
		for _, rt := range opt.RoleTallies {
			if !validUTF8NoControl(rt.Role) {
				return false
			}
		}
	}
	return true
}

func cloneSealedTallyConfig(cfg *SealedTallyConfig) *SealedTallyConfig {
	if cfg == nil {
		return nil
	}
	out := *cfg
	out.PublicKey = slices.Clone(cfg.PublicKey)
	return &out
}

func cloneSealedBallotPayload(s *SealedBallotPayload) *SealedBallotPayload {
	if s == nil {
		return nil
	}
	out := *s
	out.SingleChoiceProof = slices.Clone(s.SingleChoiceProof)
	if s.Options != nil {
		out.Options = make([]SealedOptionBallot, len(s.Options))
		for i, ob := range s.Options {
			out.Options[i] = SealedOptionBallot{
				OptionID:          ob.OptionID,
				ApproveCT:         slices.Clone(ob.ApproveCT),
				ApproveProof:      slices.Clone(ob.ApproveProof),
				DissentCT:         slices.Clone(ob.DissentCT),
				DissentProof:      slices.Clone(ob.DissentProof),
				ExclusiveProof:    slices.Clone(ob.ExclusiveProof),
				DissentRandomness: slices.Clone(ob.DissentRandomness),
			}
		}
	}
	return &out
}

func cloneSealedTallyProof(p *SealedTallyProof) *SealedTallyProof {
	if p == nil {
		return nil
	}
	var out SealedTallyProof
	if p.Options != nil {
		out.Options = make([]SealedOptionTallyProof, len(p.Options))
		for i, opt := range p.Options {
			co := SealedOptionTallyProof{
				OptionID:           opt.OptionID,
				ApproveCount:       opt.ApproveCount,
				ApproveCountProof:  slices.Clone(opt.ApproveCountProof),
				ApproveWeight:      opt.ApproveWeight,
				ApproveWeightProof: slices.Clone(opt.ApproveWeightProof),
				DissentCount:       opt.DissentCount,
				DissentCountProof:  slices.Clone(opt.DissentCountProof),
				DissentWeight:      opt.DissentWeight,
				DissentWeightProof: slices.Clone(opt.DissentWeightProof),
			}
			if opt.RoleTallies != nil {
				co.RoleTallies = make([]SealedRoleTallyProof, len(opt.RoleTallies))
				for j, rt := range opt.RoleTallies {
					co.RoleTallies[j] = SealedRoleTallyProof{
						Role:               rt.Role,
						ApproveCount:       rt.ApproveCount,
						ApproveCountProof:  slices.Clone(rt.ApproveCountProof),
						ApproveWeight:      rt.ApproveWeight,
						ApproveWeightProof: slices.Clone(rt.ApproveWeightProof),
					}
				}
			}
			out.Options[i] = co
		}
	}
	return &out
}

func cloneRecordedSealedBallots(ballots []RecordedSealedBallot) []RecordedSealedBallot {
	if len(ballots) == 0 {
		return nil
	}
	out := make([]RecordedSealedBallot, len(ballots))
	for i, b := range ballots {
		cb := RecordedSealedBallot{
			Actor:         b.Actor,
			GrantID:       b.GrantID,
			Weight:        b.Weight,
			DomainRoles:   cloneNonEmptyStrings(b.DomainRoles),
			RationaleHash: b.RationaleHash,
			Height:        b.Height,
			ReceiptHash:   b.ReceiptHash,
		}
		if len(b.Options) > 0 {
			cb.Options = make([]RecordedSealedOption, len(b.Options))
			for j, ob := range b.Options {
				cb.Options[j] = RecordedSealedOption{
					OptionID:  ob.OptionID,
					ApproveCT: slices.Clone(ob.ApproveCT),
					DissentCT: slices.Clone(ob.DissentCT),
				}
			}
		}
		out[i] = cb
	}
	return out
}
