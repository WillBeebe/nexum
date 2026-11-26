package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

type accordActor struct {
	id  nex.Identity
	pub nex.Public
}

func newAccordActor(t *testing.T) accordActor {
	t.Helper()
	id, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return accordActor{id: id, pub: mustPublic(t, id)}
}

type accordWorld struct {
	release   accordActor
	sre       accordActor
	safety    accordActor
	security  accordActor
	authority nex.Identity
	authPub   nex.Public
	store     *nex.AccordStore
	dir       string
	key       []byte
	id        string
	spec      nex.AccordSpec
	height    *atomic.Uint64
	inner     *AccordAuthority
}

func makeCompletedProtocolEvidence(t *testing.T, large bool) (nex.ProtocolBundle, accordActor) {
	t.Helper()
	owner := newAccordActor(t)
	worker := newAccordActor(t)
	witness := newAccordActor(t)
	scope := "accord/evidence"
	grant := func(id string, actor accordActor, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{
			ID:                 id,
			Actor:              actor.pub.ID(),
			Label:              id,
			Scope:              scope,
			Permissions:        perms,
			ExpiresAtHeight:    40,
			LimitsHash:         nex.Hash("limit:" + id),
			EvidenceObligation: nex.Hash("obl:" + id),
		}
	}
	spec := nex.ProtocolSpec{
		Version:           nex.ProtocolVersionV2,
		Nonce:             "ev-proto-v2",
		Purpose:           "Produce verified audit bundle",
		IntendedOutcome:   "Audit accepted",
		Scope:             scope,
		SpecificationHash: nex.Hash("ev-spec"),
		AcceptanceHash:    nex.Hash("ev-acc"),
		FailurePolicyHash: nex.Hash("ev-fail"),
		Initiator:         owner.pub.ID(),
		Participants:      []nex.Public{owner.pub, worker.pub, witness.pub},
		Roles: []nex.RoleGrant{
			grant("owner", owner, nex.PermitCommit, nex.PermitDecide, nex.PermitReturn),
			grant("worker", worker, nex.PermitWork, nex.PermitReturn),
			grant("witness", witness, nex.PermitReview),
		},
		WorkByHeight:      20,
		ReturnByHeight:    40,
		RequiredWitnesses: []string{witness.pub.ID()},
		DissentPolicy:     "record",
		Return: nex.ReturnRequirements{
			SuccessArtifacts:   []string{"audit"},
			FailureArtifacts:   []string{"failure"},
			AllowedDisposition: []string{"continue", "retry", "refuse"},
		},
		MaxEvents: 32,
	}
	store, err := nex.OpenProtocolStore(filepath.Join(t.TempDir(), "ev-protos"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := store.Create(spec)
	if err != nil {
		t.Fatal(err)
	}
	applyProto := func(actor accordActor, grantID, action, reqID string, height uint64, fill func(*nex.ProtocolCommand)) {
		t.Helper()
		cmd, err := store.Prepare(pid, actor.pub.ID(), grantID, scope, action, reqID, height)
		if err != nil {
			t.Fatal(err)
		}
		if action == "admit" {
			cmd.GrantID = ""
			cmd.Scope = ""
		}
		if fill != nil {
			fill(&cmd)
		}
		if _, err := store.Apply(pid, cmd, nex.Sign(actor.id, "protocol", cmd), height); err != nil {
			t.Fatalf("%s/%s: %v", action, reqID, err)
		}
	}

	content := []byte("verified-audit-artifact")
	sum := sha256.Sum256(content)
	artRef := nex.ArtifactRef{
		Digest:    hex.EncodeToString(sum[:]),
		Size:      uint64(len(content)),
		MediaType: "text/plain",
	}
	inputs := []nex.NamedArtifact(nil)
	outputs := []nex.NamedArtifact{{Name: "audit", Ref: artRef}}
	returnArts := []nex.ReturnArtifact{{ID: "audit", Commitment: artRef.Digest, ReuseRestrictions: "cite"}}
	var claims []string
	uncertainty := "none"
	assumptions := []string{"audited"}
	if large {
		for i := 0; i < 64; i++ {
			inName := fmt.Sprintf("in-%02d-%s", i, strings.Repeat("i", 110))
			inputs = append(inputs, nex.NamedArtifact{Name: inName, Ref: artRef})
			claims = append(claims, nex.Hash(fmt.Sprintf("claim-%d", i)))
		}
		for i := 0; i < 63; i++ {
			outName := fmt.Sprintf("out-%02d-%s", i, strings.Repeat("o", 110))
			outputs = append(outputs, nex.NamedArtifact{Name: outName, Ref: artRef})
			returnArts = append(returnArts, nex.ReturnArtifact{
				ID:                outName,
				Commitment:        artRef.Digest,
				ReuseRestrictions: strings.Repeat("r", 120),
			})
		}
		uncertainty = strings.Repeat("u", 3000)
		assumptions = nil
		for i := 0; i < 28; i++ {
			assumptions = append(assumptions, fmt.Sprintf("assumption-%02d-%s", i, strings.Repeat("a", 980)))
		}
	}

	applyProto(owner, "", "admit", "admit-o", 1, nil)
	applyProto(worker, "", "admit", "admit-w", 2, nil)
	applyProto(witness, "", "admit", "admit-wit", 3, nil)
	applyProto(owner, "owner", "commit", "commit-1", 4, nil)
	applyProto(worker, "worker", "report", "report-1", 5, func(c *nex.ProtocolCommand) {
		c.Report = &nex.WorkReport{
			Outcome:    nex.WorkCompleted,
			Stage:      "audit",
			ReasonHash: nex.Hash("audit-ok"),
			Evidence:   []string{artRef.Digest},
			Manifest: &nex.EvidenceManifest{
				MethodHash: nex.Hash("method"),
				Inputs:     inputs,
				Outputs:    outputs,
				Claims:     claims,
			},
		}
	})
	vRep, err := store.View(pid)
	if err != nil {
		t.Fatal(err)
	}
	applyProto(witness, "witness", "review", "review-1", 6, func(c *nex.ProtocolCommand) {
		c.Review = &nex.WitnessReview{
			ReportHash:     nex.Hash(vRep.Report),
			AssessmentHash: nex.Hash("verified"),
			Dissent:        false,
		}
	})
	applyProto(owner, "owner", "resolve", "resolve-1", 7, func(c *nex.ProtocolCommand) {
		c.Resolution = &nex.Resolution{
			ReportHash: nex.Hash(vRep.Report),
			Outcome:    "accept",
			ReasonHash: nex.Hash("accept-audit"),
		}
	})
	vRes, err := store.View(pid)
	if err != nil {
		t.Fatal(err)
	}
	applyProto(worker, "worker", "return", "return-1", 8, func(c *nex.ProtocolCommand) {
		c.Return = &nex.ReturnManifest{
			ResolutionHash:  nex.Hash(vRes.Resolution),
			ReviewsHash:     nex.Hash(vRes.Reviews),
			Evidence:        []string{artRef.Digest},
			Uncertainty:     uncertainty,
			SafeAssumptions: assumptions,
			Artifacts:       returnArts,
			Disposition:     "continue",
		}
	})
	bundle, err := store.Export(pid)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, owner
}

func newAccordWorld(t *testing.T, allowProposals bool) (accordWorld, nex.ProtocolBundle) {
	t.Helper()
	release := newAccordActor(t)
	sre := newAccordActor(t)
	safety := newAccordActor(t)
	security := newAccordActor(t)
	authority, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	bundle, _ := makeCompletedProtocolEvidence(t, false)
	scope := "release/v2"
	spec := nex.AccordSpec{
		Version:      nex.AccordVersion,
		Nonce:        "adapter-accord-v1",
		Purpose:      "Choose rollout path via adapter outbox",
		Scope:        scope,
		PolicyHash:   nex.Hash("policy-v1"),
		Participants: []nex.Public{release.pub, sre.pub, safety.pub, security.pub},
		Roles: []nex.AccordRoleGrant{
			{
				ID: "release-propose", Actor: release.pub.ID(), Scope: scope,
				Permissions: []nex.AccordPermission{nex.AccordPermitAttest}, ExpiresAtHeight: 15, LimitsHash: nex.Hash("att"),
			},
			{
				ID: "release-vote", Actor: release.pub.ID(), Scope: scope,
				DomainRoles: []string{"release"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote, nex.AccordPermitResolve},
				Weight: 2, ExpiresAtHeight: 20, LimitsHash: nex.Hash("rel"),
			},
			{
				ID: "sre-vote", Actor: sre.pub.ID(), Scope: scope,
				DomainRoles: []string{"sre"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("sre"),
			},
			{
				ID: "safety-vote", Actor: safety.pub.ID(), Scope: scope,
				DomainRoles: []string{"safety"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote, nex.AccordPermitVeto},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("saf"),
			},
			{
				ID: "security-vote", Actor: security.pub.ID(), Scope: scope,
				DomainRoles: []string{"security"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote, nex.AccordPermitResolve},
				Weight: 1, ExpiresAtHeight: 20, LimitsHash: nex.Hash("sec"),
			},
		},
		Evidence: []nex.EvidenceSlot{
			{
				ID:                "audit",
				Kind:              nex.EvidenceProtocolBundle,
				ProtocolID:        nex.Hash(bundle.Spec),
				ExpectedAuthority: bundle.Spec.Initiator,
				ExpectedHead:      bundle.Events[len(bundle.Events)-1].ReceiptHash,
			},
		},
		VoteByHeight:    10,
		ResolveByHeight: 20,
		Rules: nex.DecisionRules{
			BallotMode:              nex.BallotApproval,
			MinParticipationCount:   2,
			MinParticipationWeight:  4,
			MinApprovalCount:        2,
			MinApprovalWeight:       4,
			MinApprovalMarginWeight: 1,
			MandatoryRoles:          []nex.RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 2}},
			Veto: nex.VetoPolicy{
				Mode:               nex.VetoBlocking,
				MaxVetoesPerActor:  1,
				RequireEvidence:    true,
				AllowedDomainRoles: []string{"safety"},
			},
			TieBreak: nex.TieBreakLowestPriority,
		},
		MaxEvents: 64,
	}

	optCanary := nex.AccordOption{
		ID:       "canary-rollout",
		Title:    "Canary rollout",
		Priority: 1,
		Guard: nex.OptionGuard{
			AllOf: []nex.EvidencePredicate{
				{EvidenceID: "audit", Op: nex.GuardOutcomeIn, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}},
				{EvidenceID: "audit", Op: nex.GuardNoWitnessDissent},
			},
		},
		Binding: nex.OptionBinding{
			Kind:           nex.BindingDisposition,
			Disposition:    "continue",
			ActionHash:     nex.Hash("canary-act"),
			ParametersHash: nex.Hash("canary-params"),
		},
	}
	optHold := nex.AccordOption{
		ID:       "hold-release",
		Title:    "Hold release",
		Priority: 2,
		Binding: nex.OptionBinding{
			Kind:           nex.BindingDisposition,
			Disposition:    "hold",
			ActionHash:     nex.Hash("hold-act"),
			ParametersHash: nex.Hash("hold-params"),
		},
	}

	if allowProposals {
		spec.AllowProposals = true
		spec.ProposalByHeight = 5
		spec.Roles[0].Permissions = []nex.AccordPermission{nex.AccordPermitPropose, nex.AccordPermitAttest}
	} else {
		spec.Options = []nex.AccordOption{optCanary, optHold}
	}

	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "accords")
	store, err := nex.OpenAccordStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(spec)
	if err != nil {
		t.Fatal(err)
	}

	w := accordWorld{
		release:   release,
		sre:       sre,
		safety:    safety,
		security:  security,
		authority: authority,
		authPub:   mustPublic(t, authority),
		store:     store,
		dir:       dir,
		key:       key,
		id:        id,
		spec:      spec,
		height:    &atomic.Uint64{},
	}
	w.height.Store(1)
	w.inner = &AccordAuthority{
		Tenant: tenant,
		Store:  store,
		Height: func() uint64 { return w.height.Load() },
	}
	return w, bundle
}

func (w *accordWorld) buildItem(t *testing.T, actor accordActor, grant, action, reqID string, height uint64, fill func(*nex.AccordCommand)) OutboundItem {
	t.Helper()
	cmd, err := w.store.Prepare(w.id, actor.pub.ID(), grant, w.spec.Scope, action, reqID, height)
	if err != nil {
		t.Fatal(err)
	}
	if fill != nil {
		fill(&cmd)
	}
	sig, err := nex.SignAccordCommand(actor.id, cmd)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeAccord(cmd, sig)
	if err != nil {
		t.Fatal(err)
	}
	return OutboundItem{
		Version:      Version,
		Tenant:       tenant,
		AgreementID:  w.id,
		OperationID:  reqID,
		Kind:         KindAccord,
		SignedObject: raw,
		Destination:  "accord-authority-1",
		CreatedAt:    time.Now().UTC(),
	}
}

func (w *accordWorld) enqueue(t *testing.T, o *Outbox, actor accordActor, grant, action, reqID string, height uint64, fill func(*nex.AccordCommand)) OutboundItem {
	t.Helper()
	item := w.buildItem(t, actor, grant, action, reqID, height, fill)
	if err := o.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	return item
}

func (w *accordWorld) apply(t *testing.T, o *Outbox, actor accordActor, grant, action, reqID string, height uint64, fill func(*nex.AccordCommand)) AuthenticatedResponse {
	t.Helper()
	w.height.Store(height)
	w.enqueue(t, o, actor, grant, action, reqID, height, fill)
	resp, err := o.Reconcile(tenant, reqID, w.inner)
	if err != nil {
		t.Fatalf("%s/%s Reconcile: %v (resp=%+v)", action, reqID, err, resp)
	}
	if err := o.RecordVerified(tenant, reqID, resp, w.authPub, SignAuthorityResponse(w.authority, resp)); err != nil {
		t.Fatalf("%s/%s RecordVerified: %v", action, reqID, err)
	}
	return resp
}

func TestEncodeDecodeAccordAndStrictPayload(t *testing.T) {
	w, _ := newAccordWorld(t, false)
	cmd, err := w.store.Prepare(w.id, w.sre.pub.ID(), "sre-vote", w.spec.Scope, "vote", "vote-enc-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	sig, err := nex.SignAccordCommand(w.sre.id, cmd)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeAccord(cmd, sig)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePayload(raw)
	if err != nil || p.Kind != KindAccord || p.Accord == nil || p.Operation != nil || p.Command != nil {
		t.Fatalf("DecodePayload valid accord failed: %+v %v", p, err)
	}
	if p.Accord.AccordID != w.id || p.Accord.RequestID != "vote-enc-1" || p.Height != 2 {
		t.Fatalf("unexpected decoded accord payload: %+v", p)
	}

	// Reject 0, 2, or 3 populated payload fields, kind mismatches, and missing IDs/signatures.
	badPayloads := []struct {
		name string
		raw  string
	}{
		{"zero_populated", `{"version":1,"kind":"accord","signature":"YQ=="}`},
		{"op_and_accord", `{"version":1,"kind":"accord","operation":{"id":"r"},"accord":{"request_id":"r","accord_id":"a"},"signature":"YQ=="}`},
		{"cmd_and_accord", `{"version":1,"kind":"accord","command":{"protocol_id":"p","request_id":"r"},"accord":{"request_id":"r","accord_id":"a"},"signature":"YQ=="}`},
		{"all_three", `{"version":1,"kind":"accord","operation":{"id":"r"},"command":{"protocol_id":"p","request_id":"r"},"accord":{"request_id":"r","accord_id":"a"},"signature":"YQ=="}`},
		{"kind_protocol_with_accord", `{"version":1,"kind":"protocol","accord":{"request_id":"r","accord_id":"a"},"signature":"YQ=="}`},
		{"kind_agreement_with_accord", `{"version":1,"kind":"agreement","accord":{"request_id":"r","accord_id":"a"},"signature":"YQ=="}`},
		{"kind_accord_with_cmd", `{"version":1,"kind":"accord","command":{"protocol_id":"p","request_id":"r"},"signature":"YQ=="}`},
		{"missing_request_id", `{"version":1,"kind":"accord","accord":{"accord_id":"a"},"signature":"YQ=="}`},
		{"missing_accord_id", `{"version":1,"kind":"accord","accord":{"request_id":"r"},"signature":"YQ=="}`},
		{"missing_signature", `{"version":1,"kind":"accord","accord":{"request_id":"r","accord_id":"a"}}`},
		{"wrong_version", `{"version":2,"kind":"accord","accord":{"request_id":"r","accord_id":"a"},"signature":"YQ=="}`},
		{"unknown_kind", `{"version":1,"kind":"other","accord":{"request_id":"r","accord_id":"a"},"signature":"YQ=="}`},
	}
	for _, tc := range badPayloads {
		if _, err := DecodePayload([]byte(tc.raw)); !errors.Is(err, ErrItem) {
			t.Fatalf("%s: expected ErrItem, got %v", tc.name, err)
		}
	}
}

func TestAccordOutboxValidateAndResponseShape(t *testing.T) {
	w, _ := newAccordWorld(t, false)
	o := testOutbox(t)

	item := w.buildItem(t, w.sre, "sre-vote", "vote", "v-shape", 2, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("r")}
	})

	badAccordID := item
	badAccordID.AgreementID = "different-accord"
	if err := o.Enqueue(badAccordID); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for AccordID mismatch, got %v", err)
	}

	badReqID := item
	badReqID.OperationID = "different-op"
	if err := o.Enqueue(badReqID); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for RequestID mismatch, got %v", err)
	}

	badKind := item
	badKind.Kind = KindProtocol
	if err := o.Enqueue(badKind); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for Kind mismatch, got %v", err)
	}

	// Zero Height in AccordCommand must fail Outbox.Enqueue.
	zeroCmd, err := w.store.Prepare(w.id, w.sre.pub.ID(), "sre-vote", w.spec.Scope, "vote", "v-zero-h", 0)
	if err != nil {
		t.Fatal(err)
	}
	zeroCmd.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("r")}
	zeroRaw, err := EncodeAccord(zeroCmd, nex.Sign(w.sre.id, nex.AccordCommandDomain, zeroCmd))
	if err != nil {
		t.Fatal(err)
	}
	zeroItem := item
	zeroItem.OperationID = "v-zero-h"
	zeroItem.SignedObject = zeroRaw
	if err := o.Enqueue(zeroItem); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for Height==0 in validateItem, got %v", err)
	}

	// Enqueue valid item and verify response shape constraints in Reconcile and RecordVerified.
	if err := o.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	badRespResultAuth := &scriptedAuthority{
		apply: func(it OutboundItem) (AuthenticatedResponse, error) {
			return AuthenticatedResponse{
				Version:     Version,
				Tenant:      it.Tenant,
				AgreementID: it.AgreementID,
				RequestID:   it.OperationID,
				CommandHash: CommandHash(it.SignedObject),
				Kind:        ResultAgreement,
				Result:      &nex.Result{Head: nex.Hash("unexpected-result")},
				ReceiptHead: nex.Hash("unexpected-result"),
			}, nil
		},
	}
	if _, err := o.Reconcile(tenant, item.OperationID, badRespResultAuth); !errors.Is(err, ErrResponse) {
		t.Fatalf("expected ErrResponse for non-nil Result on KindAccord, got %v", err)
	}
	missingHeadAuth := &scriptedAuthority{
		apply: func(it OutboundItem) (AuthenticatedResponse, error) {
			return AuthenticatedResponse{
				Version:     Version,
				Tenant:      it.Tenant,
				AgreementID: it.AgreementID,
				RequestID:   it.OperationID,
				CommandHash: CommandHash(it.SignedObject),
				Kind:        ResultAgreement,
			}, nil
		},
	}
	if _, err := o.Reconcile(tenant, item.OperationID, missingHeadAuth); !errors.Is(err, ErrResponse) {
		t.Fatalf("expected ErrResponse for empty ReceiptHead on KindAccord, got %v", err)
	}
	badRecordResp := AuthenticatedResponse{
		Version:     Version,
		Tenant:      tenant,
		AgreementID: w.id,
		RequestID:   item.OperationID,
		CommandHash: CommandHash(item.SignedObject),
		Kind:        ResultAgreement,
		Result:      &nex.Result{Head: nex.Hash("h")},
		ReceiptHead: nex.Hash("h"),
	}
	if err := o.RecordVerified(tenant, item.OperationID, badRecordResp, w.authPub, SignAuthorityResponse(w.authority, badRecordResp)); !errors.Is(err, ErrResponse) {
		t.Fatalf("expected ErrResponse on RecordVerified with non-nil Result, got %v", err)
	}
}

func TestAccordAuthorityLifecycleProposeAttestVoteVetoResolve(t *testing.T) {
	w, bundle := newAccordWorld(t, true)
	o := testOutbox(t)

	// Open view before any commands.
	openSnap, err := w.inner.View(tenant, w.id)
	if err != nil {
		t.Fatal(err)
	}
	if openSnap.AgreementID != w.id || openSnap.Head != w.id || openSnap.Phase != string(nex.AccordPhaseOpen) || openSnap.WorkOutcome != "" {
		t.Fatalf("unexpected initial ViewSnapshot: %+v", openSnap)
	}

	// 1. Propose two options during [1, ProposalByHeight=5).
	w.apply(t, o, w.release, "release-propose", "propose", "prop-canary", 1, func(c *nex.AccordCommand) {
		c.Propose = &nex.ProposePayload{Option: nex.AccordOption{
			ID:       "canary-rollout",
			Title:    "Canary rollout",
			Priority: 1,
			Guard: nex.OptionGuard{
				AllOf: []nex.EvidencePredicate{
					{EvidenceID: "audit", Op: nex.GuardOutcomeIn, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}},
					{EvidenceID: "audit", Op: nex.GuardNoWitnessDissent},
				},
			},
			Binding: nex.OptionBinding{
				Kind:           nex.BindingDisposition,
				Disposition:    "continue",
				ActionHash:     nex.Hash("canary-act"),
				ParametersHash: nex.Hash("canary-params"),
			},
		}}
	})
	w.apply(t, o, w.release, "release-propose", "propose", "prop-hold", 2, func(c *nex.AccordCommand) {
		c.Propose = &nex.ProposePayload{Option: nex.AccordOption{
			ID:       "hold-release",
			Title:    "Hold release",
			Priority: 2,
			Binding: nex.OptionBinding{
				Kind:           nex.BindingDisposition,
				Disposition:    "hold",
				ActionHash:     nex.Hash("hold-act"),
				ParametersHash: nex.Hash("hold-params"),
			},
		}}
	})

	// 2. Attest evidence bundle.
	w.apply(t, o, w.release, "release-propose", "attest", "att-audit", 3, func(c *nex.AccordCommand) {
		c.Attest = &nex.AttestPayload{EvidenceID: "audit", Protocol: &bundle}
	})

	// 3. Dissent + Veto on hold-release during [ProposalByHeight=5, VoteByHeight=10).
	w.apply(t, o, w.safety, "safety-vote", "vote", "saf-dissent-hold", 5, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "hold-release", Position: nex.BallotDissent, RationaleHash: nex.Hash("prefer-canary")}
	})
	w.apply(t, o, w.safety, "safety-vote", "veto", "saf-veto-hold", 6, func(c *nex.AccordCommand) {
		c.Veto = &nex.VetoPayload{OptionID: "hold-release", ReasonHash: nex.Hash("unsafe-hold"), EvidenceIDs: []string{"audit"}}
	})

	// 4. Approve canary-rollout (safety=2 + sre=2 + security=1 = 5; release=2 dissents -> margin 3 >= 1).
	w.apply(t, o, w.safety, "safety-vote", "vote", "saf-app-canary", 7, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	})
	w.apply(t, o, w.sre, "sre-vote", "vote", "sre-app-canary", 8, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	})
	w.apply(t, o, w.security, "security-vote", "vote", "sec-app-canary", 8, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	})
	w.apply(t, o, w.release, "release-vote", "vote", "rel-dis-canary", 9, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotDissent, RationaleHash: nex.Hash("dissent")}
	})

	// 5. Resolve at VoteByHeight=10.
	resResp := w.apply(t, o, w.security, "security-vote", "resolve", "res-1", 10, func(c *nex.AccordCommand) {
		c.Resolve = &nex.ResolvePayload{ReasonHash: nex.Hash("complete")}
	})
	if resResp.Result != nil || resResp.ReceiptHead == "" {
		t.Fatalf("unexpected resolve response: %+v", resResp)
	}

	snap, err := w.inner.View(tenant, w.id)
	if err != nil {
		t.Fatal(err)
	}
	if snap.AgreementID != w.id || snap.Head != resResp.ReceiptHead || snap.Phase != string(nex.AccordPhaseDecided) || snap.WorkOutcome != "canary-rollout" {
		t.Fatalf("unexpected decided ViewSnapshot: %+v", snap)
	}

	exported, err := w.store.Export(w.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nex.VerifyAccordBundle(exported, w.id, resResp.ReceiptHead); err != nil {
		t.Fatalf("VerifyAccordBundle failed: %v", err)
	}
}

func TestAccordAuthorityLargeAttestAndExpireView(t *testing.T) {
	// Verify >64 KiB attest commands pass Outbox validation and work end-to-end,
	// and verify expire sets Phase="expired" with empty WorkOutcome.
	w, _ := newAccordWorld(t, false)
	largeBundle, _ := makeCompletedProtocolEvidence(t, true) // >64 KiB JSON

	// Create a new Accord pinned to largeBundle.
	spec := w.spec
	spec.Nonce = "large-attest-accord"
	spec.Evidence = []nex.EvidenceSlot{
		{
			ID:                "audit",
			Kind:              nex.EvidenceProtocolBundle,
			ProtocolID:        nex.Hash(largeBundle.Spec),
			ExpectedAuthority: largeBundle.Spec.Initiator,
			ExpectedHead:      largeBundle.Events[len(largeBundle.Events)-1].ReceiptHash,
		},
	}
	id, err := w.store.Create(spec)
	if err != nil {
		t.Fatal(err)
	}
	w.id = id
	w.spec = spec

	o := testOutbox(t)
	attItem := w.buildItem(t, w.release, "release-propose", "attest", "att-large", 1, func(c *nex.AccordCommand) {
		c.Attest = &nex.AttestPayload{EvidenceID: "audit", Protocol: &largeBundle}
	})
	if len(attItem.SignedObject) <= 64<<10 {
		t.Fatalf("expected >64 KiB attest item for boundary check, got %d bytes", len(attItem.SignedObject))
	}
	if err := o.Enqueue(attItem); err != nil {
		t.Fatalf("Outbox.Enqueue rejected valid large attest (%d bytes): %v", len(attItem.SignedObject), err)
	}
	w.height.Store(1)
	attResp, err := o.Reconcile(tenant, attItem.OperationID, w.inner)
	if err != nil || attResp.ReceiptHead == "" {
		t.Fatalf("large attest Reconcile: %v", err)
	}
	if err := o.RecordVerified(tenant, attItem.OperationID, attResp, w.authPub, SignAuthorityResponse(w.authority, attResp)); err != nil {
		t.Fatal(err)
	}

	// Expire at ResolveByHeight=20.
	expResp := w.apply(t, o, w.security, "security-vote", "expire", "exp-1", 20, func(c *nex.AccordCommand) {
		c.Expire = &nex.ExpirePayload{ReasonHash: nex.Hash("deadline-reached")}
	})
	snap, err := w.inner.View(tenant, w.id)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Head != expResp.ReceiptHead || snap.Phase != string(nex.AccordPhaseExpired) || snap.WorkOutcome != "" {
		t.Fatalf("unexpected expired ViewSnapshot: %+v", snap)
	}
}

func TestAccordAuthorityDropNextAndExactRetry(t *testing.T) {
	w, _ := newAccordWorld(t, false)
	o := testOutbox(t)
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	o.SetNow(func() time.Time { return now })

	item := w.enqueue(t, o, w.sre, "sre-vote", "vote", "vote-drop-1", 2, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	})

	w.height.Store(2)
	w.inner.DropNext = true
	resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if !errors.Is(err, ErrLostResponse) || resp.Kind != ResultUncertain {
		t.Fatalf("expected ErrLostResponse/ResultUncertain, got %+v %v", resp, err)
	}
	if w.inner.DropNext {
		t.Fatal("DropNext remained true after firing")
	}

	got, err := o.Get(tenant, item.OperationID)
	if err != nil || got.Status != StatusUnknown {
		t.Fatalf("expected StatusUnknown after dropped response, got %+v %v", got, err)
	}
	if due, err := o.Due(tenant); err != nil || len(due) != 0 {
		t.Fatalf("expected no due items during backoff, got %+v %v", due, err)
	}
	if _, err := o.ReconcileDue(tenant, item.OperationID, w.inner); !errors.Is(err, ErrNotDue) {
		t.Fatalf("expected ErrNotDue before backoff elapsed, got %v", err)
	}

	// Advance clock and recover exact receipt via ReconcileDue, even at a higher height.
	now = now.Add(3 * time.Second)
	due, err := o.Due(tenant)
	if err != nil || len(due) != 1 || due[0].Item.OperationID != item.OperationID {
		t.Fatalf("expected 1 due item after backoff, got %+v %v", due, err)
	}
	w.height.Store(25)
	recovered, err := o.ReconcileDue(tenant, item.OperationID, w.inner)
	if err != nil || recovered.Kind != ResultAgreement || recovered.ReceiptHead == "" || recovered.Result != nil {
		t.Fatalf("ReconcileDue recovery failed: %+v %v", recovered, err)
	}
	if err := o.RecordVerified(tenant, item.OperationID, recovered, w.authPub, SignAuthorityResponse(w.authority, recovered)); err != nil {
		t.Fatal(err)
	}

	// Direct exact retry on AccordAuthority returns identical ReceiptHead even at different height.
	w.height.Store(99)
	directRetry, err := w.inner.Apply(item)
	if err != nil || directRetry.ReceiptHead != recovered.ReceiptHead {
		t.Fatalf("direct exact retry mismatch: %+v %v (want head %s)", directRetry, err, recovered.ReceiptHead)
	}

	// Outbox Reconcile after StatusResolved returns recorded Original.
	outboxRetry, err := o.Reconcile(tenant, item.OperationID, w.inner)
	if err != nil || outboxRetry.ReceiptHead != recovered.ReceiptHead {
		t.Fatalf("outbox retry mismatch: %+v %v", outboxRetry, err)
	}
}

func TestAccordAuthorityConflictDetection(t *testing.T) {
	w, _ := newAccordWorld(t, false)
	o := testOutbox(t)

	first := w.apply(t, o, w.sre, "sre-vote", "vote", "shared-req", 2, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("choice-a")}
	})
	if first.ReceiptHead == "" {
		t.Fatal("missing receipt head")
	}

	// Different signed command reusing (sre, "shared-req").
	conflicting := w.buildItem(t, w.sre, "sre-vote", "vote", "shared-req", 2, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "hold-release", Position: nex.BallotDissent, RationaleHash: nex.Hash("choice-b")}
	})
	w.height.Store(2)
	got, err := w.inner.Apply(conflicting)
	if !errors.Is(err, nex.ErrOperationConflict) || got.Kind != ResultConflict || got.Definitive {
		t.Fatalf("expected ResultConflict / ErrOperationConflict, got %+v %v", got, err)
	}

	// Outbox records StatusConflict terminally when applying conflicting command from another outbox.
	o2 := testOutbox(t)
	if err := o2.Enqueue(conflicting); err != nil {
		t.Fatal(err)
	}
	if _, err := o2.Reconcile(tenant, conflicting.OperationID, w.inner); !errors.Is(err, nex.ErrOperationConflict) {
		t.Fatalf("expected ErrOperationConflict on Reconcile, got %v", err)
	}
	rec, err := o2.Get(tenant, conflicting.OperationID)
	if err != nil || rec.Status != StatusConflict {
		t.Fatalf("expected StatusConflict, got %+v %v", rec, err)
	}
	if _, err := o2.Reconcile(tenant, conflicting.OperationID, w.inner); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected terminal ErrConflict on second Reconcile, got %v", err)
	}
}

func TestAccordAuthorityForeignTenantAndFailClosedConfig(t *testing.T) {
	w, _ := newAccordWorld(t, false)
	o := testOutbox(t)

	valid := w.enqueue(t, o, w.sre, "sre-vote", "vote", "cfg-vote", 2, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	})

	// 1. Tenant mismatch on Apply and View.
	cross := valid
	cross.Tenant = "other-tenant"
	if resp, err := w.inner.Apply(cross); !errors.Is(err, ErrTenant) || resp.Kind != ResultRefused || resp.Definitive {
		t.Fatalf("expected non-definitive ErrTenant, got %+v %v", resp, err)
	}
	if _, err := w.inner.View("other-tenant", w.id); !errors.Is(err, ErrTenant) {
		t.Fatalf("expected View ErrTenant, got %v", err)
	}

	// 2. Wrong Kind -> Definitive ErrItem.
	wrongKind := valid
	wrongKind.Kind = KindProtocol
	if resp, err := w.inner.Apply(wrongKind); !errors.Is(err, ErrItem) || resp.Kind != ResultRefused || !resp.Definitive {
		t.Fatalf("expected definitive ErrItem on wrong kind, got %+v %v", resp, err)
	}

	// 3. Foreign AgreementID / OperationID -> Definitive ErrForeign.
	foreignAg := valid
	foreignAg.AgreementID = "other-agreement"
	if resp, err := w.inner.Apply(foreignAg); !errors.Is(err, ErrForeign) || resp.Kind != ResultRefused || !resp.Definitive {
		t.Fatalf("expected definitive ErrForeign on AgreementID mismatch, got %+v %v", resp, err)
	}
	foreignOp := valid
	foreignOp.OperationID = "other-op"
	if resp, err := w.inner.Apply(foreignOp); !errors.Is(err, ErrForeign) || resp.Kind != ResultRefused || !resp.Definitive {
		t.Fatalf("expected definitive ErrForeign on OperationID mismatch, got %+v %v", resp, err)
	}

	// 4. Nil Store -> Fail closed, non-definitive.
	nilStoreAuth := &AccordAuthority{Tenant: tenant, Store: nil, Height: func() uint64 { return 2 }}
	if resp, err := nilStoreAuth.Apply(valid); !errors.Is(err, ErrItem) || resp.Kind != ResultRefused || resp.Definitive {
		t.Fatalf("expected non-definitive ErrItem for nil Store, got %+v %v", resp, err)
	}
	if _, err := nilStoreAuth.View(tenant, w.id); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for nil Store View, got %v", err)
	}

	// 5. Nil Receiver -> Fail closed without panic.
	var nilAuth *AccordAuthority
	if resp, err := nilAuth.Apply(valid); !errors.Is(err, ErrItem) || resp.Kind != ResultRefused {
		t.Fatalf("expected ErrItem for nil receiver Apply, got %+v %v", resp, err)
	}
	if _, err := nilAuth.View(tenant, w.id); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for nil receiver View, got %v", err)
	}

	// 6. Nil Height and Zero Height -> Fail closed, non-definitive, do not consume DropNext or mutate Store.
	nilHeightAuth := &AccordAuthority{Tenant: tenant, Store: w.store, DropNext: true, Height: nil}
	if resp, err := nilHeightAuth.Apply(valid); !errors.Is(err, ErrItem) || resp.Kind != ResultRefused || resp.Definitive {
		t.Fatalf("expected non-definitive ErrItem for nil Height, got %+v %v", resp, err)
	}
	if !nilHeightAuth.DropNext {
		t.Fatal("nil Height check consumed DropNext")
	}

	var curHeight uint64
	zeroHeightAuth := &AccordAuthority{Tenant: tenant, Store: w.store, DropNext: true, Height: func() uint64 { return curHeight }}
	if _, err := o.Reconcile(tenant, valid.OperationID, zeroHeightAuth); !errors.Is(err, ErrItem) {
		t.Fatalf("expected ErrItem for zero Height, got %v", err)
	}
	if !zeroHeightAuth.DropNext {
		t.Fatal("zero Height check consumed DropNext")
	}
	// Item stayed StatusUnknown (retryable), NOT StatusRefused!
	rec, err := o.Get(tenant, valid.OperationID)
	if err != nil || rec.Status != StatusUnknown {
		t.Fatalf("expected StatusUnknown after zero-height refusal, got %+v %v", rec, err)
	}
	vCheck, err := w.store.View(w.id)
	if err != nil || len(vCheck.Votes) != 0 {
		t.Fatalf("zero-height check mutated store: %+v %v", vCheck, err)
	}

	// Fix Height -> exact retry succeeds!
	curHeight = 2
	zeroHeightAuth.DropNext = false
	okResp, err := o.Reconcile(tenant, valid.OperationID, zeroHeightAuth)
	if err != nil || okResp.ReceiptHead == "" {
		t.Fatalf("retry after fixing Height failed: %+v %v", okResp, err)
	}
	if err := o.RecordVerified(tenant, valid.OperationID, okResp, w.authPub, SignAuthorityResponse(w.authority, okResp)); err != nil {
		t.Fatal(err)
	}

	// Even an already-committed exact retry MUST fail closed if Height is nil or returns 0!
	if resp, err := nilHeightAuth.Apply(valid); !errors.Is(err, ErrItem) || resp.Kind != ResultRefused {
		t.Fatalf("committed retry accepted nil Height: %+v %v", resp, err)
	}
	curHeight = 0
	if resp, err := zeroHeightAuth.Apply(valid); !errors.Is(err, ErrItem) || resp.Kind != ResultRefused {
		t.Fatalf("committed retry accepted zero Height: %+v %v", resp, err)
	}
}

func TestAccordAuthorityRefusalClassification(t *testing.T) {
	w, _ := newAccordWorld(t, false)
	o := testOutbox(t)

	// Non-definitive: ErrAccordPhase (resolve before VoteByHeight=10).
	earlyRes := w.enqueue(t, o, w.security, "security-vote", "resolve", "res-early", 5, func(c *nex.AccordCommand) {
		c.Resolve = &nex.ResolvePayload{ReasonHash: nex.Hash("too-early")}
	})
	w.height.Store(5)
	gotEarly, err := o.Reconcile(tenant, earlyRes.OperationID, w.inner)
	if !errors.Is(err, nex.ErrAccordPhase) || gotEarly.Kind != ResultRefused || gotEarly.Definitive {
		t.Fatalf("expected non-definitive ErrAccordPhase, got %+v %v", gotEarly, err)
	}
	recEarly, err := o.Get(tenant, earlyRes.OperationID)
	if err != nil || recEarly.Status != StatusUnknown {
		t.Fatalf("expected StatusUnknown for ErrAccordPhase, got %+v %v", recEarly, err)
	}

	// Non-definitive: ErrAccordEvidence (veto citing unattested evidence slot).
	unattestedVeto := w.enqueue(t, o, w.safety, "safety-vote", "veto", "veto-unattested", 5, func(c *nex.AccordCommand) {
		c.Veto = &nex.VetoPayload{OptionID: "hold-release", ReasonHash: nex.Hash("needs-audit"), EvidenceIDs: []string{"audit"}}
	})
	gotEv, err := o.Reconcile(tenant, unattestedVeto.OperationID, w.inner)
	if !errors.Is(err, nex.ErrAccordEvidence) || gotEv.Kind != ResultRefused || gotEv.Definitive {
		t.Fatalf("expected non-definitive ErrAccordEvidence, got %+v %v", gotEv, err)
	}
	recEv, err := o.Get(tenant, unattestedVeto.OperationID)
	if err != nil || recEv.Status != StatusUnknown {
		t.Fatalf("expected StatusUnknown for ErrAccordEvidence, got %+v %v", recEv, err)
	}

	// Non-definitive: ErrCommitUncertain -> ResultUncertain.
	uncertainResp, uncertainErr := classifyAccord(AuthenticatedResponse{}, "", fmt.Errorf("%w: dir sync", nex.ErrCommitUncertain))
	if uncertainResp.Kind != ResultUncertain || uncertainResp.Definitive || !errors.Is(uncertainErr, nex.ErrCommitUncertain) {
		t.Fatalf("expected ResultUncertain for ErrCommitUncertain, got %+v %v", uncertainResp, uncertainErr)
	}

	// Definitive cases: verify each produces ResultRefused, Definitive=true, and StatusRefused in Outbox.
	assertDefinitive := func(name string, item OutboundItem, applyHeight uint64, wantErr error) {
		t.Helper()
		w.height.Store(applyHeight)
		if err := o.Enqueue(item); err != nil {
			t.Fatalf("%s Enqueue: %v", name, err)
		}
		resp, err := o.Reconcile(tenant, item.OperationID, w.inner)
		if err == nil || (wantErr != nil && !errors.Is(err, wantErr)) {
			t.Fatalf("%s: got err=%v, want %v (resp=%+v)", name, err, wantErr, resp)
		}
		if resp.Kind != ResultRefused || !resp.Definitive {
			t.Fatalf("%s: expected Definitive ResultRefused, got %+v", name, resp)
		}
		rec, gerr := o.Get(tenant, item.OperationID)
		if gerr != nil || rec.Status != StatusRefused {
			t.Fatalf("%s: expected StatusRefused, got %+v %v", name, rec, gerr)
		}
		if _, rerr := o.Reconcile(tenant, item.OperationID, w.inner); !errors.Is(rerr, ErrDefinitive) {
			t.Fatalf("%s: expected ErrDefinitive on retry, got %v", name, rerr)
		}
	}

	// 1. ErrAccordAuthority (sre lacks veto permission).
	noPerm := w.buildItem(t, w.sre, "sre-vote", "veto", "def-auth", 5, func(c *nex.AccordCommand) {
		c.Veto = &nex.VetoPayload{OptionID: "hold-release", ReasonHash: nex.Hash("nope")}
	})
	assertDefinitive("ErrAccordAuthority", noPerm, 5, nex.ErrAccordAuthority)

	// 2. ErrAccordSpec (invalid RationaleHash).
	badSpec := w.buildItem(t, w.sre, "sre-vote", "vote", "def-spec", 5, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: "not-hex"}
	})
	assertDefinitive("ErrAccordSpec", badSpec, 5, nex.ErrAccordSpec)

	// 3. Invalid signature (wrong signing key).
	badSigCmd, err := w.store.Prepare(w.id, w.sre.pub.ID(), "sre-vote", w.spec.Scope, "vote", "def-sig", 5)
	if err != nil {
		t.Fatal(err)
	}
	badSigCmd.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	badSigRaw, err := EncodeAccord(badSigCmd, nex.Sign(w.release.id, nex.AccordCommandDomain, badSigCmd))
	if err != nil {
		t.Fatal(err)
	}
	assertDefinitive("InvalidSignature", OutboundItem{
		Version: Version, Tenant: tenant, AgreementID: w.id, OperationID: "def-sig",
		Kind: KindAccord, SignedObject: badSigRaw, Destination: "accord-authority-1",
	}, 5, nil)

	// 4. ErrAccordStale (command Height != receiver Height).
	staleHeight := w.buildItem(t, w.sre, "sre-vote", "vote", "def-stale-h", 5, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	})
	assertDefinitive("ErrAccordStale_height", staleHeight, 6, nex.ErrAccordStale)

	// 5. Advance state with a real vote, then test ErrAccordStale (stale head) & ErrAccordEquivocation (duplicate vote).
	w.apply(t, o, w.sre, "sre-vote", "vote", "real-sre-vote", 6, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")}
	})

	// Stale head (head pinned to initial id instead of current head).
	staleHeadCmd := nex.AccordCommand{
		RequestID: "def-stale-head", AccordID: w.id, Head: w.id,
		Actor: w.safety.pub.ID(), GrantID: "safety-vote", Scope: w.spec.Scope,
		Action: "vote", Height: 6,
		Vote: &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("ok")},
	}
	staleHeadSig, err := nex.SignAccordCommand(w.safety.id, staleHeadCmd)
	if err != nil {
		t.Fatal(err)
	}
	staleHeadRaw, err := EncodeAccord(staleHeadCmd, staleHeadSig)
	if err != nil {
		t.Fatal(err)
	}
	assertDefinitive("ErrAccordStale_head", OutboundItem{
		Version: Version, Tenant: tenant, AgreementID: w.id, OperationID: "def-stale-head",
		Kind: KindAccord, SignedObject: staleHeadRaw, Destination: "accord-authority-1",
	}, 6, nex.ErrAccordStale)

	// ErrAccordEquivocation (sre votes on canary-rollout a second time with a new RequestID).
	equiv := w.buildItem(t, w.sre, "sre-vote", "vote", "def-equiv", 6, func(c *nex.AccordCommand) {
		c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotDissent, RationaleHash: nex.Hash("flip")}
	})
	assertDefinitive("ErrAccordEquivocation", equiv, 6, nex.ErrAccordEquivocation)
}

func TestAccordAuthorityFencedOwnerHandoffAndConcurrency(t *testing.T) {
	t.Run("OwnerFenceHandoff", func(t *testing.T) {
		w, _ := newAccordWorld(t, false)
		o := testOutbox(t)
		coord := &Coordinator{}
		f1, err := coord.Issue("owner-a")
		if err != nil {
			t.Fatal(err)
		}
		ownerA := BindCoordinatorOwner(coord, "owner-a", f1, w.inner)

		// Owner A submits vote 1 under fence 1.
		w.height.Store(2)
		item1 := w.enqueue(t, o, w.sre, "sre-vote", "vote", "fence-v1", 2, func(c *nex.AccordCommand) {
			c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("sre")}
		})
		resp1, err := ownerA.Submit(RoutingEnvelope{Item: item1, Generation: f1.Generation}, f1)
		if err != nil || resp1.ReceiptHead == "" {
			t.Fatalf("ownerA Submit failed: %+v %v", resp1, err)
		}
		if err := o.RecordVerified(tenant, item1.OperationID, resp1, w.authPub, SignAuthorityResponse(w.authority, resp1)); err != nil {
			t.Fatal(err)
		}

		// Record checkpoint head, stop admission, fence owner-a, and copy store to owner-b.
		view1, err := w.inner.View(tenant, w.id)
		if err != nil {
			t.Fatal(err)
		}
		if err := coord.RecordCheckpoint(view1.Head); err != nil {
			t.Fatal(err)
		}
		o.StopAdmission()
		if _, err := coord.StopAndFence("owner-a"); err != nil {
			t.Fatal(err)
		}
		ownerA.Deactivate()

		dstDir := filepath.Join(t.TempDir(), "accords-handoff")
		if err := CopyPrivateDir(w.dir, dstDir); err != nil {
			t.Fatal(err)
		}
		dstStore, err := nex.OpenAccordStore(dstDir, w.key)
		if err != nil {
			t.Fatal(err)
		}
		var h atomic.Uint64
		h.Store(4)
		dstAuth := &AccordAuthority{
			Tenant: tenant,
			Store:  dstStore,
			Height: func() uint64 { return h.Load() },
		}
		ownerB, err := ActivateCoordinatorReplacement(coord, ownerA, "owner-b", view1.Head, dstAuth)
		if err != nil {
			t.Fatal(err)
		}

		// Build second item against dstStore (which has view1.Head).
		cmd2, err := dstStore.Prepare(w.id, w.safety.pub.ID(), "safety-vote", w.spec.Scope, "vote", "fence-v2", 4)
		if err != nil {
			t.Fatal(err)
		}
		cmd2.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("saf")}
		sig2, err := nex.SignAccordCommand(w.safety.id, cmd2)
		if err != nil {
			t.Fatal(err)
		}
		raw2, err := EncodeAccord(cmd2, sig2)
		if err != nil {
			t.Fatal(err)
		}
		item2 := OutboundItem{
			Version: Version, Tenant: tenant, AgreementID: w.id, OperationID: "fence-v2",
			Kind: KindAccord, SignedObject: raw2, Destination: "accord-authority-1",
		}

		// Retired ownerA must fail with ErrFenced.
		if _, err := ownerA.Submit(RoutingEnvelope{Item: item2, Generation: f1.Generation}, f1); !errors.Is(err, ErrFenced) {
			t.Fatalf("fenced ownerA accepted submission: %v", err)
		}
		// ownerB presenting stale fence f1 must fail with ErrFenced.
		if _, err := ownerB.Submit(RoutingEnvelope{Item: item2, Generation: f1.Generation}, f1); !errors.Is(err, ErrFenced) {
			t.Fatalf("ownerB accepted stale fence: %v", err)
		}

		f2, err := coord.Current()
		if err != nil {
			t.Fatal(err)
		}
		resp2, err := ownerB.Submit(RoutingEnvelope{Item: item2, Generation: f2.Generation}, f2)
		if err != nil || resp2.ReceiptHead == "" {
			t.Fatalf("ownerB Submit failed: %+v %v", resp2, err)
		}
		// Exact retry via ownerB returns identical ReceiptHead.
		retry2, err := ownerB.Submit(RoutingEnvelope{Item: item2, Generation: f2.Generation}, f2)
		if err != nil || retry2.ReceiptHead != resp2.ReceiptHead {
			t.Fatalf("ownerB exact retry failed: %+v %v", retry2, err)
		}
		view2, err := dstAuth.View(tenant, w.id)
		if err != nil || view2.Head != resp2.ReceiptHead {
			t.Fatalf("unexpected dstAuth View after handoff: %+v %v", view2, err)
		}
	})

	t.Run("ConcurrentApplyAndViewRace", func(t *testing.T) {
		w, _ := newAccordWorld(t, false)
		w.height.Store(2)
		item := w.buildItem(t, w.sre, "sre-vote", "vote", "race-v1", 2, func(c *nex.AccordCommand) {
			c.Vote = &nex.VotePayload{OptionID: "canary-rollout", Position: nex.BallotApprove, RationaleHash: nex.Hash("race")}
		})
		// Commit once so concurrent exact retries + View calls contend on AccordStore.
		first, err := w.inner.Apply(item)
		if err != nil || first.ReceiptHead == "" {
			t.Fatalf("initial Apply: %+v %v", first, err)
		}

		const workers = 8
		var wg sync.WaitGroup
		errs := make(chan error, workers*2)
		for i := 0; i < workers; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				resp, err := w.inner.Apply(item)
				if err != nil {
					errs <- err
					return
				}
				if resp.ReceiptHead != first.ReceiptHead {
					errs <- fmt.Errorf("head mismatch: got %s want %s", resp.ReceiptHead, first.ReceiptHead)
				}
			}()
			go func() {
				defer wg.Done()
				snap, err := w.inner.View(tenant, w.id)
				if err != nil {
					errs <- err
					return
				}
				if snap.Head != first.ReceiptHead || snap.Phase != string(nex.AccordPhaseOpen) {
					errs <- fmt.Errorf("unexpected concurrent View: %+v", snap)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	})
}
