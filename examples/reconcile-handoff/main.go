// Local demonstration of exact-command reconcile, a failure return that stays
// a failure, an unknown external effect, and a stopped-writer fenced handoff.
// Temporary keys and directories are discarded on exit; do not copy that
// lifecycle into an application.
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/WillBeebe/nexum/adapter"
	"github.com/WillBeebe/nexum/nex"
)

func run() error {
	parent, err := os.MkdirTemp("", "nex-reconcile-handoff-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(parent)
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	now := time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)
	buyer, seller, authority, err := identities()
	if err != nil {
		return err
	}
	authPub, err := authority.Public()
	if err != nil {
		return err
	}
	bp, err := buyer.Public()
	if err != nil {
		return err
	}
	sp, err := seller.Public()
	if err != nil {
		return err
	}
	c, err := nex.New("work.bounty", bp, sp, 10, "reconcile fixture", now, now.Add(time.Hour))
	if err != nil {
		return err
	}
	store, err := nex.OpenStore(filepath.Join(parent, "agreements"), key)
	if err != nil {
		return err
	}
	if err = store.Create(c); err != nil {
		return err
	}
	outbox, err := adapter.OpenOutbox(filepath.Join(parent, "outbox"), key)
	if err != nil {
		return err
	}
	inner := &adapter.StoreAuthority{Tenant: "lab", Store: store, Now: func() time.Time { return now }}
	op, err := store.Prepare(c.ID(), "lock-1", "lock", "")
	if err != nil {
		return err
	}
	raw, err := adapter.EncodeOperation(op, nex.Sign(buyer, "operation", op), now)
	if err != nil {
		return err
	}
	item := adapter.OutboundItem{Version: adapter.Version, Tenant: "lab", AgreementID: c.ID(), OperationID: "lock-1", Kind: adapter.KindAgreement, SignedObject: raw, Destination: "authority-1", CreatedAt: now}
	if err = outbox.Enqueue(item); err != nil {
		return err
	}
	inner.DropNext = true
	if _, err = outbox.Reconcile("lab", "lock-1", inner); !errors.Is(err, adapter.ErrLostResponse) {
		return fmt.Errorf("expected lost response: %w", err)
	}
	lock, err := outbox.Reconcile("lab", "lock-1", inner)
	if err != nil {
		return err
	}
	if err = outbox.RecordVerified("lab", "lock-1", lock, authPub, adapter.SignResponse(authority, lock)); err != nil {
		return err
	}

	owner, worker, witness, err := identities()
	if err != nil {
		return err
	}
	spec := protocolSpec(owner, worker, witness)
	protocols, err := nex.OpenProtocolStore(filepath.Join(parent, "protocols"), key)
	if err != nil {
		return err
	}
	id, err := protocols.Create(spec)
	if err != nil {
		return err
	}
	pAuth := &adapter.ProtocolAuthority{Tenant: "lab", Store: protocols}
	submit := func(actor nex.Identity, grant, action, request string, height uint64, fill func(*nex.ProtocolCommand)) error {
		cmd, err := protocols.Prepare(id, mustID(actor), grant, spec.Scope, action, request, height)
		if err != nil {
			return err
		}
		if action == "admit" {
			cmd.GrantID = ""
			cmd.Scope = ""
		}
		if fill != nil {
			fill(&cmd)
		}
		raw, err := adapter.EncodeProtocol(cmd, nex.Sign(actor, "protocol", cmd))
		if err != nil {
			return err
		}
		item := adapter.OutboundItem{Version: adapter.Version, Tenant: "lab", AgreementID: id, OperationID: request, Kind: adapter.KindProtocol, SignedObject: raw, Destination: "authority-1", CreatedAt: now}
		if err = outbox.Enqueue(item); err != nil {
			return err
		}
		resp, err := outbox.Reconcile("lab", request, pAuth)
		if err != nil {
			return err
		}
		return outbox.RecordVerified("lab", request, resp, authPub, adapter.SignResponse(authority, resp))
	}
	if err = submit(owner, "", "admit", "admit-owner", 1, nil); err != nil {
		return err
	}
	if err = submit(worker, "", "admit", "admit-worker", 2, nil); err != nil {
		return err
	}
	if err = submit(witness, "", "admit", "admit-witness", 3, nil); err != nil {
		return err
	}
	if err = submit(owner, "owner", "commit", "commit-1", 4, nil); err != nil {
		return err
	}
	if err = submit(worker, "worker", "report", "report-1", 5, func(cmd *nex.ProtocolCommand) {
		cmd.Report = &nex.WorkReport{Outcome: nex.WorkSpecDefect, Stage: "inputs", ReasonHash: nex.Hash("missing dataset"), Evidence: []string{nex.Hash("gap")}}
	}); err != nil {
		return err
	}
	view, err := protocols.View(id)
	if err != nil {
		return err
	}
	if err = submit(witness, "witness", "review", "review-1", 6, func(cmd *nex.ProtocolCommand) {
		cmd.Review = &nex.WitnessReview{ReportHash: nex.Hash(view.Report), AssessmentHash: nex.Hash("dissent"), Dissent: true}
	}); err != nil {
		return err
	}
	view, err = protocols.View(id)
	if err != nil {
		return err
	}
	if err = submit(owner, "owner", "resolve", "resolve-1", 7, func(cmd *nex.ProtocolCommand) {
		cmd.Resolution = &nex.Resolution{ReportHash: nex.Hash(view.Report), Outcome: "reject", ReasonHash: nex.Hash("no answer")}
	}); err != nil {
		return err
	}
	view, err = protocols.View(id)
	if err != nil {
		return err
	}
	if err = submit(worker, "worker", "return", "return-1", 8, func(cmd *nex.ProtocolCommand) {
		cmd.Return = &nex.ReturnManifest{ResolutionHash: nex.Hash(view.Resolution), ReviewsHash: nex.Hash(view.Reviews), Evidence: view.Report.Evidence, Uncertainty: "Inputs were missing", SafeAssumptions: []string{"No answer was verified"}, Artifacts: []nex.ReturnArtifact{{ID: "failure", Commitment: nex.Hash("failure-record"), ReuseRestrictions: "Preserve dissent"}}, Disposition: "retry"}
	}); err != nil {
		return err
	}
	final, err := protocols.View(id)
	if err != nil {
		return err
	}

	effects, err := adapter.OpenEffects(filepath.Join(parent, "effects"), key)
	if err != nil {
		return err
	}
	intent := adapter.EffectIntent{Tenant: "lab", EffectID: "tool-1", AgreementID: id, Evidence: "external-tool"}
	if err = effects.Intend(intent); err != nil {
		return err
	}
	dest := adapter.NewMemoryDestination()
	dest.Fence = adapter.Fence{Version: adapter.Version, Generation: 1, Owner: "owner-a", Token: make([]byte, 32)}
	copy(dest.Fence.Token, key)
	dest.LoseNext = true
	if err = effects.Apply("lab", "tool-1", dest, dest.Fence); !errors.Is(err, adapter.ErrEffectUnknown) {
		return fmt.Errorf("expected unknown effect: %w", err)
	}

	coord := &adapter.Coordinator{}
	srcFence, err := coord.Issue("owner-a")
	if err != nil {
		return err
	}
	src := adapter.BindOwner("owner-a", srcFence, pAuth)
	coord.RecordCheckpoint(final.Head)
	outbox.StopAdmission()
	if _, err = coord.StopAndFence("owner-a"); err != nil {
		return err
	}
	src.Deactivate()
	dstDir := filepath.Join(parent, "protocols-b")
	if err = adapter.CopyPrivateDir(filepath.Join(parent, "protocols"), dstDir); err != nil {
		return err
	}
	if err = adapter.CopyPrivateDir(filepath.Join(parent, "outbox"), filepath.Join(parent, "outbox-b")); err != nil {
		return err
	}
	if _, err = adapter.OpenOutbox(filepath.Join(parent, "outbox-b"), key); err != nil {
		return err
	}
	dstStore, err := nex.OpenProtocolStore(dstDir, key)
	if err != nil {
		return err
	}
	dst, err := adapter.ActivateReplacement(coord, src, "owner-b", final.Head, &adapter.ProtocolAuthority{Tenant: "lab", Store: dstStore})
	if err != nil {
		return err
	}
	current, err := coord.Current()
	if err != nil {
		return err
	}
	_, oldErr := src.Submit(adapter.RoutingEnvelope{Item: item, Generation: srcFence.Generation}, srcFence)
	if !errors.Is(oldErr, adapter.ErrFenced) {
		return fmt.Errorf("old owner still writable: %v", oldErr)
	}

	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"example":            "reconcile-handoff",
		"lock_status":        lock.Result.Status,
		"same_retry_result":  lock.Result.Head == lock.ReceiptHead,
		"protocol_phase":     final.Phase,
		"work_succeeded":     adapter.WorkSucceeded(final),
		"dissent_preserved":  final.Reviews[0].Review.Dissent,
		"effect_unknown":     true,
		"old_owner_rejected": errors.Is(oldErr, adapter.ErrFenced),
		"new_owner_active":   dst.Active && dst.ID == "owner-b",
		"fence_generation":   current.Generation,
	})
}

func identities() (nex.Identity, nex.Identity, nex.Identity, error) {
	a, err := nex.NewIdentity()
	if err != nil {
		return nex.Identity{}, nex.Identity{}, nex.Identity{}, err
	}
	b, err := nex.NewIdentity()
	if err != nil {
		return nex.Identity{}, nex.Identity{}, nex.Identity{}, err
	}
	c, err := nex.NewIdentity()
	if err != nil {
		return nex.Identity{}, nex.Identity{}, nex.Identity{}, err
	}
	return a, b, c, nil
}

func mustID(i nex.Identity) string {
	p, err := i.Public()
	if err != nil {
		panic(err)
	}
	return p.ID()
}

func protocolSpec(owner, worker, witness nex.Identity) nex.ProtocolSpec {
	scope := "research/reconcile"
	pub := func(i nex.Identity) nex.Public {
		p, err := i.Public()
		if err != nil {
			panic(err)
		}
		return p
	}
	grant := func(id string, actor nex.Identity, label string, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{ID: id, Actor: pub(actor).ID(), Label: label, Scope: scope, Permissions: perms, ExpiresAtHeight: 40, LimitsHash: nex.Hash("only this"), EvidenceObligation: nex.Hash("cite")}
	}
	a, b, c := pub(owner), pub(worker), pub(witness)
	return nex.ProtocolSpec{Version: nex.ProtocolVersion, Nonce: "reconcile-handoff-example-v1", Purpose: "Return a useful failure after a lost transport response", IntendedOutcome: "A documented failure, not a silent success", Scope: scope, SpecificationHash: nex.Hash("spec"), AcceptanceHash: nex.Hash("accept"), FailurePolicyHash: nex.Hash("retain failure"), Initiator: a.ID(), Participants: []nex.Public{a, b, c}, Roles: []nex.RoleGrant{grant("owner", owner, "proposer", nex.PermitCommit, nex.PermitDecide, nex.PermitReturn), grant("worker", worker, "worker", nex.PermitWork, nex.PermitReturn), grant("witness", witness, "witness", nex.PermitReview)}, WorkByHeight: 20, ReturnByHeight: 40, RequiredWitnesses: []string{c.ID()}, DissentPolicy: "record", Return: nex.ReturnRequirements{SuccessArtifacts: []string{"answer"}, FailureArtifacts: []string{"failure"}, AllowedDisposition: []string{"retry", "continue", "refuse"}, AllowSuccessors: true}, MaxEvents: 32}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
