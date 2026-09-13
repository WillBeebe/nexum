package adapter

import (
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/nex"
)

const tenant = "lab"

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func testOutbox(t *testing.T) *Outbox {
	t.Helper()
	o, err := OpenOutbox(filepath.Join(t.TempDir(), "outbox"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func mustPublic(t *testing.T, i nex.Identity) nex.Public {
	t.Helper()
	p, err := i.Public()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type storeWorld struct {
	buyer, seller, authority nex.Identity
	authPub                  nex.Public
	store                    *nex.Store
	dir                      string
	key                      []byte
	contract                 *nex.Contract
	now                      time.Time
	inner                    *StoreAuthority
}

func newStoreWorld(t *testing.T) storeWorld {
	t.Helper()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	buyer, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	seller, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bp, err := buyer.Public()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := seller.Public()
	if err != nil {
		t.Fatal(err)
	}
	c, err := nex.New("work.bounty", bp, sp, 10, "adapter fixture", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "agreements")
	store, err := nex.OpenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Create(c); err != nil {
		t.Fatal(err)
	}
	inner := &StoreAuthority{Tenant: tenant, Store: store, Now: func() time.Time { return now }}
	return storeWorld{buyer, seller, authority, mustPublic(t, authority), store, dir, key, c, now, inner}
}

func (w storeWorld) enqueueLock(t *testing.T, o *Outbox, opID string) OutboundItem {
	t.Helper()
	op, err := w.store.Prepare(w.contract.ID(), opID, "lock", "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeOperation(op, nex.Sign(w.buyer, "operation", op), w.now)
	if err != nil {
		t.Fatal(err)
	}
	item := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.contract.ID(), OperationID: opID, Kind: KindAgreement, SignedObject: raw, Destination: "authority-1", CreatedAt: w.now}
	if err = o.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	return item
}

func recordOK(t *testing.T, o *Outbox, w storeWorld, opID string, resp AuthenticatedResponse) {
	t.Helper()
	if err := o.RecordVerified(tenant, opID, resp, w.authPub, SignResponse(w.authority, resp)); err != nil {
		t.Fatal(err)
	}
}

type protocolWorld struct {
	owner, worker, witness, authority nex.Identity
	authPub                           nex.Public
	store                             *nex.ProtocolStore
	dir                               string
	key                               []byte
	id                                string
	spec                              nex.ProtocolSpec
	inner                             *ProtocolAuthority
}

func newProtocolWorld(t *testing.T) protocolWorld {
	t.Helper()
	a, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	scope := "research/adapter"
	pub := func(i nex.Identity) nex.Public { return mustPublic(t, i) }
	grant := func(id string, actor nex.Identity, label string, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{ID: id, Actor: pub(actor).ID(), Label: label, Scope: scope, Permissions: perms, ExpiresAtHeight: 40, LimitsHash: nex.Hash("only this"), EvidenceObligation: nex.Hash("cite")}
	}
	spec := nex.ProtocolSpec{Version: nex.ProtocolVersion, Nonce: "adapter-protocol-v1", Purpose: "Reconcile a lost response without claiming success", IntendedOutcome: "A verified answer or a documented failure", Scope: scope, SpecificationHash: nex.Hash("spec"), AcceptanceHash: nex.Hash("accept"), FailurePolicyHash: nex.Hash("retain failure"), Initiator: pub(a).ID(), Participants: []nex.Public{pub(a), pub(b), pub(c)}, Roles: []nex.RoleGrant{grant("owner", a, "proposer", nex.PermitCommit, nex.PermitDecide, nex.PermitReturn), grant("worker", b, "worker", nex.PermitWork, nex.PermitReturn), grant("witness", c, "witness", nex.PermitReview)}, WorkByHeight: 20, ReturnByHeight: 40, RequiredWitnesses: []string{pub(c).ID()}, DissentPolicy: "record", Return: nex.ReturnRequirements{SuccessArtifacts: []string{"answer"}, FailureArtifacts: []string{"failure"}, AllowedDisposition: []string{"retry", "continue", "refuse"}, AllowSuccessors: true}, MaxEvents: 32}
	key := testKey(t)
	dir := filepath.Join(t.TempDir(), "protocols")
	store, err := nex.OpenProtocolStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(spec)
	if err != nil {
		t.Fatal(err)
	}
	return protocolWorld{a, b, c, authority, mustPublic(t, authority), store, dir, key, id, spec, &ProtocolAuthority{Tenant: tenant, Store: store}}
}

func (w protocolWorld) enqueue(t *testing.T, o *Outbox, actor nex.Identity, grant, action, request string, height uint64, fill func(*nex.ProtocolCommand)) OutboundItem {
	t.Helper()
	cmd, err := w.store.Prepare(w.id, mustPublic(t, actor).ID(), grant, w.spec.Scope, action, request, height)
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
	raw, err := EncodeProtocol(cmd, nex.Sign(actor, "protocol", cmd))
	if err != nil {
		t.Fatal(err)
	}
	item := OutboundItem{Version: Version, Tenant: tenant, AgreementID: w.id, OperationID: request, Kind: KindProtocol, SignedObject: raw, Destination: "authority-1", CreatedAt: time.Now().UTC()}
	if err = o.Enqueue(item); err != nil {
		t.Fatal(err)
	}
	return item
}

func (w protocolWorld) apply(t *testing.T, o *Outbox, actor nex.Identity, grant, action, request string, height uint64, fill func(*nex.ProtocolCommand)) AuthenticatedResponse {
	t.Helper()
	w.enqueue(t, o, actor, grant, action, request, height, fill)
	resp, err := o.Reconcile(tenant, request, w.inner)
	if err != nil {
		t.Fatal(action, err)
	}
	if err = o.RecordVerified(tenant, request, resp, w.authPub, SignResponse(w.authority, resp)); err != nil {
		t.Fatal(err)
	}
	return resp
}

func failManifest(v nex.ProtocolView) nex.ReturnManifest {
	return nex.ReturnManifest{ResolutionHash: nex.Hash(v.Resolution), ReviewsHash: nex.Hash(v.Reviews), Evidence: append([]string(nil), v.Report.Evidence...), Resources: v.Report.Resources, Uncertainty: "Reproduction inputs were missing", SafeAssumptions: []string{"No answer was verified"}, Artifacts: []nex.ReturnArtifact{{ID: "failure", Commitment: nex.Hash("failure-record"), ReuseRestrictions: "Preserve dissent"}}, Disposition: "retry"}
}
