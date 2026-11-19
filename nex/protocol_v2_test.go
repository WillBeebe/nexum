package nex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testArtifactRef(contents string) ArtifactRef {
	digest := sha256.Sum256([]byte(contents))
	return ArtifactRef{Digest: hex.EncodeToString(digest[:]), Size: uint64(len(contents)), MediaType: "text/plain"}
}

func TestProtocolV2ReviewedOutputBinding(t *testing.T) {
	f := newProtocolFixture(t)
	f.spec.Version = ProtocolVersionV2
	p := enterProtocol(t, f)
	answer := testArtifactRef("reviewed answer")
	report := &WorkReport{Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("reason"), Evidence: []string{Hash("evidence")}}
	command := p.Prepare(protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "report", "worker-report", 5)
	command.Report = report
	rejectProtocolCommand(t, p, f.worker, command, ErrProtocolEvidence)
	report.Manifest = &EvidenceManifest{MethodHash: Hash("method"), Outputs: []NamedArtifact{{Name: "answer", Ref: answer}}}
	if _, err := p.Apply(command, Sign(f.worker, "protocol", command), command.Height); err != nil {
		t.Fatal(err)
	}
	reviewProtocol(t, p, f, false)
	resolveProtocol(t, p, f, "accept")
	command = p.Prepare(protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "return", "worker-return", 8)
	manifest := manifestFor(p)
	command.Return = &manifest
	rejectProtocolCommand(t, p, f.worker, command, ErrProtocolEvidence)
	manifest.Artifacts[0].Commitment = answer.Digest
	head, err := p.Apply(command, Sign(f.worker, "protocol", command), command.Height)
	if err != nil {
		t.Fatal(err)
	}
	view, err := VerifyProtocolBundle(p.Bundle(), p.View().ID, head)
	if err != nil || view.Phase != "complete" || view.Report.Manifest.Outputs[0].Ref != answer {
		t.Fatal(view, err)
	}
}

func TestProtocolV1SigningEncoding(t *testing.T) {
	const legacy = `{"RequestID":"report","ProtocolID":"protocol","Head":"head","Actor":"worker","GrantID":"worker","Scope":"scope","Action":"report","Height":5,"Report":{"Outcome":"completed","Stage":"work","ReasonHash":"reason","Evidence":["evidence"],"Resources":null,"BreachClaims":null},"Review":null,"Resolution":null,"Return":null}`
	var command ProtocolCommand
	if err := json.Unmarshal([]byte(legacy), &command); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(command)
	if err != nil || string(encoded) != legacy {
		t.Fatalf("changed v1 signed encoding: %s %v", encoded, err)
	}
}

func TestProtocolV2IncompleteSurvivesReopen(t *testing.T) {
	f := newProtocolFixture(t)
	f.spec.Version = ProtocolVersionV2
	missing, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	missingID := protocolPublic(missing).ID()
	missingGrant := f.spec.Roles[2]
	missingGrant.ID = "silent-witness"
	missingGrant.Actor = missingID
	f.spec.Participants = append(f.spec.Participants, protocolPublic(missing))
	f.spec.Roles = append(f.spec.Roles, missingGrant)
	f.spec.RequiredWitnesses = append(f.spec.RequiredWitnesses, missingID)
	p := enterProtocolWithSilentWitness(t, f, missing)
	dir := filepath.Join(t.TempDir(), "store")
	key := bytes.Repeat([]byte{7}, 32)
	store, err := OpenProtocolStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.Create(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range p.Bundle().Events {
		if _, err := store.Apply(id, e.Command, e.Signature, e.Command.Height); err != nil {
			t.Fatal(err)
		}
	}
	closeout := &IncompleteReturn{ReasonHash: Hash("witness unavailable"), Artifacts: []NamedArtifact{{Name: "notes", Ref: testArtifactRef("partial notes")}}}
	command := p.Prepare(protocolPublic(f.owner).ID(), "owner", f.spec.Scope, "incomplete", "closeout", f.spec.ReturnByHeight-1)
	command.Incomplete = closeout
	if _, err := store.Apply(id, command, Sign(f.owner, "protocol", command), command.Height); !errors.Is(err, ErrProtocolAuthority) {
		t.Fatalf("early incomplete return: %v", err)
	}
	command.Height++
	sig := Sign(f.owner, "protocol", command)
	if _, err := store.Apply(id, command, sig, command.Height-1); !errors.Is(err, ErrProtocolStale) {
		t.Fatalf("signed height is not authoritative: %v", err)
	}
	head, err := store.Apply(id, command, sig, command.Height)
	if err != nil {
		t.Fatal(err)
	}
	store, err = OpenProtocolStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.Apply(id, command, sig, command.Height+1)
	if err != nil || retry != head {
		t.Fatal(retry, err)
	}
	bundle, err := store.Export(id)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyProtocolBundle(bundle, id, head)
	if err != nil || v.Phase != "incomplete" || v.Incomplete == nil || v.Return != nil || v.Resolution != nil {
		t.Fatal(v, err)
	}
	if !slices.Equal(v.Incomplete.MissingWitnesses, []string{missingID}) || !slices.Equal(v.Incomplete.MissingObligations, []string{"resolve", "return"}) || !v.Reviews[0].Review.Dissent || v.Incomplete.Artifacts[0] != closeout.Artifacts[0] {
		t.Fatal(v)
	}
}

func enterProtocolWithSilentWitness(t *testing.T, f protocolFixture, missing Identity) *Protocol {
	t.Helper()
	p, err := NewProtocol(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []Identity{f.owner, f.worker, f.witness, missing} {
		protocolApply(t, p, actor, "", "admit", nil)
	}
	protocolApply(t, p, f.owner, "owner", "commit", nil)
	reportProtocol(t, p, f, WorkSpecDefect)
	reviewProtocol(t, p, f, true)
	return p
}

func TestProtocolV2RejectsSharedSigningKey(t *testing.T) {
	f := newProtocolFixture(t)
	f.spec.Version = ProtocolVersionV2
	f.witness.Signing = f.worker.Signing
	witness := protocolPublic(f.witness)
	f.spec.Participants[2] = witness
	f.spec.Roles[2].Actor = witness.ID()
	f.spec.RequiredWitnesses[0] = witness.ID()
	if _, err := NewProtocol(f.spec); !errors.Is(err, ErrProtocolSpec) {
		t.Fatal(err)
	}
}

func TestArtifactRefVerifiesSizeAndDigest(t *testing.T) {
	ref := testArtifactRef("one")
	if err := ref.Verify(strings.NewReader("one")); err != nil {
		t.Fatal(err)
	}
	for _, contents := range []string{"", "two", "one extra"} {
		if err := ref.Verify(strings.NewReader(contents)); !errors.Is(err, ErrProtocolEvidence) {
			t.Fatalf("verified wrong bytes %q: %v", contents, err)
		}
	}
}
