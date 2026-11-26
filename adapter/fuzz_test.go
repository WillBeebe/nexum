package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/nex"
)

func fuzzBuildPayloadSeeds(tb testing.TB) (opRaw, protoRaw []byte, opAgreementID, opID, protoAgreementID, protoOpID string) {
	tb.Helper()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	buyer, err := nex.NewIdentity()
	if err != nil {
		tb.Fatal(err)
	}
	seller, err := nex.NewIdentity()
	if err != nil {
		tb.Fatal(err)
	}
	witness, err := nex.NewIdentity()
	if err != nil {
		tb.Fatal(err)
	}
	bp, err := buyer.Public()
	if err != nil {
		tb.Fatal(err)
	}
	sp, err := seller.Public()
	if err != nil {
		tb.Fatal(err)
	}
	wp, err := witness.Public()
	if err != nil {
		tb.Fatal(err)
	}

	c, err := nex.New("work.bounty", bp, sp, 10, "fuzz adapter seed", now, now.Add(time.Hour))
	if err != nil {
		tb.Fatal(err)
	}
	op := nex.Operation{
		ID: "op-lock-1",
		Command: nex.Command{
			Terms:    c.ID(),
			Head:     c.Head(),
			Action:   "lock",
			Evidence: "checked",
		},
	}
	opRaw, err = EncodeOperation(op, nex.Sign(buyer, "operation", op), now)
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := DecodePayload(opRaw); err != nil {
		tb.Fatalf("valid operation seed failed DecodePayload: %v", err)
	}

	scope := "fuzz/adapter"
	grant := func(id string, pub nex.Public, label string, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{
			ID:                 id,
			Actor:              pub.ID(),
			Label:              label,
			Scope:              scope,
			Permissions:        perms,
			ExpiresAtHeight:    40,
			LimitsHash:         nex.Hash(scope + ":" + id),
			EvidenceObligation: nex.Hash("cite"),
		}
	}
	spec := nex.ProtocolSpec{
		Version:           nex.ProtocolVersion,
		Nonce:             "fuzz-adapter-proto",
		Purpose:           "Fuzz adapter SignedPayload",
		IntendedOutcome:   "Verified command encoding",
		Scope:             scope,
		SpecificationHash: nex.Hash("spec"),
		AcceptanceHash:    nex.Hash("acc"),
		FailurePolicyHash: nex.Hash("fail"),
		Initiator:         bp.ID(),
		Participants:      []nex.Public{bp, sp, wp},
		Roles: []nex.RoleGrant{
			grant("owner", bp, "owner", nex.PermitCommit, nex.PermitDecide, nex.PermitReturn),
			grant("worker", sp, "worker", nex.PermitWork, nex.PermitReturn),
			grant("witness", wp, "witness", nex.PermitReview),
		},
		WorkByHeight:      20,
		ReturnByHeight:    40,
		RequiredWitnesses: []string{wp.ID()},
		DissentPolicy:     "record",
		Return: nex.ReturnRequirements{
			SuccessArtifacts:   []string{"answer"},
			FailureArtifacts:   []string{"failure"},
			AllowedDisposition: []string{"continue", "retry", "refuse"},
		},
		MaxEvents: 32,
	}
	p, err := nex.NewProtocol(spec)
	if err != nil {
		tb.Fatal(err)
	}
	cmd := p.Prepare(bp.ID(), "", "", "admit", "req-admit-1", 1)
	protoRaw, err = EncodeProtocol(cmd, nex.Sign(buyer, "protocol", cmd))
	if err != nil {
		tb.Fatal(err)
	}
	if _, err := DecodePayload(protoRaw); err != nil {
		tb.Fatalf("valid protocol seed failed DecodePayload: %v", err)
	}

	return opRaw, protoRaw, c.ID(), op.ID, p.View().ID, cmd.RequestID
}

func fuzzPruneOutboxBoxes(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".box") {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func FuzzDecodePayload(f *testing.F) {
	opRaw, protoRaw, opAgreementID, opID, protoAgreementID, protoOpID := fuzzBuildPayloadSeeds(f)

	// Open one reusable outbox outside f.Fuzz to avoid unbounded directoryLocks growth
	// and per-iteration mkdir/fsync overhead.
	outboxDir := filepath.Join(f.TempDir(), "fuzz-outbox")
	outboxKey := bytes.Repeat([]byte{0x7c}, 32)
	outbox, err := OpenOutbox(outboxDir, outboxKey)
	if err != nil {
		f.Fatal(err)
	}
	outbox.Quota = 32
	outbox.HistoryLimit = 64

	// Valid seeds.
	f.Add(opRaw, "tenant-a", opAgreementID, opID, "dest-1", uint8(0))
	f.Add(protoRaw, "tenant-a", protoAgreementID, protoOpID, "dest-1", uint8(1))

	// Mutated & edge-case seeds.
	f.Add([]byte(`{`), "tenant-a", opAgreementID, opID, "dest-1", uint8(0))
	f.Add([]byte(`{}`), "tenant-a", opAgreementID, opID, "dest-1", uint8(0))
	f.Add([]byte(`null`), "", "", "", "", uint8(2))
	f.Add([]byte(`{"version":2,"kind":"agreement","operation":{"ID":"op-1"},"signature":"AQ=="}`), "tenant-a", opAgreementID, "op-1", "dest-1", uint8(0))
	f.Add([]byte(`{"version":1,"kind":"agreement","operation":{"ID":"op-1"},"command":{"RequestID":"r","ProtocolID":"p"},"signature":"AQ=="}`), "tenant-a", opAgreementID, "op-1", "dest-1", uint8(0))
	f.Add([]byte(`{"version":1,"kind":"agreement","operation":{"ID":"op-1"},"signature":""}`), "tenant-a", opAgreementID, "op-1", "dest-1", uint8(0))
	f.Add([]byte(`{"version":1,"kind":"protocol","command":{"RequestID":"","ProtocolID":"p"},"signature":"AQ=="}`), "tenant-a", "p", "", "dest-1", uint8(1))
	f.Add([]byte(`{"version":1,"kind":"unknown-kind","operation":{"ID":"op-1"},"signature":"AQ=="}`), "tenant-a", "a", "op-1", "dest-1", uint8(2))
	// Path-traversal / NUL / whitespace IDs in OutboundItem.
	f.Add(opRaw, "../escape", opAgreementID, opID, "dest-1", uint8(0))
	f.Add(opRaw, "tenant-a", opAgreementID, "bad\x00id", "dest-1", uint8(0))
	f.Add(opRaw, " tenant ", opAgreementID, opID, "dest-1", uint8(0))

	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	writes := 0

	f.Fuzz(func(t *testing.T, raw []byte, itemTenant, agreementID, itemOpID, dest string, kindSel uint8) {
		payload, decErr := DecodePayload(raw)
		if decErr == nil {
			if payload.Version != Version {
				t.Fatalf("DecodePayload accepted wrong version %d", payload.Version)
			}
			if len(payload.Signature) == 0 {
				t.Fatal("DecodePayload accepted empty signature")
			}
			switch payload.Kind {
			case KindAgreement:
				if payload.Operation == nil || payload.Command != nil || payload.Operation.ID == "" {
					t.Fatalf("DecodePayload accepted invalid agreement payload: %+v", payload)
				}
			case KindProtocol:
				if payload.Command == nil || payload.Operation != nil || payload.Command.RequestID == "" || payload.Command.ProtocolID == "" {
					t.Fatalf("DecodePayload accepted invalid protocol payload: %+v", payload)
				}
			}

			// Fail-closed mutation checks on valid decoded SignedPayload.
			badVer := payload
			badVer.Version = Version + 1
			if encoded, err := json.Marshal(badVer); err == nil {
				if _, err := DecodePayload(encoded); err == nil {
					t.Fatal("DecodePayload accepted wrong version")
				}
			}

			noSig := payload
			noSig.Signature = nil
			if encoded, err := json.Marshal(noSig); err == nil {
				if _, err := DecodePayload(encoded); err == nil {
					t.Fatal("DecodePayload accepted missing signature")
				}
			}

			badKind := payload
			badKind.Kind = Kind("invalid-unknown-kind")
			if encoded, err := json.Marshal(badKind); err == nil {
				if _, err := DecodePayload(encoded); err == nil {
					t.Fatal("DecodePayload accepted unknown kind")
				}
			}

			dual := payload
			dual.Kind = KindProtocol
			dual.Operation = &nex.Operation{ID: "op-dual"}
			dual.Command = &nex.ProtocolCommand{RequestID: "req-dual", ProtocolID: "proto-dual"}
			if encoded, err := json.Marshal(dual); err == nil {
				if _, err := DecodePayload(encoded); err == nil {
					t.Fatal("DecodePayload accepted both Operation and Command set")
				}
			}
		}

		// Validate Outbox.Enqueue with fuzzed metadata (must never panic).
		var kind Kind
		switch kindSel % 3 {
		case 0:
			kind = KindAgreement
		case 1:
			kind = KindProtocol
		default:
			kind = Kind("invalid-unknown-kind")
		}
		fuzzedItem := OutboundItem{
			Version:      Version,
			Tenant:       itemTenant,
			AgreementID:  agreementID,
			OperationID:  itemOpID,
			Kind:         kind,
			SignedObject: raw,
			Destination:  dest,
			CreatedAt:    now,
		}
		enqErr := outbox.Enqueue(fuzzedItem)
		if enqErr == nil {
			if decErr != nil {
				t.Fatalf("Outbox.Enqueue accepted item whose SignedObject failed DecodePayload (%v)", decErr)
			}
			writes++
			rec, getErr := outbox.Get(fuzzedItem.Tenant, fuzzedItem.OperationID)
			if getErr != nil {
				t.Fatalf("Outbox.Get failed right after Enqueue: %v", getErr)
			}
			if !bytes.Equal(rec.Item.SignedObject, raw) {
				t.Fatal("Outbox.Get returned altered SignedObject bytes")
			}
		}

		// When DecodePayload succeeds for v2.0.2 kinds, also verify Outbox.Enqueue enforces
		// exact metadata binding (mismatched kind/agreement/operation must fail closed).
		if decErr == nil && (payload.Kind == KindAgreement || payload.Kind == KindProtocol) {
			var wantAgID, wantOpID string
			var wrongKind Kind
			if payload.Kind == KindAgreement {
				wantAgID = payload.Operation.Command.Terms
				wantOpID = payload.Operation.ID
				wrongKind = KindProtocol
			} else {
				wantAgID = payload.Command.ProtocolID
				wantOpID = payload.Command.RequestID
				wrongKind = KindAgreement
			}

			base := OutboundItem{
				Version:      Version,
				Tenant:       "fuzz-tenant",
				AgreementID:  wantAgID,
				OperationID:  wantOpID,
				Kind:         payload.Kind,
				SignedObject: raw,
				Destination:  "dest-fuzz",
				CreatedAt:    now,
			}

			// Mismatched Kind must always fail.
			mismatchKind := base
			mismatchKind.Kind = wrongKind
			if outbox.Enqueue(mismatchKind) == nil {
				t.Fatal("Outbox.Enqueue accepted Kind mismatch")
			}

			// Mismatched OperationID must always fail.
			mismatchOp := base
			mismatchOp.OperationID = wantOpID + "-x"
			if outbox.Enqueue(mismatchOp) == nil {
				t.Fatal("Outbox.Enqueue accepted OperationID mismatch")
			}

			// Mismatched AgreementID must always fail.
			mismatchAg := base
			mismatchAg.AgreementID = wantAgID + "-x"
			if outbox.Enqueue(mismatchAg) == nil {
				t.Fatal("Outbox.Enqueue accepted AgreementID mismatch")
			}

			// Well-bound item must succeed (unless IDs themselves violate validateID or size > 64 KiB) and never panic.
			if err := outbox.Enqueue(base); err == nil {
				writes++
				if _, err := outbox.Get(base.Tenant, base.OperationID); err != nil {
					t.Fatalf("Outbox.Get failed for well-bound item: %v", err)
				}
			}
		}

		if writes >= 16 {
			fuzzPruneOutboxBoxes(outboxDir)
			writes = 0
		}
	})
}
