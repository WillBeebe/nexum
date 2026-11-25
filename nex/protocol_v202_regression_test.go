// Regression tests for Nexum v2.0.2 protocol fixes:
//   - BUG-05: Protocol.Apply rejects invalid UTF-8 strings (RequestID and nested command fields)
//             before and after cloneProtocol with ErrProtocolSpec (v1 & v2).
//   - BUG-06: NewProtocol rejects invalid UTF-8 strings in ProtocolSpec (length expansion &
//             duplicate-ID coalescing) before and after cloneProtocol with ErrProtocolSpec (v1 & v2).
//   - BUG-22: Protocol.Apply verifies actor signature and c.ProtocolID == p.view.ID (ErrProtocolStale)
//             before (Actor, RequestID) history lookup (ErrOperationConflict).
//   - BUG-38: validateReturn compares Resources order-insensitively and treats nil and []ResourceUse{}
//             identically while still rejecting mismatched or duplicate resources.

package nex_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WillBeebe/nexum/v2/nex"
)

type v202ProtocolActors struct {
	owner, worker, witness nex.Identity
	spec                   nex.ProtocolSpec
}

func makeV202ProtocolActors(t *testing.T, version int) v202ProtocolActors {
	t.Helper()
	owner, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	worker, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	witness, err := nex.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub := func(id nex.Identity) nex.Public {
		p, err := id.Public()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	op, wp, zp := pub(owner), pub(worker), pub(witness)
	scope := "v202/scope-1"
	grant := func(id, actor, label string, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{
			ID:                 id,
			Actor:              actor,
			Label:              label,
			Scope:              scope,
			Permissions:        perms,
			ExpiresAtHeight:    40,
			LimitsHash:         nex.Hash("limits"),
			EvidenceObligation: nex.Hash("evidence"),
		}
	}
	spec := nex.ProtocolSpec{
		Version:           version,
		Nonce:             "v202-nonce",
		Purpose:           "Verify protocol regression fixes",
		IntendedOutcome:   "Verified handoff",
		Scope:             scope,
		SpecificationHash: nex.Hash("spec"),
		AcceptanceHash:    nex.Hash("accept"),
		FailurePolicyHash: nex.Hash("failure"),
		Initiator:         op.ID(),
		Participants:      []nex.Public{op, wp, zp},
		Roles: []nex.RoleGrant{
			grant("owner", op.ID(), "owner", nex.PermitCommit, nex.PermitDecide, nex.PermitReturn),
			grant("worker", wp.ID(), "worker", nex.PermitWork, nex.PermitReturn),
			grant("witness", zp.ID(), "witness", nex.PermitReview),
		},
		WorkByHeight:      20,
		ReturnByHeight:    40,
		RequiredWitnesses: []string{zp.ID()},
		DissentPolicy:     "record",
		Return: nex.ReturnRequirements{
			SuccessArtifacts:   []string{"answer"},
			FailureArtifacts:   []string{"failure"},
			AllowedDisposition: []string{"continue", "retry", "refuse"},
			AllowSuccessors:    true,
		},
		MaxEvents: 32,
	}
	return v202ProtocolActors{owner: owner, worker: worker, witness: witness, spec: spec}
}

func v202PubID(t *testing.T, id nex.Identity) string {
	t.Helper()
	p, err := id.Public()
	if err != nil {
		t.Fatal(err)
	}
	return p.ID()
}

func v202ArtifactRef(contents string) nex.ArtifactRef {
	sum := sha256.Sum256([]byte(contents))
	return nex.ArtifactRef{
		Digest:    hex.EncodeToString(sum[:]),
		Size:      uint64(len(contents)),
		MediaType: "text/plain",
	}
}

func admitAndCommitV202(t *testing.T, p *nex.Protocol, f v202ProtocolActors) {
	t.Helper()
	for _, a := range []nex.Identity{f.owner, f.worker, f.witness} {
		c := p.Prepare(v202PubID(t, a), "", "", "admit", "admit-"+v202PubID(t, a), 1)
		if _, err := p.Apply(c, nex.Sign(a, "protocol", c), 1); err != nil {
			t.Fatal(err)
		}
	}
	commit := p.Prepare(v202PubID(t, f.owner), "owner", f.spec.Scope, "commit", "commit", 1)
	if _, err := p.Apply(commit, nex.Sign(f.owner, "protocol", commit), 1); err != nil {
		t.Fatal(err)
	}
}

// BUG-05: Protocol.Apply must reject invalid UTF-8 strings (including 1400-byte \xff RequestID
// and nested command fields) with ErrProtocolSpec before cloneProtocol can expand them, keeping
// ProtocolStore readable and VerifyProtocolBundle valid in both v1 and v2.
func TestV202_ProtocolApplyRejectsInvalidUTF8Commands(t *testing.T) {
	for _, version := range []int{nex.ProtocolVersion, nex.ProtocolVersionV2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			f := makeV202ProtocolActors(t, version)
			store, err := nex.OpenProtocolStore(filepath.Join(t.TempDir(), "ps"), bytes.Repeat([]byte{11}, 32))
			if err != nil {
				t.Fatal(err)
			}
			id, err := store.Create(f.spec)
			if err != nil {
				t.Fatal(err)
			}

			badReqID := strings.Repeat("\xff", 1400) // 1400 <= 4096, would expand to 4200 > 4096 in cloneProtocol
			cmd, err := store.Prepare(id, v202PubID(t, f.witness), "", "", "admit", badReqID, 1)
			if err != nil {
				t.Fatal(err)
			}
			sig := nex.Sign(f.witness, "protocol", cmd)

			if _, applyErr := store.Apply(id, cmd, sig, 1); !errors.Is(applyErr, nex.ErrProtocolSpec) {
				t.Fatalf("v%d store.Apply with invalid UTF-8 RequestID: got %v, want ErrProtocolSpec", version, applyErr)
			}
			view, viewErr := store.View(id)
			if viewErr != nil {
				t.Fatalf("v%d ProtocolStore.View failed after rejected command: %v", version, viewErr)
			}
			if len(view.Admitted) != 0 {
				t.Fatalf("v%d rejected command mutated Admitted: %+v", version, view.Admitted)
			}
			bundle, err := store.Export(id)
			if err != nil {
				t.Fatal(err)
			}
			if _, verifyErr := nex.VerifyProtocolBundle(bundle, view.ID, view.Head); verifyErr != nil {
				t.Fatalf("v%d VerifyProtocolBundle failed after rejected command: %v", version, verifyErr)
			}

			// In-memory Protocol.Apply must also reject invalid UTF-8 in RequestID and nested fields.
			p, err := nex.NewProtocol(f.spec)
			if err != nil {
				t.Fatal(err)
			}
			c2 := p.Prepare(v202PubID(t, f.witness), "", "", "admit", badReqID, 1)
			if _, err := p.Apply(c2, nex.Sign(f.witness, "protocol", c2), 1); !errors.Is(err, nex.ErrProtocolSpec) {
				t.Fatalf("v%d in-mem Apply invalid UTF-8 RequestID: got %v, want ErrProtocolSpec", version, err)
			}

			admitAndCommitV202(t, p, f)
			answer := v202ArtifactRef("ok")

			badReportCases := []struct {
				name   string
				mutate func(*nex.WorkReport)
			}{
				{"stage", func(r *nex.WorkReport) { r.Stage = "bad\xffstage" }},
				{"resource", func(r *nex.WorkReport) { r.Resources = []nex.ResourceUse{{Resource: "cpu\xff"}} }},
				{"breach_actor", func(r *nex.WorkReport) {
					r.BreachClaims = []nex.BreachClaim{{Actor: "\xff", EvidenceHash: nex.Hash("e")}}
				}},
			}
			if version == nex.ProtocolVersionV2 {
				badReportCases = append(badReportCases,
					struct {
						name   string
						mutate func(*nex.WorkReport)
					}{"manifest_output_name", func(r *nex.WorkReport) {
						r.Manifest = &nex.EvidenceManifest{
							MethodHash: nex.Hash("m"),
							Outputs:    []nex.NamedArtifact{{Name: "ans\xff", Ref: answer}},
						}
					}},
					struct {
						name   string
						mutate func(*nex.WorkReport)
					}{"manifest_media_type", func(r *nex.WorkReport) {
						badRef := answer
						badRef.MediaType = "text/plain; x=\xff"
						r.Manifest = &nex.EvidenceManifest{
							MethodHash: nex.Hash("m"),
							Outputs:    []nex.NamedArtifact{{Name: "answer", Ref: badRef}},
						}
					}},
				)
			}
			for _, tc := range badReportCases {
				rep := p.Prepare(v202PubID(t, f.worker), "worker", f.spec.Scope, "report", "rep-"+tc.name, 2)
				wr := &nex.WorkReport{
					Outcome:    nex.WorkCompleted,
					Stage:      "done",
					ReasonHash: nex.Hash("r"),
					Evidence:   []string{nex.Hash("e")},
				}
				if version == nex.ProtocolVersionV2 {
					wr.Manifest = &nex.EvidenceManifest{
						MethodHash: nex.Hash("m"),
						Outputs:    []nex.NamedArtifact{{Name: "answer", Ref: answer}},
					}
				}
				tc.mutate(wr)
				rep.Report = wr
				if _, err := p.Apply(rep, nex.Sign(f.worker, "protocol", rep), 2); !errors.Is(err, nex.ErrProtocolSpec) {
					t.Fatalf("v%d report invalid UTF-8 (%s): got %v, want ErrProtocolSpec", version, tc.name, err)
				}
			}

			// Advance to return_due and verify invalid UTF-8 in ReturnManifest fields is rejected with ErrProtocolSpec.
			goodRep := p.Prepare(v202PubID(t, f.worker), "worker", f.spec.Scope, "report", "rep-good", 2)
			goodRep.Report = &nex.WorkReport{
				Outcome:    nex.WorkCompleted,
				Stage:      "done",
				ReasonHash: nex.Hash("r"),
				Evidence:   []string{nex.Hash("e")},
			}
			if version == nex.ProtocolVersionV2 {
				goodRep.Report.Manifest = &nex.EvidenceManifest{
					MethodHash: nex.Hash("m"),
					Outputs:    []nex.NamedArtifact{{Name: "answer", Ref: answer}},
				}
			}
			if _, err := p.Apply(goodRep, nex.Sign(f.worker, "protocol", goodRep), 2); err != nil {
				t.Fatal(err)
			}
			rev := p.Prepare(v202PubID(t, f.witness), "witness", f.spec.Scope, "review", "rev", 3)
			rev.Review = &nex.WitnessReview{ReportHash: nex.Hash(p.View().Report), AssessmentHash: nex.Hash("a")}
			if _, err := p.Apply(rev, nex.Sign(f.witness, "protocol", rev), 3); err != nil {
				t.Fatal(err)
			}
			res := p.Prepare(v202PubID(t, f.owner), "owner", f.spec.Scope, "resolve", "res", 4)
			res.Resolution = &nex.Resolution{ReportHash: nex.Hash(p.View().Report), Outcome: "accept", ReasonHash: nex.Hash("ok")}
			if _, err := p.Apply(res, nex.Sign(f.owner, "protocol", res), 4); err != nil {
				t.Fatal(err)
			}

			v := p.View()
			badReturnCases := []struct {
				name   string
				mutate func(*nex.ReturnManifest)
			}{
				{"uncertainty", func(m *nex.ReturnManifest) { m.Uncertainty = "unc\xff" }},
				{"safe_assumption", func(m *nex.ReturnManifest) { m.SafeAssumptions = []string{"ok\xff"} }},
				{"artifact_reuse", func(m *nex.ReturnManifest) { m.Artifacts[0].ReuseRestrictions = "cite\xff" }},
				{"resource", func(m *nex.ReturnManifest) { m.Resources = []nex.ResourceUse{{Resource: "\xff"}} }},
			}
			for _, tc := range badReturnCases {
				ret := p.Prepare(v202PubID(t, f.worker), "worker", f.spec.Scope, "return", "ret-"+tc.name, 5)
				m := &nex.ReturnManifest{
					ResolutionHash:  nex.Hash(v.Resolution),
					ReviewsHash:     nex.Hash(v.Reviews),
					Evidence:        v.Report.Evidence,
					Uncertainty:     "bounded",
					SafeAssumptions: []string{"none"},
					Artifacts:       []nex.ReturnArtifact{{ID: "answer", Commitment: answer.Digest, ReuseRestrictions: "cite"}},
					Disposition:     "continue",
				}
				tc.mutate(m)
				ret.Return = m
				if _, err := p.Apply(ret, nex.Sign(f.worker, "protocol", ret), 5); !errors.Is(err, nex.ErrProtocolSpec) {
					t.Fatalf("v%d return invalid UTF-8 (%s): got %v, want ErrProtocolSpec", version, tc.name, err)
				}
			}
		})
	}
}

// BUG-06: NewProtocol and ProtocolStore.Create must reject invalid UTF-8 strings in both
// v1 and v2 ProtocolSpec (preventing 3x length expansion and duplicate-ID coalescing).
func TestV202_ProtocolNewRejectsInvalidUTF8Specs(t *testing.T) {
	for _, version := range []int{nex.ProtocolVersion, nex.ProtocolVersionV2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			cases := []struct {
				name   string
				mutate func(*nex.ProtocolSpec)
			}{
				{
					name: "length_expansion_success_artifact",
					mutate: func(s *nex.ProtocolSpec) {
						s.Return.SuccessArtifacts = []string{strings.Repeat("\xff", 43)}
					},
				},
				{
					name: "failure_artifact_invalid_utf8",
					mutate: func(s *nex.ProtocolSpec) {
						s.Return.FailureArtifacts = []string{"fail\xff"}
					},
				},
				{
					name: "duplicate_coalescing_role_ids",
					mutate: func(s *nex.ProtocolSpec) {
						s.Roles[0].ID = "\xfe"
						s.Roles[1].ID = "\xff"
					},
				},
				{
					name: "role_label_invalid_utf8",
					mutate: func(s *nex.ProtocolSpec) {
						s.Roles[0].Label = "owner\xff"
					},
				},
				{
					name: "nonce_invalid_utf8",
					mutate: func(s *nex.ProtocolSpec) {
						s.Nonce = strings.Repeat("\xff", 1400)
					},
				},
				{
					name: "purpose_invalid_utf8",
					mutate: func(s *nex.ProtocolSpec) {
						s.Purpose = "purpose\xff"
					},
				},
				{
					name: "intended_outcome_invalid_utf8",
					mutate: func(s *nex.ProtocolSpec) {
						s.IntendedOutcome = "outcome\xff"
					},
				},
				{
					name: "scope_invalid_utf8",
					mutate: func(s *nex.ProtocolSpec) {
						s.Scope = "scope\xff"
						for i := range s.Roles {
							s.Roles[i].Scope = s.Scope
						}
					},
				},
				{
					name: "resource_invalid_utf8",
					mutate: func(s *nex.ProtocolSpec) {
						s.Resources = []nex.ResourceLimit{{Resource: "gpu\xff", Maximum: 10}}
					},
				},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					f := makeV202ProtocolActors(t, version)
					tc.mutate(&f.spec)
					if _, err := nex.NewProtocol(f.spec); !errors.Is(err, nex.ErrProtocolSpec) {
						t.Fatalf("v%d NewProtocol(%s): got %v, want ErrProtocolSpec", version, tc.name, err)
					}
					store, err := nex.OpenProtocolStore(filepath.Join(t.TempDir(), "ps"), bytes.Repeat([]byte{12}, 32))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := store.Create(f.spec); !errors.Is(err, nex.ErrProtocolSpec) {
						t.Fatalf("v%d ProtocolStore.Create(%s): got %v, want ErrProtocolSpec", version, tc.name, err)
					}
				})
			}
		})
	}
}

// BUG-22: Protocol.Apply must verify actor signature and c.ProtocolID == p.view.ID (ErrProtocolStale)
// BEFORE checking (Actor, RequestID) history (ErrOperationConflict).
func TestV202_ProtocolForeignCommandReturnsStaleNotConflict(t *testing.T) {
	f1 := makeV202ProtocolActors(t, nex.ProtocolVersionV2)
	f2 := f1
	f2.spec.Nonce = "v202-nonce-2"

	p1, err := nex.NewProtocol(f1.spec)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := nex.NewProtocol(f2.spec)
	if err != nil {
		t.Fatal(err)
	}

	c1 := p1.Prepare(v202PubID(t, f1.owner), "", "", "admit", "admit-owner", 1)
	sig1 := nex.Sign(f1.owner, "protocol", c1)
	h1, err := p1.Apply(c1, sig1, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Validly signed command targeting p2 with the same per-protocol RequestID "admit-owner".
	c2 := p2.Prepare(v202PubID(t, f1.owner), "", "", "admit", "admit-owner", 1)
	sig2 := nex.Sign(f1.owner, "protocol", c2)

	if _, err := p1.Apply(c2, sig2, 1); !errors.Is(err, nex.ErrProtocolStale) {
		t.Fatalf("foreign command returned %v (ErrOperationConflict=%v), want ErrProtocolStale",
			err, errors.Is(err, nex.ErrOperationConflict))
	}

	// Forged signature on a foreign command with colliding RequestID must fail signature
	// verification FIRST (not ErrProtocolStale and not ErrOperationConflict).
	badSig := bytes.Clone(sig2)
	badSig[0] ^= 0xff
	if _, err := p1.Apply(c2, badSig, 1); err == nil || errors.Is(err, nex.ErrProtocolStale) || errors.Is(err, nex.ErrOperationConflict) {
		t.Fatalf("forged foreign command returned %v, want signature error", err)
	}

	// Same-protocol exact retry still returns original receipt.
	if got, err := p1.Apply(c1, sig1, 99); err != nil || got != h1 {
		t.Fatalf("exact retry got (%q, %v), want (%q, nil)", got, err, h1)
	}

	// Same-protocol conflicting payload on the same (Actor, RequestID) still returns ErrOperationConflict.
	conflict := c1
	conflict.Height = 2
	if _, err := p1.Apply(conflict, nex.Sign(f1.owner, "protocol", conflict), 2); !errors.Is(err, nex.ErrOperationConflict) {
		t.Fatalf("same-protocol conflict returned %v, want ErrOperationConflict", err)
	}

	// Verify identical behavior through ProtocolStore.Apply as well.
	store, err := nex.OpenProtocolStore(filepath.Join(t.TempDir(), "ps"), bytes.Repeat([]byte{14}, 32))
	if err != nil {
		t.Fatal(err)
	}
	id1, err := store.Create(f1.spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(id1, c1, sig1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(id1, c2, sig2, 1); !errors.Is(err, nex.ErrProtocolStale) {
		t.Fatalf("store.Apply foreign command returned %v, want ErrProtocolStale", err)
	}
}

// BUG-38: validateReturn must compare m.Resources and v.Report.Resources order-insensitively
// and treat nil and []ResourceUse{} identically, while rejecting mismatched or duplicate resources.
func TestV202_ProtocolReturnResourcesOrderAndEmptySlice(t *testing.T) {
	setupReadyForReturn := func(t *testing.T, limits []nex.ResourceLimit, reportRes []nex.ResourceUse) (*nex.Protocol, v202ProtocolActors, nex.ArtifactRef) {
		t.Helper()
		f := makeV202ProtocolActors(t, nex.ProtocolVersionV2)
		f.spec.Resources = limits
		p, err := nex.NewProtocol(f.spec)
		if err != nil {
			t.Fatal(err)
		}
		admitAndCommitV202(t, p, f)
		answer := v202ArtifactRef("ok")
		rep := p.Prepare(v202PubID(t, f.worker), "worker", f.spec.Scope, "report", "report", 2)
		rep.Report = &nex.WorkReport{
			Outcome:    nex.WorkCompleted,
			Stage:      "done",
			ReasonHash: nex.Hash("r"),
			Evidence:   []string{nex.Hash("e")},
			Resources:  reportRes,
			Manifest:   &nex.EvidenceManifest{MethodHash: nex.Hash("m"), Outputs: []nex.NamedArtifact{{Name: "answer", Ref: answer}}},
		}
		if _, err := p.Apply(rep, nex.Sign(f.worker, "protocol", rep), 2); err != nil {
			t.Fatal(err)
		}
		rev := p.Prepare(v202PubID(t, f.witness), "witness", f.spec.Scope, "review", "review", 3)
		rev.Review = &nex.WitnessReview{ReportHash: nex.Hash(p.View().Report), AssessmentHash: nex.Hash("a")}
		if _, err := p.Apply(rev, nex.Sign(f.witness, "protocol", rev), 3); err != nil {
			t.Fatal(err)
		}
		res := p.Prepare(v202PubID(t, f.owner), "owner", f.spec.Scope, "resolve", "resolve", 4)
		res.Resolution = &nex.Resolution{ReportHash: nex.Hash(p.View().Report), Outcome: "accept", ReasonHash: nex.Hash("ok")}
		if _, err := p.Apply(res, nex.Sign(f.owner, "protocol", res), 4); err != nil {
			t.Fatal(err)
		}
		return p, f, answer
	}

	makeReturn := func(t *testing.T, p *nex.Protocol, f v202ProtocolActors, answer nex.ArtifactRef, reqID string, resources []nex.ResourceUse) nex.ProtocolCommand {
		t.Helper()
		v := p.View()
		ret := p.Prepare(v202PubID(t, f.worker), "worker", f.spec.Scope, "return", reqID, 5)
		ret.Return = &nex.ReturnManifest{
			ResolutionHash:  nex.Hash(v.Resolution),
			ReviewsHash:     nex.Hash(v.Reviews),
			Evidence:        v.Report.Evidence,
			Resources:       resources,
			Uncertainty:     "bounded",
			SafeAssumptions: []string{"none"},
			Artifacts:       []nex.ReturnArtifact{{ID: "answer", Commitment: answer.Digest, ReuseRestrictions: "cite"}},
			Disposition:     "continue",
		}
		return ret
	}

	t.Run("nil_vs_empty_slice", func(t *testing.T) {
		p, f, answer := setupReadyForReturn(t, nil, []nex.ResourceUse{})
		ret := makeReturn(t, p, f, answer, "return", nil)
		head, err := p.Apply(ret, nex.Sign(f.worker, "protocol", ret), 5)
		if err != nil {
			t.Fatalf("return with Resources=nil rejected when report had Resources=[]ResourceUse{}: %v", err)
		}
		if _, err := nex.VerifyProtocolBundle(p.Bundle(), p.View().ID, head); err != nil {
			t.Fatalf("VerifyProtocolBundle failed: %v", err)
		}
	})

	t.Run("empty_slice_vs_nil", func(t *testing.T) {
		p, f, answer := setupReadyForReturn(t, nil, nil)
		ret := makeReturn(t, p, f, answer, "return", []nex.ResourceUse{})
		head, err := p.Apply(ret, nex.Sign(f.worker, "protocol", ret), 5)
		if err != nil {
			t.Fatalf("return with Resources=[]ResourceUse{} rejected when report had Resources=nil: %v", err)
		}
		if _, err := nex.VerifyProtocolBundle(p.Bundle(), p.View().ID, head); err != nil {
			t.Fatalf("VerifyProtocolBundle failed: %v", err)
		}
	})

	t.Run("reordered_resources", func(t *testing.T) {
		limits := []nex.ResourceLimit{
			{Resource: "cpu_ms", Maximum: 100},
			{Resource: "mem_mb", Maximum: 256},
		}
		reportRes := []nex.ResourceUse{
			{Resource: "cpu_ms", Used: 10},
			{Resource: "mem_mb", Used: 64},
		}
		p, f, answer := setupReadyForReturn(t, limits, reportRes)

		// Negative checks first (must not mutate state):
		badCases := []struct {
			name string
			res  []nex.ResourceUse
		}{
			{"different_used", []nex.ResourceUse{{Resource: "mem_mb", Used: 65}, {Resource: "cpu_ms", Used: 10}}},
			{"different_unknown", []nex.ResourceUse{{Resource: "mem_mb", Used: 64, Unknown: true}, {Resource: "cpu_ms", Used: 10}}},
			{"duplicate_resource", []nex.ResourceUse{{Resource: "cpu_ms", Used: 10}, {Resource: "cpu_ms", Used: 10}}},
			{"missing_resource", []nex.ResourceUse{{Resource: "cpu_ms", Used: 10}}},
		}
		for _, tc := range badCases {
			bad := makeReturn(t, p, f, answer, "bad-"+tc.name, tc.res)
			if _, err := p.Apply(bad, nex.Sign(f.worker, "protocol", bad), 5); !errors.Is(err, nex.ErrProtocolEvidence) {
				t.Fatalf("mismatched resources (%s) got %v, want ErrProtocolEvidence", tc.name, err)
			}
		}

		// Positive check: reordered identical resources must succeed and verify cleanly.
		reordered := []nex.ResourceUse{
			{Resource: "mem_mb", Used: 64},
			{Resource: "cpu_ms", Used: 10},
		}
		ret := makeReturn(t, p, f, answer, "return-ok", reordered)
		head, err := p.Apply(ret, nex.Sign(f.worker, "protocol", ret), 5)
		if err != nil {
			t.Fatalf("return with reordered identical Resources rejected: %v", err)
		}
		if _, err := nex.VerifyProtocolBundle(p.Bundle(), p.View().ID, head); err != nil {
			t.Fatalf("VerifyProtocolBundle failed: %v", err)
		}
	})
}
