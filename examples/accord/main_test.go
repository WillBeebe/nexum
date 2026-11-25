package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"github.com/WillBeebe/nexum/v2/nex"
)

func TestAccordExample(t *testing.T) {
	got, err := run(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.Example != "accord" {
		t.Fatalf("unexpected example name: %q", got.Example)
	}
	if got.UpstreamOutcomes["patch"] != nex.TaskAccepted ||
		got.UpstreamOutcomes["window"] != nex.TaskAccepted ||
		got.UpstreamOutcomes["safety"] != nex.TaskIncomplete {
		t.Fatalf("unexpected upstream outcomes: %+v", got.UpstreamOutcomes)
	}
	if got.AccordPhase != nex.AccordPhaseDecided ||
		got.WinningOption != "canary-rollout" ||
		got.WinningBindingKind != nex.BindingProtocolSpec {
		t.Fatalf("unexpected accord outcome: phase=%q winner=%q kind=%q",
			got.AccordPhase, got.WinningOption, got.WinningBindingKind)
	}
	if got.ParticipatingCount != 4 || got.ParticipatingWeight != 9 {
		t.Fatalf("unexpected participation: count=%d weight=%d", got.ParticipatingCount, got.ParticipatingWeight)
	}
	if got.WinningDissentsPreserved != 1 || got.WinningDissentRationaleHash != nex.Hash(releaseDissentRationale) {
		t.Fatalf("minority dissent not preserved: count=%d hash=%q",
			got.WinningDissentsPreserved, got.WinningDissentRationaleHash)
	}
	if !got.BoundedVetoCapEnforced || !got.ReopenRetryIdempotent || !got.TerminalRetryIdempotent ||
		!got.OfflineBundleVerified || got.OfflineArtifactsVerified != 3 ||
		!got.DisqualifiedBindingRejected || got.AuthorizedDownstreamPhase != "working" ||
		!got.DownstreamMatchesCommitment {
		t.Fatalf("expected all governance and durability invariants true: %+v", got)
	}

	byID := make(map[string]optionSummary, len(got.Options))
	for _, opt := range got.Options {
		byID[opt.OptionID] = opt
	}

	full, ok := byID["full-rollout"]
	if !ok {
		t.Fatalf("missing full-rollout tally: %+v", got.Options)
	}
	if full.GuardPassed || !full.VetoEffective || full.Eligible {
		t.Fatalf("expected full-rollout guard failed + vetoed + ineligible: %+v", full)
	}
	for _, wantPred := range []string{"safety:outcome_in:outcome_mismatch", "safety:no_witness_dissent:protocol_not_complete"} {
		if !slices.Contains(full.FailedPredicates, wantPred) {
			t.Fatalf("full-rollout missing predicate failure %q in %v", wantPred, full.FailedPredicates)
		}
	}
	for _, wantReason := range []string{"guard_failed", "vetoed"} {
		if !slices.Contains(full.DisqualificationReasons, wantReason) {
			t.Fatalf("full-rollout missing disqualification %q in %v", wantReason, full.DisqualificationReasons)
		}
	}

	canary, ok := byID["canary-rollout"]
	if !ok {
		t.Fatalf("missing canary-rollout tally: %+v", got.Options)
	}
	if !canary.GuardPassed || !canary.Eligible || canary.VetoEffective ||
		canary.ApproveCount != 3 || canary.ApproveWeight != 7 ||
		canary.DissentCount != 1 || canary.DissentWeight != 2 {
		t.Fatalf("unexpected canary-rollout tally: %+v", canary)
	}
	if !slices.Equal(canary.SatisfiedEvidence, []string{"patch", "safety", "window"}) {
		t.Fatalf("unexpected canary satisfied evidence: %v", canary.SatisfiedEvidence)
	}

	hold, ok := byID["hold-and-remediate"]
	if !ok {
		t.Fatalf("missing hold-and-remediate tally: %+v", got.Options)
	}
	if !hold.GuardPassed || hold.Eligible || hold.ApproveCount != 0 {
		t.Fatalf("unexpected hold-and-remediate tally: %+v", hold)
	}
}

func TestAccordExampleDeterministicOutput(t *testing.T) {
	var first, second bytes.Buffer
	if err := runTo(t.TempDir(), &first); err != nil {
		t.Fatal(err)
	}
	if err := runTo(t.TempDir(), &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatalf("non-deterministic output:\nfirst:\n%s\nsecond:\n%s", first.String(), second.String())
	}
}

func TestAccordOfflineBundleRejectsTampering(t *testing.T) {
	res, err := execute(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var bundle nex.AccordBundle
	if err := json.Unmarshal(res.bundleJSON, &bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := nex.VerifyAccordBundle(bundle, res.accordID, res.finalHead); err != nil {
		t.Fatalf("valid offline bundle failed verification: %v", err)
	}

	// Mutating any recorded vote rationale digest must fail offline replay.
	for i := range bundle.Events {
		if bundle.Events[i].Command.Vote != nil {
			bundle.Events[i].Command.Vote.RationaleHash = nex.Hash("tampered rationale")
			break
		}
	}
	if _, err := nex.VerifyAccordBundle(bundle, res.accordID, res.finalHead); err == nil {
		t.Fatal("expected tampered offline AccordBundle to be rejected")
	}
}
