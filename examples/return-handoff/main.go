// A delegation that returns a useful failure artifact and preserved dissent,
// with no amount, token, reward, or resource allocation.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/WillBeebe/nexum/nex"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	owner, err := nex.NewIdentity()
	if err != nil {
		return err
	}
	worker, err := nex.NewIdentity()
	if err != nil {
		return err
	}
	witness, err := nex.NewIdentity()
	if err != nil {
		return err
	}
	a, err := owner.Public()
	if err != nil {
		return err
	}
	b, err := worker.Public()
	if err != nil {
		return err
	}
	c, err := witness.Public()
	if err != nil {
		return err
	}
	purpose := "Return a reproducible answer, or enough evidence for the next agent to continue safely"
	scope := "research/reproducibility"
	grant := func(id, actor, label string, permissions ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{ID: id, Actor: actor, Label: label, Scope: scope, Permissions: permissions, ExpiresAtHeight: 40, LimitsHash: nex.Hash("only this research question"), EvidenceObligation: nex.Hash("cite reproducible evidence")}
	}
	spec := nex.ProtocolSpec{Version: nex.ProtocolVersion, Nonce: "return-handoff-example-v1", Purpose: purpose, IntendedOutcome: "An answer or a documented specification defect", Scope: scope, SpecificationHash: nex.Hash("Attempt reproduction; do not invent missing inputs"), AcceptanceHash: nex.Hash("Independent witness can reproduce the answer"), FailurePolicyHash: nex.Hash("Return failure evidence and uncertainty; retry requires fresh admission"), Initiator: a.ID(), Participants: []nex.Public{a, b, c}, Roles: []nex.RoleGrant{grant("proposer", a.ID(), "proposer", nex.PermitCommit, nex.PermitDecide, nex.PermitReturn), grant("worker", b.ID(), "worker", nex.PermitWork, nex.PermitReturn), grant("witness", c.ID(), "witness", nex.PermitReview)}, WorkByHeight: 20, ReturnByHeight: 40, RequiredWitnesses: []string{c.ID()}, DissentPolicy: "record", Return: nex.ReturnRequirements{SuccessArtifacts: []string{"answer"}, FailureArtifacts: []string{"failure-record"}, AllowedDisposition: []string{"retry", "continue", "refuse"}, AllowSuccessors: true}, MaxEvents: 32}
	p, err := nex.NewProtocol(spec)
	if err != nil {
		return err
	}
	apply := func(actor nex.Identity, role, action string, fill func(*nex.ProtocolCommand)) error {
		pub, err := actor.Public()
		if err != nil {
			return err
		}
		v := p.View()
		cmd := p.Prepare(pub.ID(), role, scope, action, action+":"+v.Head, v.Height+1)
		if action == "admit" {
			cmd.Scope = ""
			cmd.GrantID = ""
		}
		if fill != nil {
			fill(&cmd)
		}
		_, err = p.Apply(cmd, nex.Sign(actor, "protocol", cmd), cmd.Height)
		return err
	}
	for _, actor := range []nex.Identity{owner, worker, witness} {
		if err = apply(actor, "", "admit", nil); err != nil {
			return err
		}
	}
	if err = apply(owner, "proposer", "commit", nil); err != nil {
		return err
	}
	failure := "The requested reproduction omitted its input dataset version. No reproducibility claim can be made."
	if err = apply(worker, "worker", "report", func(cmd *nex.ProtocolCommand) {
		cmd.Report = &nex.WorkReport{Outcome: nex.WorkSpecDefect, Stage: "reproduction prerequisites", ReasonHash: nex.Hash(failure), Evidence: []string{nex.Hash(failure)}}
	}); err != nil {
		return err
	}
	if err = apply(witness, "witness", "review", func(cmd *nex.ProtocolCommand) {
		cmd.Review = &nex.WitnessReview{ReportHash: nex.Hash(p.View().Report), AssessmentHash: nex.Hash("Agree that reproduction is blocked; dissent from calling the specification itself defective before asking its author"), Dissent: true}
	}); err != nil {
		return err
	}
	if err = apply(owner, "proposer", "resolve", func(cmd *nex.ProtocolCommand) {
		cmd.Resolution = &nex.Resolution{ReportHash: nex.Hash(p.View().Report), Outcome: "reject", ReasonHash: nex.Hash("No verified answer; preserve the attempt and the witness interpretation")}
	}); err != nil {
		return err
	}
	if err = apply(worker, "worker", "return", func(cmd *nex.ProtocolCommand) {
		v := p.View()
		cmd.Return = &nex.ReturnManifest{ResolutionHash: nex.Hash(v.Resolution), ReviewsHash: nex.Hash(v.Reviews), Evidence: v.Report.Evidence, Resources: v.Report.Resources, Uncertainty: "The dataset may exist elsewhere; the cause remains unresolved", SafeAssumptions: []string{"No reproduction was verified", "Ask for the exact dataset version before trying again"}, Artifacts: []nex.ReturnArtifact{{ID: "failure-record", Commitment: nex.Hash(failure), ReuseRestrictions: "Preserve the missing-input limitation and witness dissent"}}, Disposition: "retry", SuccessorSpecs: []string{nex.Hash("A fresh agreement to obtain the dataset version")}}
	}); err != nil {
		return err
	}
	v := p.View()
	if _, err = nex.VerifyProtocolBundle(p.Bundle(), v.ID, v.Head); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"purpose": purpose, "phase": v.Phase, "work_outcome": v.Report.Outcome, "resolution": v.Resolution.Outcome, "dissent_preserved": v.Reviews[0].Review.Dissent, "return": v.Return, "verified": true, "head": v.Head})
}
