package nex

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"mime"
	"slices"
	"strings"
	"unicode/utf8"
)

// ArtifactRef commits to a byte sequence using a lowercase hex SHA-256 digest.
// Artifact access and storage belong to the application.
type ArtifactRef struct {
	Digest    string
	Size      uint64
	MediaType string
}

func (a ArtifactRef) Validate() error {
	if !protocolHash(a.Digest) || a.Size >= math.MaxInt64 || len(a.MediaType) > 255 || !utf8.ValidString(a.MediaType) {
		return ErrProtocolEvidence
	}
	mediaType, _, err := mime.ParseMediaType(a.MediaType)
	if err != nil || !strings.Contains(mediaType, "/") {
		return ErrProtocolEvidence
	}
	return nil
}

// Verify checks the size and digest of bytes from an artifact source. Any later
// use must read the same verified bytes or independently verify them again.
func (a ArtifactRef) Verify(r io.Reader) error {
	if err := a.Validate(); err != nil {
		return err
	}
	h := sha256.New()
	size, err := io.Copy(h, io.LimitReader(r, int64(a.Size)+1))
	if err != nil {
		return err
	}
	if uint64(size) != a.Size || hex.EncodeToString(h.Sum(nil)) != a.Digest {
		return ErrProtocolEvidence
	}
	return nil
}

type NamedArtifact struct {
	Name string
	Ref  ArtifactRef
}

// EvidenceManifest names the artifacts and commitments examined during review.
// MethodHash and Claims refer to application-defined content. A manifest binds
// these assertions, while a witness establishes what it actually verified.
type EvidenceManifest struct {
	Inputs, Outputs []NamedArtifact
	MethodHash      string
	Claims          []string
}

func (m EvidenceManifest) Validate() error {
	if !protocolHash(m.MethodHash) || !uniqueStrings(m.Claims, 64, protocolHash) ||
		!validNamedArtifacts(m.Inputs) || !validNamedArtifacts(m.Outputs) {
		return ErrProtocolEvidence
	}
	return nil
}

func validNamedArtifacts(artifacts []NamedArtifact) bool {
	if len(artifacts) > 64 {
		return false
	}
	names := map[string]bool{}
	for _, a := range artifacts {
		if len(a.Name) == 0 || len(a.Name) > 128 || !utf8.ValidString(a.Name) || names[a.Name] || a.Ref.Validate() != nil {
			return false
		}
		names[a.Name] = true
	}
	return true
}

func validV2SpecText(s ProtocolSpec) bool {
	return validProtocolSpecUTF8(s)
}

func validateReportManifest(r WorkReport, s ProtocolSpec) error {
	if r.Manifest == nil {
		if s.Version == ProtocolVersionV2 && r.Outcome == WorkCompleted {
			return ErrProtocolEvidence
		}
		return nil
	}
	if s.Version != ProtocolVersionV2 || r.Manifest.Validate() != nil {
		return ErrProtocolEvidence
	}
	if r.Outcome == WorkCompleted {
		for _, required := range s.Return.SuccessArtifacts {
			if !slices.ContainsFunc(r.Manifest.Outputs, func(a NamedArtifact) bool { return a.Name == required }) {
				return ErrProtocolEvidence
			}
		}
	}
	return nil
}

func validateReturnedOutputs(m ReturnManifest, reviewed *EvidenceManifest) error {
	for _, a := range m.Artifacts {
		if !slices.ContainsFunc(reviewed.Outputs, func(output NamedArtifact) bool {
			return output.Name == a.ID && output.Ref.Digest == a.Commitment
		}) {
			return ErrProtocolEvidence
		}
	}
	return nil
}

// IncompleteReturn supplies evidence for a deadline closeout. These artifacts
// are explicitly partial and may be supplied without a work report or review.
type IncompleteReturn struct {
	ReasonHash string
	Evidence   []string
	Artifacts  []NamedArtifact
}

func (r IncompleteReturn) validate() error {
	if !protocolHash(r.ReasonHash) || !uniqueStrings(r.Evidence, 128, protocolHash) || !validNamedArtifacts(r.Artifacts) {
		return ErrProtocolEvidence
	}
	return nil
}

// IncompleteState records missing protocol obligations derived from the signed
// transcript. Any existing report, reviews, and resolution remain in the view.
type IncompleteState struct {
	IncompleteReturn
	MissingAdmissions  []string
	MissingWitnesses   []string
	MissingObligations []string
}

func incompleteState(r IncompleteReturn, v ProtocolView, s ProtocolSpec) *IncompleteState {
	state := &IncompleteState{IncompleteReturn: r}
	for _, participant := range s.Participants {
		id := participant.ID()
		if !slices.Contains(v.Admitted, id) {
			state.MissingAdmissions = append(state.MissingAdmissions, id)
		}
	}
	for _, witness := range s.RequiredWitnesses {
		if !slices.ContainsFunc(v.Reviews, func(review RecordedReview) bool { return review.Actor == witness }) {
			state.MissingWitnesses = append(state.MissingWitnesses, witness)
		}
	}
	if v.Phase == "admission" {
		state.MissingObligations = append(state.MissingObligations, "commit")
	}
	if v.Report == nil {
		state.MissingObligations = append(state.MissingObligations, "report")
	}
	if v.Resolution == nil {
		state.MissingObligations = append(state.MissingObligations, "resolve")
	}
	state.MissingObligations = append(state.MissingObligations, "return")
	return state
}
