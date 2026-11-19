package nex

import (
	"errors"
	"fmt"
)

var ErrTaskHandoff = errors.New("nex: invalid task handoff")

// TaskHandoff carries the signed work needed to check one finalized task away
// from its coordinating host. ClaimSignature is the task authority's original
// signature over Claim. Result must be independently pinned by the consumer.
type TaskHandoff struct {
	Task           TaskSpec
	Claim          ClaimRequest
	ClaimSignature []byte
	Protocol       ProtocolBundle
	Result         TaskResult
}

// VerifyTaskHandoff checks a single task's authorization, signed attempt, and
// derived outcome against independently obtained pins. expectedTaskID normally
// comes from a verified goal plan. expectedResultHash is Hash(result) obtained
// from the trusted coordinator through an authenticated channel.
//
// The result pin attests which generation and result the coordinator finalized.
// This proof alone cannot establish current ownership, the coordinator's clock,
// or the validity of upstream tasks. Artifact bytes require separate checking.
// The transport must bound input bytes before decoding this complete protocol
// bundle. Verification also enforces the protocol's event and command limits.
func VerifyTaskHandoff(h TaskHandoff, expectedTaskID, expectedResultHash string) (TaskResult, error) {
	if !protocolHash(expectedTaskID) || !protocolHash(expectedResultHash) ||
		!protocolHash(h.Task.GoalID) || !protocolHash(h.Claim.WorkerID) ||
		!protocolHash(h.Claim.ProtocolID) || !protocolHash(h.Result.Head) ||
		len(h.Result.Artifacts) > 64 {
		return TaskResult{}, ErrTaskHandoff
	}
	switch h.Result.Outcome {
	case TaskAccepted, TaskRejected, TaskIncomplete:
	default:
		return TaskResult{}, ErrTaskHandoff
	}
	if err := h.Task.validate(h.Task.GoalID); err != nil {
		return TaskResult{}, fmt.Errorf("%w: task: %w", ErrTaskHandoff, err)
	}
	if h.Task.ID() != expectedTaskID || h.Claim.TaskID != expectedTaskID || h.Claim.GoalID != h.Task.GoalID ||
		validateOperationID(h.Claim.RequestID) != nil {
		return TaskResult{}, ErrTaskHandoff
	}
	if err := Verify(h.Task.Authority, ClaimSignatureDomain, h.Claim, h.ClaimSignature); err != nil {
		return TaskResult{}, fmt.Errorf("%w: claim signature: %w", ErrTaskHandoff, err)
	}
	if err := checkAttempt(h.Task, h.Claim, h.Protocol.Spec); err != nil {
		return TaskResult{}, fmt.Errorf("%w: attempt binding: %w", ErrTaskHandoff, err)
	}
	lease := TaskLease{
		GoalID: h.Claim.GoalID, TaskID: h.Claim.TaskID, ProtocolID: h.Claim.ProtocolID,
		WorkerID: h.Claim.WorkerID, RequestID: h.Claim.RequestID,
		Generation: h.Protocol.Spec.Generation, LeaseUntilHeight: h.Claim.LeaseUntilHeight,
	}
	if lease != h.Result.Lease {
		return TaskResult{}, ErrTaskHandoff
	}
	for _, artifact := range h.Result.Artifacts {
		if !coordinationName(artifact.Slot) || !protocolHash(artifact.Digest) {
			return TaskResult{}, ErrTaskHandoff
		}
	}
	if Hash(h.Result) != expectedResultHash {
		return TaskResult{}, ErrTaskHandoff
	}
	view, err := VerifyProtocolBundle(h.Protocol, h.Claim.ProtocolID, h.Result.Head)
	if err != nil {
		return TaskResult{}, fmt.Errorf("%w: protocol: %w", ErrTaskHandoff, err)
	}
	if view.Height >= lease.LeaseUntilHeight {
		return TaskResult{}, ErrTaskHandoff
	}
	result, err := taskResult(h.Task, lease, view)
	if err != nil {
		return TaskResult{}, fmt.Errorf("%w: result: %w", ErrTaskHandoff, err)
	}
	if Hash(result) != expectedResultHash {
		return TaskResult{}, ErrTaskHandoff
	}
	return result, nil
}

// ExportHandoff packages an already finalized attempt. The caller supplies the
// original signed claim because coordination checkpoints retain its hash rather
// than its signature. Supplying it does not create a claim or finalize work.
// The returned proof can be verified using independently authenticated task and
// result pins; it does not authenticate those pins to a remote consumer.
func (s *CoordinationStore) ExportHandoff(request ClaimRequest, signature []byte) (TaskHandoff, error) {
	task, err := s.goals.Task(request.GoalID, request.TaskID)
	if err != nil {
		return TaskHandoff{}, err
	}
	if err := Verify(task.Authority, ClaimSignatureDomain, request, signature); err != nil {
		return TaskHandoff{}, fmt.Errorf("%w: claim signature: %w", ErrTaskHandoff, err)
	}
	result, err := s.Result(request.GoalID, request.TaskID, request.ProtocolID)
	if err != nil {
		return TaskHandoff{}, err
	}
	protocol, err := s.attempts.Export(request.ProtocolID)
	if err != nil {
		return TaskHandoff{}, err
	}
	h := TaskHandoff{
		Task: task, Claim: request, ClaimSignature: append([]byte(nil), signature...),
		Protocol: protocol, Result: result,
	}
	if _, err := VerifyTaskHandoff(h, request.TaskID, Hash(result)); err != nil {
		return TaskHandoff{}, err
	}
	return h, nil
}
