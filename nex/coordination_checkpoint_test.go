package nex

import "testing"

func TestTaskCheckpointRejectsConflictingAcceptedResults(t *testing.T) {
	lease := TaskLease{GoalID: "goal", TaskID: "task", ProtocolID: "proto-1", WorkerID: "worker", RequestID: "req-1", Generation: 1, LeaseUntilHeight: 10}
	state := taskCheckpoint{
		Version: taskCheckpointVersion, Lease: lease, ClaimHash: "claim",
		Results: map[string]TaskResult{
			"proto-1": {Lease: lease, Head: "head-1", Outcome: TaskAccepted},
			"proto-2": {Lease: TaskLease{GoalID: "goal", TaskID: "task", ProtocolID: "proto-2", WorkerID: "worker", RequestID: "req-2", Generation: 2, LeaseUntilHeight: 20}, Head: "head-2", Outcome: TaskAccepted},
		},
	}
	if validateTaskCheckpoint(state, "goal", "task") == nil {
		t.Fatal("two accepted task results passed validation")
	}
	delete(state.Results, "proto-2")
	if err := validateTaskCheckpoint(state, "goal", "task"); err != nil {
		t.Fatal(err)
	}
	mismatched := state.Results["proto-1"]
	mismatched.Lease.ProtocolID = "other"
	mismatched.Head = "head-2"
	mismatched.Outcome = TaskIncomplete
	state.Results["proto-2"] = mismatched
	if validateTaskCheckpoint(state, "goal", "task") == nil {
		t.Fatal("result key did not match its protocol id")
	}
}
