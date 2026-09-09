package nex

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

type storeFixture struct {
	store         *Store
	dir           string
	key           []byte
	buyer, seller Identity
	contract      *Contract
	now           time.Time
}

func newStoreFixture(t *testing.T) storeFixture {
	t.Helper()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	buyer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	seller, err := NewIdentity()
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
	c, err := New("work.bounty", bp, sp, 10, map[string]string{"task": "private test artifact"}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "agreements")
	store, err := OpenStore(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Create(c); err != nil {
		t.Fatal(err)
	}
	return storeFixture{store, dir, key, buyer, seller, c, now}
}

func (f storeFixture) reopen(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(f.dir, f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (f storeFixture) prepare(t *testing.T, opID, action string) (Operation, []byte) {
	t.Helper()
	op, err := f.store.Prepare(f.contract.ID(), opID, action, "checked artifact")
	if err != nil {
		t.Fatal(err)
	}
	signer := f.buyer
	if action == "agree" || action == "reject" {
		signer = f.seller
	}
	return op, Sign(signer, "operation", op)
}
func viewStore(t *testing.T, s *Store, id string) ContractState {
	t.Helper()
	v, err := s.View(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestStoreRestartAndStableRetryResults(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	initial := viewStore(t, f.store, id)
	if !reflect.DeepEqual(initial, viewStore(t, f.reopen(t), id)) {
		t.Fatal("creation changed after restart")
	}
	if err := f.store.Create(f.contract); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	var locked Result
	var lockOp Operation
	var lockSig []byte
	for i, action := range []string{"lock", "agree", "settle"} {
		op, sig := f.prepare(t, action+"-stable-id", action)
		result, err := f.store.Apply(id, op, sig, f.now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(action, err)
		}
		f.store = f.reopen(t)
		state := viewStore(t, f.store, id)
		if state.Head != result.Head || state.Status != result.Status {
			t.Fatal("result not persisted")
		}
		retried, err := f.store.Apply(id, op, sig, f.now.Add(24*time.Hour))
		if err != nil || retried != result {
			t.Fatalf("retry after expiry: %+v %v", retried, err)
		}
		if !reflect.DeepEqual(state, viewStore(t, f.store, id)) {
			t.Fatal("retry changed state")
		}
		if action == "lock" {
			locked = result
			lockOp = op
			lockSig = sig
		}
	}
	final := viewStore(t, f.store, id)
	if final.Status != StatusAccepted || !final.Agreed || len(final.Receipts) != 6 {
		t.Fatalf("%+v", final)
	}
	if !reflect.DeepEqual(initial.Terms, final.Terms) {
		t.Fatal("terms changed")
	}
	// An old successful result remains stable after later commands and restart.
	result, err := f.store.Apply(id, lockOp, lockSig, f.now.Add(48*time.Hour))
	if err != nil || result != locked || result.Head == final.Head {
		t.Fatalf("old result: %+v %v", result, err)
	}
	// No caller-owned alias can alter the durable record.
	final.Terms.Spec[0] = '!'
	final.Receipts[0].Note = "rewritten"
	if !reflect.DeepEqual(initial.Terms, viewStore(t, f.store, id).Terms) {
		t.Fatal("view aliases storage")
	}
	data, err := os.ReadFile(f.store.path(id))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("private test artifact")) || bytes.Contains(data, []byte("checked artifact")) {
		t.Fatal("plaintext persisted")
	}
}

func TestStoreRetryAuthenticationAndIDConflict(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	op, sig := f.prepare(t, "request-1", "lock")
	result, err := f.store.Apply(id, op, sig, f.now)
	if err != nil {
		t.Fatal(err)
	}
	before := viewStore(t, f.store, id)
	if _, err = f.store.Apply(id, op, make([]byte, len(sig)), f.now); err == nil {
		t.Fatal("cached result bypassed authentication")
	}
	changed := op
	changed.Command.Evidence = "different"
	if _, err = f.store.Apply(id, changed, Sign(f.buyer, "operation", changed), f.now); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("ID reuse: %v", err)
	}
	// A fresh ID does not turn a stale command into a retry.
	fresh := op
	fresh.ID = "different-request"
	if _, err = f.store.Apply(id, fresh, Sign(f.buyer, "operation", fresh), f.now); err == nil {
		t.Fatal("stale new operation accepted")
	}
	again, err := f.store.Apply(id, op, sig, f.now)
	if err != nil || again != result || !reflect.DeepEqual(before, viewStore(t, f.store, id)) {
		t.Fatal("refusals changed state")
	}
}

func TestStoreFailedCommandsDoNotConsumeID(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	op, sig := f.prepare(t, "retry-time", "lock")
	before := viewStore(t, f.store, id)
	if _, err := f.store.Apply(id, op, sig, f.now.Add(-time.Minute)); err == nil {
		t.Fatal("early command accepted")
	}
	if !reflect.DeepEqual(before, viewStore(t, f.reopen(t), id)) {
		t.Fatal("failed command persisted")
	}
	if _, err := f.store.Apply(id, op, sig, f.now); err != nil {
		t.Fatal("ID consumed", err)
	}
}

func TestStoreWriteFailuresAreAtomic(t *testing.T) {
	for _, stage := range []string{"after-write", "before-rename", "after-rename", "after-sync"} {
		t.Run(stage, func(t *testing.T) {
			f := newStoreFixture(t)
			id := f.contract.ID()
			op, sig := f.prepare(t, "retry-io", "lock")
			before := viewStore(t, f.store, id)
			f.store.commitHook = func(at string) error {
				if at == stage {
					return errors.New("injected I/O failure")
				}
				return nil
			}
			_, err := f.store.Apply(id, op, sig, f.now)
			if err == nil {
				t.Fatal("write failure hidden")
			}
			uncertain := stage == "after-rename" || stage == "after-sync"
			if errors.Is(err, ErrCommitUncertain) != uncertain {
				t.Fatalf("wrong commit outcome: %v", err)
			}
			reopened := f.reopen(t)
			recovered := viewStore(t, reopened, id)
			if uncertain {
				if recovered.Status != StatusLocked || len(recovered.Receipts) != 3 {
					t.Fatal("committed state missing")
				}
			} else if !reflect.DeepEqual(before, recovered) {
				t.Fatal("uncommitted state leaked")
			}
			result, err := reopened.Apply(id, op, sig, f.now)
			if err != nil || result.Status != StatusLocked {
				t.Fatal(result, err)
			}
			if got := viewStore(t, reopened, id); len(got.Receipts) != 3 {
				t.Fatal("duplicate lock", got)
			}
		})
	}
}

func TestStoreConcurrentHandles(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	op, sig := f.prepare(t, "same-request", "lock")
	var wg sync.WaitGroup
	results := make(chan Result, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		s := f.reopen(t)
		wg.Add(1)
		go func() { defer wg.Done(); r, e := s.Apply(id, op, sig, f.now); results <- r; errs <- e }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var expected Result
	for r := range results {
		if expected.Head == "" {
			expected = r
		}
		if r != expected {
			t.Fatal("retry result diverged")
		}
	}
	if len(viewStore(t, f.store, id).Receipts) != 3 {
		t.Fatal("concurrent duplicate execution")
	}
}

func TestStoreRejectsCorruptionWrongKeysAndVersions(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	original, err := os.ReadFile(f.store.path(id))
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), f.key...)
	wrong[0] ^= 1
	s, err := OpenStore(f.dir, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.View(id); !errors.Is(err, ErrCorruptStore) {
		t.Fatalf("wrong key: %v", err)
	}
	for _, data := range [][]byte{original[:20], append([]byte(nil), original...)} {
		if len(data) == len(original) {
			data[len(data)-1] ^= 1
		}
		if err = os.WriteFile(f.store.path(id), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.View(id); !errors.Is(err, ErrCorruptStore) {
			t.Fatalf("corruption: %v", err)
		}
	}
	if err = os.WriteFile(f.store.path(id), original, 0600); err != nil {
		t.Fatal(err)
	}
	record, _, err := f.store.read(id)
	if err != nil {
		t.Fatal(err)
	}
	record.Version = 99
	if err = f.store.write(id, record); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.View(id); !errors.Is(err, ErrStoreVersion) {
		t.Fatalf("future version: %v", err)
	}
}

type processRequest struct {
	Dir        string
	Key        []byte
	ContractID string
	Operation  Operation
	Signature  []byte
	Now        time.Time
	Stage      string
}

// Invoked in a separate OS process. os.Exit bypasses defers at a real write
// boundary, leaving the same files as abrupt process termination.
func TestStoreProcessHelper(t *testing.T) {
	path := os.Getenv("NEX_STORE_PROCESS_REQUEST")
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var request processRequest
	if err = json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(request.Dir, request.Key)
	if err != nil {
		t.Fatal(err)
	}
	s.commitHook = func(stage string) error {
		if stage == request.Stage {
			os.Exit(77)
		}
		return nil
	}
	result, err := s.Apply(request.ContractID, request.Operation, request.Signature, request.Now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".result", encoded, 0600); err != nil {
		t.Fatal(err)
	}
}

func runStoreProcess(t *testing.T, request processRequest) (*exec.Cmd, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "request.json")
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreProcessHelper$")
	cmd.Env = append(os.Environ(), "NEX_STORE_PROCESS_REQUEST="+path)
	return cmd, path
}

func TestStoreProcessCrashRecovery(t *testing.T) {
	for _, stage := range []string{"before-rename", "after-rename", "after-sync"} {
		t.Run(stage, func(t *testing.T) {
			f := newStoreFixture(t)
			id := f.contract.ID()
			op, sig := f.prepare(t, "crash-request", "lock")
			request := processRequest{f.dir, f.key, id, op, sig, f.now, stage}
			cmd, _ := runStoreProcess(t, request)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 77 {
				t.Fatalf("helper did not reach crash boundary: %v", err)
			}
			// Retry in another process, so OS lock recovery and checkpoint parsing are exercised.
			request.Stage = ""
			cmd, path := runStoreProcess(t, request)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("restart: %v %s", err, output)
			}
			data, err := os.ReadFile(path + ".result")
			if err != nil {
				t.Fatal(err)
			}
			var result Result
			if err = json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			view := viewStore(t, f.reopen(t), id)
			if view.Status != StatusLocked || len(view.Receipts) != 3 || view.Head != result.Head {
				t.Fatalf("recovery: %+v", view)
			}
		})
	}
}

func TestStoreConcurrentProcesses(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	op, sig := f.prepare(t, "cross-process", "lock")
	request := processRequest{f.dir, f.key, id, op, sig, f.now, ""}
	var commands []*exec.Cmd
	var paths []string
	for i := 0; i < 3; i++ {
		cmd, path := runStoreProcess(t, request)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, cmd)
		paths = append(paths, path)
	}
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	var expected []byte
	for _, path := range paths {
		data, err := os.ReadFile(path + ".result")
		if err != nil {
			t.Fatal(err)
		}
		if expected == nil {
			expected = data
		}
		if !bytes.Equal(expected, data) {
			t.Fatal("process retry results diverged")
		}
	}
	if len(viewStore(t, f.store, id).Receipts) != 3 {
		t.Fatal("duplicate process lock")
	}
}

func TestStoreRestoresMeterAndAtomicSettlement(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	for _, action := range []string{"lock", "agree"} {
		op, sig := f.prepare(t, action, action)
		if _, err := f.store.Apply(id, op, sig, f.now); err != nil {
			t.Fatal(err)
		}
	}
	// A complete checkpoint must preserve consumed steps, not reset them to zero.
	record, _, err := f.store.read(id)
	if err != nil {
		t.Fatal(err)
	}
	record.Checkpoint.Agreement.Meter.MaxSteps = 5 // four consumed; settlement needs two
	if err = f.store.write(id, record); err != nil {
		t.Fatal(err)
	}
	f.store = f.reopen(t)
	before := viewStore(t, f.store, id)
	op, sig := f.prepare(t, "settlement", "settle")
	if _, err = f.store.Apply(id, op, sig, f.now); err == nil {
		t.Fatal("restored step bound bypassed")
	}
	if !reflect.DeepEqual(before, viewStore(t, f.reopen(t), id)) {
		t.Fatal("failed settlement changed receipts or consent")
	}
	record, _, err = f.store.read(id)
	if err != nil {
		t.Fatal(err)
	}
	record.Checkpoint.Agreement.Meter.MaxSteps = 6
	if err = f.store.write(id, record); err != nil {
		t.Fatal(err)
	}
	// Lose the process after the settlement was synced but before a response.
	cmd, _ := runStoreProcess(t, processRequest{f.dir, f.key, id, op, sig, f.now, "after-sync"})
	var exit *exec.ExitError
	if err = cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("crash: %v", err)
	}
	f.store = f.reopen(t)
	result, err := f.store.Apply(id, op, sig, f.now.Add(time.Hour*24))
	if err != nil || result.Status != StatusAccepted {
		t.Fatal(result, err)
	}
	after := viewStore(t, f.store, id)
	if len(after.Receipts) != 6 || !after.Agreed || after.Head != result.Head {
		t.Fatal("settlement lost or duplicated")
	}
}

func TestStoreTerminalRecovery(t *testing.T) {
	for _, action := range []string{"reject", "expire"} {
		t.Run(action, func(t *testing.T) {
			f := newStoreFixture(t)
			id := f.contract.ID()
			op, sig := f.prepare(t, "lock", "lock")
			if _, err := f.store.Apply(id, op, sig, f.now); err != nil {
				t.Fatal(err)
			}
			f.store = f.reopen(t)
			op, sig = f.prepare(t, "terminal", action)
			now := f.now
			expected := StatusRejected
			if action == "expire" {
				now = now.Add(time.Hour)
				expected = StatusExpired
			}
			first, err := f.store.Apply(id, op, sig, now)
			if err != nil {
				t.Fatal(err)
			}
			f.store = f.reopen(t)
			again, err := f.store.Apply(id, op, sig, now.Add(time.Hour))
			if err != nil || first != again || again.Status != expected {
				t.Fatal(again, err)
			}
			fresh, freshSig := f.prepare(t, "takeback", "lock")
			if _, err = f.store.Apply(id, fresh, freshSig, now); err == nil {
				t.Fatal("terminal state reopened")
			}
		})
	}
}

func TestStoreDifferentCommandsAgainstSameHead(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	op, sig := f.prepare(t, "lock", "lock")
	if _, err := f.store.Apply(id, op, sig, f.now); err != nil {
		t.Fatal(err)
	}
	agree, agreeSig := f.prepare(t, "agree", "agree")
	reject, rejectSig := f.prepare(t, "reject", "reject")
	start := make(chan struct{})
	errs := make(chan error, 2)
	for _, request := range []struct {
		op  Operation
		sig []byte
	}{{agree, agreeSig}, {reject, rejectSig}} {
		s := f.reopen(t)
		go func(op Operation, sig []byte) { <-start; _, err := s.Apply(id, op, sig, f.now); errs <- err }(request.op, request.sig)
	}
	close(start)
	successes := 0
	for i := 0; i < 2; i++ {
		if <-errs == nil {
			successes++
		}
	}
	if successes != 1 || len(viewStore(t, f.store, id).Receipts) != 4 {
		t.Fatal("concurrent conflicting commands committed")
	}
}

func TestStoreBindsCheckpointToContractID(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	other := Hash("other contract")
	data, err := os.ReadFile(f.store.path(id))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.store.path(other), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.View(other); !errors.Is(err, ErrCorruptStore) {
		t.Fatal("checkpoint relocation accepted", err)
	}
}

func TestContractDefinitionCompatibilityAndOwnership(t *testing.T) {
	f := newStoreFixture(t)
	original := Hash(struct {
		Kind              string
		Buyer, Seller     string
		Amount            int64
		Spec              any
		Created, Deadline time.Time
	}{"work.bounty", f.contract.buyer.ID(), f.contract.seller.ID(), 10, map[string]string{"task": "private test artifact"}, f.now, f.now.Add(time.Hour)})
	if f.contract.ID() != original {
		t.Fatal("immutable terms encoding changed")
	}
	bp, err := f.buyer.Public()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := f.seller.Public()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = New("test", bp, sp, 10, make(chan int), f.now, f.now.Add(time.Hour)); err == nil {
		t.Fatal("invalid spec accepted")
	}
	c, err := New("test", bp, sp, 10, nil, f.now, f.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	bp.Signing[0] ^= 1
	sp.Encryption[0] ^= 1
	if err = c.Execute(f.buyer, "lock", "", f.now); err != nil {
		t.Fatal("constructor retained mutable key slice", err)
	}
}

func TestStoreRejectsInvalidTextBeforeCommit(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	op, sig := f.prepare(t, "valid", "lock")
	_ = sig
	before := viewStore(t, f.store, id)
	badID := op
	badID.ID = string([]byte{0xff})
	badEvidence := op
	badEvidence.Command.Evidence = string([]byte{0xff})
	for _, bad := range []Operation{badID, badEvidence} {
		if _, err := f.store.Apply(id, bad, Sign(f.buyer, "operation", bad), f.now); err == nil {
			t.Fatal("invalid UTF-8 persisted")
		}
	}
	if !reflect.DeepEqual(before, viewStore(t, f.reopen(t), id)) {
		t.Fatal("invalid text changed checkpoint")
	}
}

func TestStoreRejectsInconsistentAuthenticatedCheckpoint(t *testing.T) {
	f := newStoreFixture(t)
	id := f.contract.ID()
	op, sig := f.prepare(t, "lock", "lock")
	if _, err := f.store.Apply(id, op, sig, f.now); err != nil {
		t.Fatal(err)
	}
	record, _, err := f.store.read(id)
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*storedContract){
		"step meter": func(r *storedContract) { r.Checkpoint.Steps = 0 },
		"consent":    func(r *storedContract) { r.Agreed = true },
		"terms":      func(r *storedContract) { r.Terms.Amount++ },
		"key":        func(r *storedContract) { r.Checkpoint.Ledger.Key.Mu[0] ^= 1 },
		"blinder":    func(r *storedContract) { r.Checkpoint.Ledger.Randomness[0] = []byte{0} },
		"receipt":    func(r *storedContract) { r.Checkpoint.Agreement.Receipts[0].Hash = "wrong" },
		"outcome": func(r *storedContract) {
			entry := r.Operations["lock"]
			entry.Result.Status = StatusAccepted
			r.Operations["lock"] = entry
		},
		"missing operation": func(r *storedContract) { delete(r.Operations, "lock") },
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			var r storedContract
			if err := json.Unmarshal(original, &r); err != nil {
				t.Fatal(err)
			}
			corrupt(&r)
			if err := f.store.write(id, r); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.View(id); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("inconsistent checkpoint accepted: %v", err)
			}
		})
	}
}
