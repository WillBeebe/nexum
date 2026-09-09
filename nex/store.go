package nex

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/WillBeebe/nexum/internal/nexum"
)

var (
	ErrNotFound          = errors.New("nex: contract not found")
	ErrExists            = errors.New("nex: contract already stored")
	ErrOperationConflict = errors.New("nex: operation ID already committed with different content")
	ErrCorruptStore      = errors.New("nex: invalid or unauthenticated contract checkpoint")
	ErrStoreVersion      = errors.New("nex: unsupported store version")
	// ErrCommitUncertain means replacement occurred but durability confirmation
	// failed. Retry the EXACT signed operation; do not invent a new operation ID.
	ErrCommitUncertain = errors.New("nex: commit outcome uncertain; retry the same signed operation")
)

const storeHeader = "NEXSTORE1"
const maxCheckpoint = 16 << 20

// Operation binds a caller-generated, stable ID to one complete command.
// Sign the whole Operation with Sign(identity, "operation", operation).
// Persist it and its signature in the sending application's outbox before send.
type Operation struct {
	ID      string
	Command Command
}

// Result is the original successful operation result, including its receipt head.
// A retry returns this result even when subsequent operations advanced the head.
type Result struct {
	ContractID, OperationID, Head string
	Status                        Status
}

// ContractState is a detached public view, without custody keys or blinding factors.
type ContractState struct {
	ID       string
	Terms    Terms
	Head     string
	Status   Status
	Agreed   bool
	Receipts []Receipt
}

type committedOperation struct {
	Operation Operation
	Signature []byte
	Result    Result
}

type storedContract struct {
	Version       int
	Terms         Terms
	Buyer, Seller Public
	Agreed        bool
	Checkpoint    nexum.PrivateCheckpoint
	Operations    map[string]committedOperation
}

// Store persists encrypted contract checkpoints on a local filesystem. Separate
// handles and processes serialize each contract through an OS file lock. It is
// not a distributed store; do not use network filesystems or delete lock files.
// Keep the 32-byte storage key in the application's key store, outside this directory.
// Losing it loses access. Restoring an old backup can roll back history.
type Store struct {
	dir  string
	aead cipher.AEAD
	// Tests inject crashes/failures at actual persistence boundaries.
	commitHook func(string) error
}

// OpenStore opens or creates one private directory (its parent must exist).
// The directory must be owned and controlled by the calling application.
func OpenStore(dir string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("nex: storage key must be 32 random bytes")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	err = os.Mkdir(absolute, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("nex: store directory must be private (0700), without a symlink")
	}
	// Persist directory creation before acknowledging any contracts within it.
	if err = syncDirectory(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{dir: absolute, aead: aead}, nil
}

// Create stores a newly constructed, unused Contract. It copies the definition
// and checkpoint; subsequent mutations of the in-memory Contract do not affect it.
// Use Contract.ID to address the stored contract. Existing IDs are never replaced.
func (s *Store) Create(c *Contract) error {
	if c == nil || c.agreement == nil || c.Status() != StatusOpen || c.agreed ||
		len(c.agreement.Receipts) != 2 || c.agreement.Sealed == nil {
		return errors.New("nex: Create requires a new, unused contract")
	}
	return s.withLock(c.ID(), func() error {
		if _, err := os.Lstat(s.path(c.ID())); err == nil {
			return ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		record := storedContract{Version: 1, Terms: c.definition, Buyer: c.buyer, Seller: c.seller, Checkpoint: c.agreement.PrivateCheckpoint(), Operations: map[string]committedOperation{}}
		if _, err := record.restore(c.ID()); err != nil {
			return err
		}
		return s.write(c.ID(), record)
	})
}

func (s *Store) View(id string) (ContractState, error) {
	var view ContractState
	err := s.withLock(id, func() error {
		record, c, err := s.read(id)
		if err != nil {
			return err
		}
		// Confirm durability when recovering a replacement whose writer exited
		// before its final directory sync, including uncertain creation.
		if err = syncDirectory(s.dir); err != nil {
			return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
		}
		view = ContractState{ID: id, Terms: record.Terms, Head: c.Head(), Status: c.Status(), Agreed: c.agreed, Receipts: c.agreement.Receipts}
		return nil
	})
	return view, err
}

// Prepare captures the current head. Keep the returned Operation unchanged for
// every retry; calling Prepare again after success constructs different content.
func (s *Store) Prepare(id, operationID, action, evidence string) (Operation, error) {
	if err := validateOperationID(operationID); err != nil {
		return Operation{}, err
	}
	view, err := s.View(id)
	if err != nil {
		return Operation{}, err
	}
	return Operation{operationID, Command{id, view.Head, action, evidence}}, nil
}

// Apply authenticates first, then checks the durable successful-operation index.
// Failed commands are not cached. Contract state and the success result become
// durable together before returning success. No network/external effect is run.
func (s *Store) Apply(id string, op Operation, signature []byte, now time.Time) (Result, error) {
	var result Result
	if err := validateOperationID(op.ID); err != nil {
		return result, err
	}
	if len(op.Command.Evidence) > 64<<10 || len(op.Command.Action) > 32 || !utf8.ValidString(op.Command.Evidence) || !utf8.ValidString(op.Command.Action) {
		return result, errors.New("nex: operation too large")
	}
	err := s.withLock(id, func() error {
		record, c, err := s.read(id)
		if err != nil {
			return err
		}
		if op.Command.Terms != id {
			return errors.New("nex: foreign operation")
		}
		if err = Verify(c.signer(op.Command.Action), "operation", op, signature); err != nil {
			return err
		}
		if prior, ok := record.Operations[op.ID]; ok {
			if prior.Operation != op {
				return ErrOperationConflict
			}
			// Also resolves a previous rename followed by an uncertain directory sync.
			if err = syncDirectory(s.dir); err != nil {
				return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
			}
			result = prior.Result
			return nil
		}
		if err = c.applyVerified(op.Command, signature, now); err != nil {
			return err
		}
		result = Result{id, op.ID, c.Head(), c.Status()}
		record.Agreed = c.agreed
		record.Checkpoint = c.agreement.PrivateCheckpoint()
		record.Operations[op.ID] = committedOperation{op, append([]byte(nil), signature...), result}
		return s.write(id, record)
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func validateOperationID(id string) error {
	if len(id) < 1 || len(id) > 128 || strings.TrimSpace(id) != id || !utf8.ValidString(id) {
		return errors.New("nex: operation ID must contain 1–128 UTF-8 bytes without surrounding whitespace")
	}
	return nil
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".nex") }

func (s *Store) withLock(id string, fn func() error) error {
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != id {
		return errors.New("nex: invalid contract ID")
	}
	f, err := os.OpenFile(filepath.Join(s.dir, id+".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close() // OS releases the lock on close and process death.
	if err = lockStoreFile(f); err != nil {
		return err
	}
	return fn()
}

func (s *Store) read(id string) (storedContract, *Contract, error) {
	var record storedContract
	f, err := os.Open(s.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return record, nil, ErrNotFound
	}
	if err != nil {
		return record, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCheckpoint+1))
	if err != nil {
		return record, nil, err
	}
	n := s.aead.NonceSize()
	if len(data) > maxCheckpoint || len(data) < len(storeHeader)+n+s.aead.Overhead() {
		return record, nil, ErrCorruptStore
	}
	if string(data[:len(storeHeader)]) != storeHeader {
		return record, nil, ErrStoreVersion
	}
	nonce := data[len(storeHeader) : len(storeHeader)+n]
	plain, err := s.aead.Open(nil, nonce, data[len(storeHeader)+n:], []byte(storeHeader+"/"+id))
	if err != nil {
		return record, nil, ErrCorruptStore
	}
	if err = json.Unmarshal(plain, &record); err != nil {
		return record, nil, ErrCorruptStore
	}
	if record.Version != 1 {
		return record, nil, ErrStoreVersion
	}
	c, err := record.restore(id)
	return record, c, err
}

func (r *storedContract) restore(id string) (*Contract, error) {
	if r.Version != 1 || r.Buyer.Validate() != nil || r.Seller.Validate() != nil || !json.Valid(r.Terms.Spec) ||
		Hash(r.Terms) != id || r.Terms.Buyer != r.Buyer.ID() || r.Terms.Seller != r.Seller.ID() || r.Operations == nil {
		return nil, ErrCorruptStore
	}
	a, err := nexum.RestorePrivate(r.Checkpoint)
	if err != nil {
		return nil, ErrCorruptStore
	}
	if a.ID != id || a.Kind != r.Terms.Kind || string(a.Buyer) != r.Terms.Buyer || string(a.Seller) != r.Terms.Seller ||
		a.Amount != r.Terms.Amount || !a.CreatedAt.Equal(r.Terms.Created) || !a.Deadline.Equal(r.Terms.Deadline) || a.Sealed == nil {
		return nil, ErrCorruptStore
	}
	c := &Contract{agreement: a, terms: id, buyer: r.Buyer, seller: r.Seller, agreed: r.Agreed, definition: r.Terms}
	// Every committed operation must account for exactly its contiguous receipts.
	// This checks the success index and consent/state against the checkpoint,
	// rather than trusting a deserialized flag or cached result independently.
	byHead := make(map[string]committedOperation, len(r.Operations))
	for key, entry := range r.Operations {
		if validateOperationID(key) != nil || entry.Operation.ID != key || entry.Operation.Command.Terms != id ||
			entry.Result.ContractID != id || entry.Result.OperationID != key ||
			Verify(c.signer(entry.Operation.Command.Action), "operation", entry.Operation, entry.Signature) != nil {
			return nil, ErrCorruptStore
		}
		if _, duplicate := byHead[entry.Operation.Command.Head]; duplicate {
			return nil, ErrCorruptStore
		}
		byHead[entry.Operation.Command.Head] = entry
	}
	if len(a.Receipts) < 2 || a.Receipts[0].Action != "open" || a.Receipts[1].Action != "deadline" {
		return nil, ErrCorruptStore
	}
	status, consent := StatusOpen, false
	used := 0
	for i := 2; i < len(a.Receipts); {
		entry, ok := byHead[a.Receipts[i-1].Hash]
		if !ok {
			return nil, ErrCorruptStore
		}
		receipt := a.Receipts[i]
		count := 1
		switch entry.Operation.Command.Action {
		case "lock":
			if status != StatusOpen || receipt.Action != "seal" || receipt.Actor != a.Buyer {
				return nil, ErrCorruptStore
			}
			status = StatusLocked
		case "agree":
			if status != StatusLocked || consent || receipt.Action != "evidence" || receipt.Actor != a.Seller ||
				receipt.Note != "signed-consent:"+Hash(entry.Signature) {
				return nil, ErrCorruptStore
			}
			consent = true
		case "settle":
			if status != StatusLocked || !consent || receipt.Action != "evidence" || receipt.Actor != a.Buyer ||
				receipt.Note != entry.Operation.Command.Evidence || i+1 >= len(a.Receipts) ||
				a.Receipts[i+1].Action != "accept" || a.Receipts[i+1].Actor != a.Seller {
				return nil, ErrCorruptStore
			}
			count = 2
			status = StatusAccepted
		case "reject":
			if status != StatusLocked || receipt.Action != "reject" || receipt.Actor != a.Seller {
				return nil, ErrCorruptStore
			}
			status = StatusRejected
		case "expire":
			if (status != StatusOpen && status != StatusLocked) || receipt.Action != "expire" || receipt.Actor != a.Buyer {
				return nil, ErrCorruptStore
			}
			status = StatusExpired
		default:
			return nil, ErrCorruptStore
		}
		if entry.Result.Head != a.Receipts[i+count-1].Hash || entry.Result.Status != status {
			return nil, ErrCorruptStore
		}
		used++
		i += count
	}
	if used != len(r.Operations) || status != a.Status || consent != r.Agreed {
		return nil, ErrCorruptStore
	}
	return c, nil
}

func (s *Store) hook(stage string) error {
	if s.commitHook != nil {
		return s.commitHook(stage)
	}
	return nil
}

func (s *Store) write(id string, record storedContract) error {
	plain, err := json.Marshal(record)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	data := append([]byte(storeHeader), nonce...)
	data = s.aead.Seal(data, nonce, plain, []byte(storeHeader+"/"+id))
	if len(data) > maxCheckpoint {
		return errors.New("nex: checkpoint size limit exceeded")
	}
	f, err := os.CreateTemp(s.dir, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = s.hook("after-write"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = s.hook("before-rename"); err != nil {
		return err
	}
	if err = os.Rename(name, s.path(id)); err != nil {
		return err
	}
	if err = s.hook("after-rename"); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	if err = syncDirectory(s.dir); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	if err = s.hook("after-sync"); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
