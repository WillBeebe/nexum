package adapter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

const vaultHeader = "NEXADAPT1"
const maxRecord = 16 << 20

type vault struct {
	dir  string
	aead cipher.AEAD
	// onWrite, when set, observes durability stages and can fail a write.
	// Production opens leave it nil. Effect tests use it to stop before
	// dispatch or before a confirmation record becomes durable.
	// Stages: "before-sync", "after-sync", "after-rename".
	onWrite func(stage string) error
}

func openVault(dir string, key []byte) (*vault, error) {
	if len(key) != 32 {
		return nil, ErrStorageKey
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
		return nil, ErrStorageDir
	}
	if err = syncDir(filepath.Dir(absolute)); err != nil {
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
	return &vault{dir: absolute, aead: aead}, nil
}

func (v *vault) path(id string) string { return filepath.Join(v.dir, id+".box") }

func (v *vault) namedPath(filename string) string { return filepath.Join(v.dir, filename) }

func recordID(tenant, operationID string) string {
	sum := sha256.Sum256([]byte(tenant + "\x00" + operationID))
	return hex.EncodeToString(sum[:])
}

func validateID(id string) error {
	if len(id) < 1 || len(id) > 128 || strings.TrimSpace(id) != id || !utf8.ValidString(id) || strings.ContainsAny(id, "/\\") {
		return ErrItem
	}
	return nil
}

func validateVaultFilename(filename string) error {
	if len(filename) < 1 || len(filename) > 200 || strings.TrimSpace(filename) != filename || !utf8.ValidString(filename) {
		return ErrItem
	}
	if filename == "." || filename == ".." || strings.ContainsAny(filename, "/\\") || strings.HasPrefix(filename, ".pending-") || strings.HasSuffix(filename, ".lock") {
		return ErrItem
	}
	return nil
}

func (v *vault) write(id string, record any) error {
	return v.writeNamed(id+".box", vaultHeader+"/"+id, record)
}

func (v *vault) writeNamed(filename, aad string, record any) error {
	if err := validateVaultFilename(filename); err != nil || aad == "" {
		return ErrItem
	}
	plain, err := json.Marshal(record)
	if err != nil {
		return err
	}
	defer clear(plain)
	nonce := make([]byte, v.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	data := append([]byte(vaultHeader), nonce...)
	data = v.aead.Seal(data, nonce, plain, []byte(aad))
	if len(data) > maxRecord {
		return errors.New("adapter: record too large")
	}
	f, err := os.CreateTemp(v.dir, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	// Every stage is checked. A failure before rename leaves the previous
	// record in place. A failure after rename means durability is uncertain;
	// callers must not treat the write as success.
	if err = v.stage("before-sync"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = v.stage("after-sync"); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, v.namedPath(filename)); err != nil {
		return err
	}
	if err = v.stage("after-rename"); err != nil {
		return err
	}
	return syncDir(v.dir)
}

func (v *vault) stage(name string) error {
	if v.onWrite == nil {
		return nil
	}
	return v.onWrite(name)
}

func (v *vault) read(id string, dest any) error {
	return v.readNamed(id+".box", vaultHeader+"/"+id, dest)
}

func (v *vault) readNamed(filename, aad string, dest any) error {
	if err := validateVaultFilename(filename); err != nil || aad == "" {
		return ErrItem
	}
	f, err := os.Open(v.namedPath(filename))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return err
	}
	n := v.aead.NonceSize()
	if len(data) > maxRecord || len(data) < len(vaultHeader)+n+v.aead.Overhead() {
		return ErrCorrupt
	}
	if string(data[:len(vaultHeader)]) != vaultHeader {
		return ErrVersion
	}
	plain, err := v.aead.Open(nil, data[len(vaultHeader):len(vaultHeader)+n], data[len(vaultHeader)+n:], []byte(aad))
	if err != nil {
		return ErrCorrupt
	}
	defer clear(plain)
	if json.Unmarshal(plain, dest) != nil {
		return ErrCorrupt
	}
	return nil
}

func (v *vault) listIDs() ([]string, error) {
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".box") {
			continue
		}
		ids = append(ids, strings.TrimSuffix(name, ".box"))
	}
	return ids, nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// CopyPrivateDir copies one flat directory of regular files.
// It rejects symlinks, nested directories, leftover partial files, and a
// destination that is group- or world-accessible. Lock files are not part of
// the copied state. A successful return is a verified file manifest, not a
// checkpoint and not a fence: activation still has to observe the recorded head.
// HandoffPrivateDir additionally requires a drained coordinator before the copy.
func CopyPrivateDir(src, dst string) error {
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	if srcAbs == dstAbs {
		return ErrStorageDir
	}
	srcInfo, err := os.Lstat(srcAbs)
	if err != nil {
		return err
	}
	if err = requirePrivateDir(srcInfo); err != nil {
		return err
	}
	created := false
	dstInfo, err := os.Lstat(dstAbs)
	if err == nil {
		if err = requirePrivateDir(dstInfo); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		if err = os.Mkdir(dstAbs, 0700); err != nil {
			return err
		}
		created = true
		dstInfo, err = os.Lstat(dstAbs)
		if err != nil {
			return err
		}
		if err = requirePrivateDir(dstInfo); err != nil {
			os.Remove(dstAbs)
			return err
		}
	}
	entries, err := os.ReadDir(srcAbs)
	if err != nil {
		if created {
			os.Remove(dstAbs)
		}
		return err
	}
	var names []string
	want := map[string][32]byte{}
	fail := func(cause error) error {
		cleanupCopy(dstAbs, created, names)
		return cause
	}
	for _, e := range entries {
		name := e.Name()
		if e.Type()&os.ModeSymlink != 0 {
			return fail(ErrStorageDir)
		}
		if strings.HasSuffix(name, ".lock") {
			continue
		}
		// A subdirectory or a temp file means this tree is not a finished flat copy.
		if strings.HasPrefix(name, ".pending-") || e.IsDir() || !e.Type().IsRegular() {
			return fail(ErrStorageDir)
		}
		in, err := os.ReadFile(filepath.Join(srcAbs, name))
		if err != nil {
			return fail(err)
		}
		if err = writePrivateFile(dstAbs, name, in); err != nil {
			return fail(err)
		}
		names = append(names, name)
		want[name] = sha256.Sum256(in)
	}
	if err = verifyPrivateCopy(dstAbs, want); err != nil {
		return fail(err)
	}
	if err = syncDir(dstAbs); err != nil {
		return fail(err)
	}
	return nil
}

func requirePrivateDir(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return ErrStorageDir
	}
	return nil
}

func writePrivateFile(dir, name string, in []byte) error {
	tmp, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err = tmp.Write(in); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err = tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err = os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err = os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func verifyPrivateCopy(dst string, want map[string][32]byte) error {
	entries, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".lock") {
			continue
		}
		if strings.HasPrefix(name, ".pending-") || e.Type()&os.ModeSymlink != 0 || !e.Type().IsRegular() {
			return ErrStorageDir
		}
		sum, ok := want[name]
		if !ok {
			return ErrStorageDir
		}
		in, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			return err
		}
		if sha256.Sum256(in) != sum {
			return ErrStorageDir
		}
		info, err := os.Lstat(filepath.Join(dst, name))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return ErrStorageDir
		}
		seen[name] = true
	}
	if len(seen) != len(want) {
		return ErrStorageDir
	}
	return nil
}

func cleanupCopy(dst string, created bool, names []string) {
	for _, name := range names {
		os.Remove(filepath.Join(dst, name))
	}
	if created {
		os.Remove(dst)
	}
}

// directoryMu serializes handles in this process. macOS advisory locks are
// per process, so a second flock in the same process does not exclude another
// goroutine. The file lock still excludes other processes.
var directoryMu sync.Mutex
var directoryLocks = map[string]*sync.Mutex{}

func lockFor(dir string) *sync.Mutex {
	directoryMu.Lock()
	defer directoryMu.Unlock()
	mu, ok := directoryLocks[dir]
	if !ok {
		mu = &sync.Mutex{}
		directoryLocks[dir] = mu
	}
	return mu
}

func (v *vault) withLock(fn func() error) error {
	return v.withNamedLock("outbox.lock", fn)
}

func (v *vault) withNamedLock(lockName string, fn func() error) error {
	lockPath := filepath.Join(v.dir, lockName)
	mu := lockFor(lockPath)
	mu.Lock()
	defer mu.Unlock()
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = lockFile(f); err != nil {
		return err
	}
	return fn()
}
