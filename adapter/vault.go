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
	"unicode/utf8"
)

const vaultHeader = "NEXADAPT1"
const maxRecord = 16 << 20

type vault struct {
	dir  string
	aead cipher.AEAD
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

func (v *vault) write(id string, record any) error {
	plain, err := json.Marshal(record)
	if err != nil {
		return err
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	data := append([]byte(vaultHeader), nonce...)
	data = v.aead.Seal(data, nonce, plain, []byte(vaultHeader+"/"+id))
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
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, v.path(id)); err != nil {
		return err
	}
	return syncDir(v.dir)
}

func (v *vault) read(id string, dest any) error {
	f, err := os.Open(v.path(id))
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
	plain, err := v.aead.Open(nil, data[len(vaultHeader):len(vaultHeader)+n], data[len(vaultHeader)+n:], []byte(vaultHeader+"/"+id))
	if err != nil {
		return ErrCorrupt
	}
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

func CopyPrivateDir(src, dst string) error {
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	dstAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dstAbs, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	entries, err := os.ReadDir(srcAbs)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".pending-") || strings.HasSuffix(name, ".lock") {
			continue
		}
		in, err := os.ReadFile(filepath.Join(srcAbs, name))
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(dstAbs, ".pending-")
		if err != nil {
			return err
		}
		if _, err = tmp.Write(in); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return err
		}
		if err = tmp.Sync(); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return err
		}
		if err = tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return err
		}
		if err = os.Chmod(tmp.Name(), 0600); err != nil {
			os.Remove(tmp.Name())
			return err
		}
		if err = os.Rename(tmp.Name(), filepath.Join(dstAbs, name)); err != nil {
			return err
		}
	}
	return syncDir(dstAbs)
}

func (v *vault) withLock(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(v.dir, "outbox.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = lockFile(f); err != nil {
		return err
	}
	return fn()
}
