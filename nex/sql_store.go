package nex

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// SQLDialect identifies the SQL engine backing an encrypted checkpoint store.
type SQLDialect string

const (
	SQLDialectPostgres SQLDialect = "postgres"
	SQLDialectSQLite   SQLDialect = "sqlite"
)

var pgSchemaInitLockKey = func() int64 {
	sum := sha256.Sum256([]byte(storeHeader + "/sql/schema-init"))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}()

func pgAdvisoryLockKey(namespace, id string) int64 {
	sum := sha256.Sum256([]byte(storeHeader + "/sql/lock/" + namespace + "/" + id))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

func validateSQLDialect(dialect SQLDialect) error {
	switch dialect {
	case SQLDialectPostgres, SQLDialectSQLite:
		return nil
	default:
		return fmt.Errorf("nex: unsupported SQL dialect %q", dialect)
	}
}

func validateSQLNamespace(namespace string) error {
	if len(namespace) == 0 || len(namespace) > 128 || !utf8.ValidString(namespace) || strings.TrimSpace(namespace) != namespace {
		return errors.New("nex: SQL namespace must be 1-128 valid UTF-8 bytes without surrounding whitespace, '/', or control characters")
	}
	for _, r := range namespace {
		if r == '/' || unicode.IsControl(r) {
			return errors.New("nex: SQL namespace must be 1-128 valid UTF-8 bytes without surrounding whitespace, '/', or control characters")
		}
	}
	return nil
}

// OpenSQLStore opens an AES-256-GCM authenticated contract checkpoint store
// backed by a database/sql handle. Checkpoints are encrypted before leaving the
// process with AAD bound to both namespace and record ID. Use distinct
// namespaces when sharing one database across store types or tenants.
func OpenSQLStore(ctx context.Context, db *sql.DB, dialect SQLDialect, namespace string, key []byte) (*Store, error) {
	if ctx == nil {
		return nil, errors.New("nex: context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, errors.New("nex: SQL database handle is required")
	}
	if err := validateSQLDialect(dialect); err != nil {
		return nil, err
	}
	if err := validateSQLNamespace(namespace); err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("nex: storage key must be 32 random bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := initSQLSchema(ctx, db, dialect, namespace); err != nil {
		return nil, err
	}
	st := &Store{aead: aead}
	st.backend = &sqlCheckpointBackend{
		db:        db,
		dialect:   dialect,
		namespace: namespace,
		store:     st,
	}
	return st, nil
}

// OpenSQLProtocolStore opens an encrypted SQL-backed ProtocolStore. Use a
// namespace distinct from Contract, Goal, Coordination, and Accord stores.
func OpenSQLProtocolStore(ctx context.Context, db *sql.DB, dialect SQLDialect, namespace string, key []byte) (*ProtocolStore, error) {
	s, err := OpenSQLStore(ctx, db, dialect, namespace, key)
	if err != nil {
		return nil, err
	}
	return &ProtocolStore{store: s, cache: make(map[string]cachedProtocol)}, nil
}

// OpenSQLGoalStore opens an encrypted SQL-backed GoalStore. Use a namespace
// distinct from Contract, Protocol, Coordination, and Accord stores.
func OpenSQLGoalStore(ctx context.Context, db *sql.DB, dialect SQLDialect, namespace string, key []byte) (*GoalStore, error) {
	s, err := OpenSQLStore(ctx, db, dialect, namespace, key)
	if err != nil {
		return nil, err
	}
	return &GoalStore{store: s}, nil
}

// OpenSQLCoordinationStore opens an encrypted SQL-backed CoordinationStore.
// Use a namespace distinct from goals, attempts, and other stores.
func OpenSQLCoordinationStore(ctx context.Context, db *sql.DB, dialect SQLDialect, namespace string, key []byte, goals *GoalStore, attempts *ProtocolStore) (*CoordinationStore, error) {
	if goals == nil || attempts == nil {
		return nil, ErrTaskResult
	}
	s, err := OpenSQLStore(ctx, db, dialect, namespace, key)
	if err != nil {
		return nil, err
	}
	return &CoordinationStore{store: s, goals: goals, attempts: attempts, cache: make(map[string]cachedTaskCheckpoint)}, nil
}

// OpenSQLAccordStore opens an encrypted SQL-backed AccordStore. Use a namespace
// distinct from Contract, Protocol, Goal, and Coordination stores.
func OpenSQLAccordStore(ctx context.Context, db *sql.DB, dialect SQLDialect, namespace string, key []byte) (*AccordStore, error) {
	s, err := OpenSQLStore(ctx, db, dialect, namespace, key)
	if err != nil {
		return nil, err
	}
	return &AccordStore{store: s, cache: make(map[string]cachedAccord)}, nil
}

func initSQLSchema(ctx context.Context, db *sql.DB, dialect SQLDialect, namespace string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	switch dialect {
	case SQLDialectPostgres:
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", pgSchemaInitLockKey); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS nex_checkpoints (
			namespace TEXT NOT NULL,
			id TEXT NOT NULL,
			version BIGINT NOT NULL,
			payload BYTEA NOT NULL,
			PRIMARY KEY (namespace, id)
		)`); err != nil {
			return err
		}
	case SQLDialectSQLite:
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS nex_checkpoints (
			namespace TEXT NOT NULL,
			id TEXT NOT NULL,
			version BIGINT NOT NULL,
			payload BLOB NOT NULL,
			PRIMARY KEY (namespace, id)
		)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS nex_checkpoint_locks (
			namespace TEXT PRIMARY KEY,
			version BIGINT NOT NULL
		)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO nex_checkpoint_locks (namespace, version) VALUES (?, 0) ON CONFLICT(namespace) DO NOTHING`, namespace); err != nil {
			return err
		}
	default:
		return validateSQLDialect(dialect)
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

type sqlCheckpointBackend struct {
	db        *sql.DB
	dialect   SQLDialect
	namespace string
	store     *Store
	mu        sync.Mutex
}

func (b *sqlCheckpointBackend) aad(id string) []byte {
	return []byte(storeHeader + "/sql/" + b.namespace + "/" + id)
}

func (b *sqlCheckpointBackend) syncDir() error {
	return nil
}

func (b *sqlCheckpointBackend) directTx() checkpointTx {
	return &sqlDirectTx{backend: b}
}

func (b *sqlCheckpointBackend) withLock(id string, fn func(checkpointTx) error) error {
	ctx := context.Background()
	waitStart := time.Now()
	if b.dialect == SQLDialectSQLite {
		b.mu.Lock()
		defer b.mu.Unlock()
	}

	sqlTx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = sqlTx.Rollback()
		}
	}()

	switch b.dialect {
	case SQLDialectPostgres:
		if _, err := sqlTx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", pgAdvisoryLockKey(b.namespace, id)); err != nil {
			return err
		}
	case SQLDialectSQLite:
		res, err := sqlTx.ExecContext(ctx, "UPDATE nex_checkpoint_locks SET version = version + 1 WHERE namespace = ?", b.namespace)
		if err != nil {
			return err
		}
		if rows, err := res.RowsAffected(); err == nil && rows == 0 {
			return errors.New("nex: SQLite checkpoint lock row missing for namespace")
		}
	default:
		return validateSQLDialect(b.dialect)
	}

	b.store.lockWaitNanos.Add(time.Since(waitStart).Nanoseconds())
	b.store.lockAcquisitions.Add(1)

	stx := &sqlCheckpointTx{backend: b, tx: sqlTx}
	if err := fn(stx); err != nil {
		return err
	}
	if err := sqlTx.Commit(); err != nil {
		if stx.wrote {
			return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
		}
		return err
	}
	committed = true
	return nil
}

type sqlQueryExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type sqlCheckpointTx struct {
	backend *sqlCheckpointBackend
	tx      *sql.Tx
	parent  *sqlCheckpointTx
	wrote   bool
}

func (tx *sqlCheckpointTx) exists(id string) (bool, error) {
	return sqlExists(tx.backend, tx.tx, id)
}

func (tx *sqlCheckpointTx) stat(id string) (checkpointMeta, error) {
	return sqlStat(tx.backend, tx.tx, id)
}

func (tx *sqlCheckpointTx) readRaw(id string) ([]byte, checkpointMeta, error) {
	return sqlReadRaw(tx.backend, tx.tx, id)
}

func (tx *sqlCheckpointTx) writeRaw(id string, data []byte) error {
	if err := sqlWriteRaw(tx.backend, tx.tx, id, data); err != nil {
		return err
	}
	tx.wrote = true
	if tx.parent != nil {
		tx.parent.wrote = true
	}
	return nil
}

type sqlDirectTx struct {
	backend *sqlCheckpointBackend
}

func (tx *sqlDirectTx) exists(id string) (bool, error) {
	return sqlExists(tx.backend, tx.backend.db, id)
}

func (tx *sqlDirectTx) stat(id string) (checkpointMeta, error) {
	return sqlStat(tx.backend, tx.backend.db, id)
}

func (tx *sqlDirectTx) readRaw(id string) ([]byte, checkpointMeta, error) {
	return sqlReadRaw(tx.backend, tx.backend.db, id)
}

func (tx *sqlDirectTx) writeRaw(id string, data []byte) error {
	return sqlWriteRaw(tx.backend, tx.backend.db, id, data)
}

func sqlExists(b *sqlCheckpointBackend, exec sqlQueryExecutor, id string) (bool, error) {
	var query string
	switch b.dialect {
	case SQLDialectPostgres:
		query = "SELECT 1 FROM nex_checkpoints WHERE namespace = $1 AND id = $2"
	case SQLDialectSQLite:
		query = "SELECT 1 FROM nex_checkpoints WHERE namespace = ? AND id = ?"
	default:
		return false, validateSQLDialect(b.dialect)
	}
	var one int
	err := exec.QueryRowContext(context.Background(), query, b.namespace, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func sqlStat(b *sqlCheckpointBackend, exec sqlQueryExecutor, id string) (checkpointMeta, error) {
	var query string
	switch b.dialect {
	case SQLDialectPostgres:
		query = "SELECT version FROM nex_checkpoints WHERE namespace = $1 AND id = $2"
	case SQLDialectSQLite:
		query = "SELECT version FROM nex_checkpoints WHERE namespace = ? AND id = ?"
	default:
		return checkpointMeta{}, validateSQLDialect(b.dialect)
	}
	var version int64
	err := exec.QueryRowContext(context.Background(), query, b.namespace, id).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return checkpointMeta{}, nil
	}
	if err != nil {
		return checkpointMeta{}, err
	}
	if version <= 0 {
		return checkpointMeta{}, ErrCorruptStore
	}
	return checkpointMeta{exists: true, version: version}, nil
}

func sqlReadRaw(b *sqlCheckpointBackend, exec sqlQueryExecutor, id string) ([]byte, checkpointMeta, error) {
	var query string
	switch b.dialect {
	case SQLDialectPostgres:
		query = "SELECT version, payload FROM nex_checkpoints WHERE namespace = $1 AND id = $2"
	case SQLDialectSQLite:
		query = "SELECT version, payload FROM nex_checkpoints WHERE namespace = ? AND id = ?"
	default:
		return nil, checkpointMeta{}, validateSQLDialect(b.dialect)
	}
	var version int64
	var payload []byte
	err := exec.QueryRowContext(context.Background(), query, b.namespace, id).Scan(&version, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, checkpointMeta{}, ErrNotFound
	}
	if err != nil {
		return nil, checkpointMeta{}, err
	}
	if version <= 0 {
		return nil, checkpointMeta{}, ErrCorruptStore
	}
	return bytes.Clone(payload), checkpointMeta{exists: true, version: version}, nil
}

func sqlWriteRaw(b *sqlCheckpointBackend, exec sqlQueryExecutor, id string, data []byte) error {
	var query string
	switch b.dialect {
	case SQLDialectPostgres:
		query = `INSERT INTO nex_checkpoints (namespace, id, version, payload)
			VALUES ($1, $2, 1, $3)
			ON CONFLICT (namespace, id) DO UPDATE
			SET version = nex_checkpoints.version + 1, payload = EXCLUDED.payload`
	case SQLDialectSQLite:
		query = `INSERT INTO nex_checkpoints (namespace, id, version, payload)
			VALUES (?, ?, 1, ?)
			ON CONFLICT (namespace, id) DO UPDATE
			SET version = nex_checkpoints.version + 1, payload = excluded.payload`
	default:
		return validateSQLDialect(b.dialect)
	}
	if _, err := exec.ExecContext(context.Background(), query, b.namespace, id, data); err != nil {
		return err
	}
	b.store.checkpointWrites.Add(1)
	return nil
}

// childSQLiteTx reuses an active SQLite write transaction when CoordinationStore
// invokes ProtocolStore on the exact same *sql.DB, avoiding SQLite single-writer
// deadlocks while preserving database-wide transactional serialization.
func childSQLiteTx(parentTx checkpointTx, target *Store) (*sqlCheckpointTx, bool) {
	if target == nil {
		return nil, false
	}
	parentSQL, ok := parentTx.(*sqlCheckpointTx)
	if !ok || parentSQL == nil || parentSQL.tx == nil || parentSQL.backend == nil {
		return nil, false
	}
	targetBackend, ok := target.backend.(*sqlCheckpointBackend)
	if !ok || targetBackend == nil {
		return nil, false
	}
	if parentSQL.backend.dialect != SQLDialectSQLite || targetBackend.dialect != SQLDialectSQLite {
		return nil, false
	}
	if parentSQL.backend.db != targetBackend.db {
		return nil, false
	}
	return &sqlCheckpointTx{backend: targetBackend, tx: parentSQL.tx, parent: parentSQL}, true
}
