package nex

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// In-process database/sql/driver implementing PostgreSQL & SQLite semantics
// with real blocking advisory/write locks, staged transactions, rollback, and
// strict invariant checks that every checkpoint query runs on the locked Tx.
// ---------------------------------------------------------------------------

const testSQLDriverName = "nex_test_sql_driver"

var (
	testSQLRegistryMu sync.Mutex
	testSQLRegistry   = make(map[string]*memSQLDB)
	testSQLSeq        atomic.Int64
)

func init() {
	sql.Register(testSQLDriverName, &memSQLDriver{})
}

type memRowKey struct {
	namespace string
	id        string
}

type memCheckpointRow struct {
	version int64
	payload []byte
}

type memSQLMetrics struct {
	schemaInitLocks  int64
	advisoryLocks    int64
	sqliteWriteLocks int64
	commits          int64
	rollbacks        int64
	nonTxQueries     int64
}

type memSQLDB struct {
	dsn     string
	dialect SQLDialect

	dataMu           sync.Mutex
	schemaCreated    bool
	lockTableCreated bool
	rows             map[memRowKey]memCheckpointRow
	locks            map[string]int64
	failNextWrite    error
	failNextCommit   error

	lockMu           sync.Mutex
	pgLocks          map[int64]chan struct{}
	pgLockOwner      map[int64]*memSQLTx
	sqliteWriteLock  chan struct{}
	sqliteWriteOwner *memSQLTx

	schemaInitLocks  atomic.Int64
	advisoryLocks    atomic.Int64
	sqliteWriteLocks atomic.Int64
	commits          atomic.Int64
	rollbacks        atomic.Int64
	nonTxQueries     atomic.Int64
}

func newTestSQLDB(t *testing.T, dialect SQLDialect) (*sql.DB, *memSQLDB) {
	t.Helper()
	dsn := fmt.Sprintf("%s-%d", dialect, testSQLSeq.Add(1))
	backing := &memSQLDB{
		dsn:         dsn,
		dialect:     dialect,
		rows:        make(map[memRowKey]memCheckpointRow),
		locks:       make(map[string]int64),
		pgLocks:     make(map[int64]chan struct{}),
		pgLockOwner: make(map[int64]*memSQLTx),
	}
	testSQLRegistryMu.Lock()
	testSQLRegistry[dsn] = backing
	testSQLRegistryMu.Unlock()

	db, err := sql.Open(testSQLDriverName, dsn)
	if err != nil {
		t.Fatalf("sql.Open(%s): %v", dialect, err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		testSQLRegistryMu.Lock()
		delete(testSQLRegistry, dsn)
		testSQLRegistryMu.Unlock()
	})
	return db, backing
}

func openPeerSQLDB(t *testing.T, backing *memSQLDB) *sql.DB {
	t.Helper()
	db, err := sql.Open(testSQLDriverName, backing.dsn)
	if err != nil {
		t.Fatalf("sql.Open peer(%s): %v", backing.dialect, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (m *memSQLDB) rawRow(namespace, id string) (int64, []byte, bool) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	r, ok := m.rows[memRowKey{namespace: namespace, id: id}]
	if !ok {
		return 0, nil, false
	}
	return r.version, bytes.Clone(r.payload), true
}

func (m *memSQLDB) setRawRow(namespace, id string, version int64, payload []byte) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	m.rows[memRowKey{namespace: namespace, id: id}] = memCheckpointRow{
		version: version,
		payload: bytes.Clone(payload),
	}
}

func (m *memSQLDB) deleteLockRow(namespace string) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	delete(m.locks, namespace)
}

func (m *memSQLDB) setFailNextWrite(err error) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	m.failNextWrite = err
}

func (m *memSQLDB) setFailNextCommit(err error) {
	m.dataMu.Lock()
	defer m.dataMu.Unlock()
	m.failNextCommit = err
}

func (m *memSQLDB) metrics() memSQLMetrics {
	return memSQLMetrics{
		schemaInitLocks:  m.schemaInitLocks.Load(),
		advisoryLocks:    m.advisoryLocks.Load(),
		sqliteWriteLocks: m.sqliteWriteLocks.Load(),
		commits:          m.commits.Load(),
		rollbacks:        m.rollbacks.Load(),
		nonTxQueries:     m.nonTxQueries.Load(),
	}
}

func (m *memSQLDB) acquirePGAdvisoryLock(ctx context.Context, tx *memSQLTx, key int64) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.lockMu.Lock()
		waitCh, held := m.pgLocks[key]
		if !held {
			ch := make(chan struct{})
			m.pgLocks[key] = ch
			m.pgLockOwner[key] = tx
			tx.pgLocks[key] = ch
			m.lockMu.Unlock()
			m.advisoryLocks.Add(1)
			if key == pgSchemaInitLockKey {
				m.schemaInitLocks.Add(1)
			}
			return nil
		}
		if m.pgLockOwner[key] == tx {
			m.lockMu.Unlock()
			return nil
		}
		m.lockMu.Unlock()
		select {
		case <-waitCh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *memSQLDB) acquireSQLiteWriteLock(ctx context.Context, tx *memSQLTx) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.lockMu.Lock()
		if m.sqliteWriteOwner == tx {
			m.lockMu.Unlock()
			return nil
		}
		if m.sqliteWriteLock == nil {
			ch := make(chan struct{})
			m.sqliteWriteLock = ch
			m.sqliteWriteOwner = tx
			tx.hasSQLiteWriteLock = true
			m.lockMu.Unlock()
			m.sqliteWriteLocks.Add(1)
			return nil
		}
		waitCh := m.sqliteWriteLock
		m.lockMu.Unlock()
		select {
		case <-waitCh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *memSQLDB) releaseTxLocks(tx *memSQLTx) {
	m.lockMu.Lock()
	defer m.lockMu.Unlock()
	for key, ch := range tx.pgLocks {
		if m.pgLockOwner[key] == tx {
			delete(m.pgLocks, key)
			delete(m.pgLockOwner, key)
			close(ch)
		}
	}
	tx.pgLocks = nil
	if tx.hasSQLiteWriteLock && m.sqliteWriteOwner == tx {
		ch := m.sqliteWriteLock
		m.sqliteWriteLock = nil
		m.sqliteWriteOwner = nil
		tx.hasSQLiteWriteLock = false
		close(ch)
	}
}

type memSQLDriver struct{}

func (d *memSQLDriver) Open(dsn string) (driver.Conn, error) {
	testSQLRegistryMu.Lock()
	backing := testSQLRegistry[dsn]
	testSQLRegistryMu.Unlock()
	if backing == nil {
		return nil, fmt.Errorf("nex_test_sql: unknown DSN %q", dsn)
	}
	return &memSQLConn{db: backing}, nil
}

type memSQLConn struct {
	db     *memSQLDB
	tx     *memSQLTx
	closed bool
}

func (c *memSQLConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("nex_test_sql: use ExecContext/QueryContext")
}

func (c *memSQLConn) Close() error {
	if c.tx != nil {
		_ = c.tx.Rollback()
	}
	c.closed = true
	return nil
}

func (c *memSQLConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *memSQLConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.tx != nil {
		return nil, errors.New("nex_test_sql: nested transaction on same connection")
	}
	tx := &memSQLTx{
		conn:        c,
		pgLocks:     make(map[int64]chan struct{}),
		stagedRows:  make(map[memRowKey]memCheckpointRow),
		stagedLocks: make(map[string]int64),
	}
	c.tx = tx
	return tx, nil
}

type memSQLTx struct {
	conn                   *memSQLConn
	pgLocks                map[int64]chan struct{}
	hasSQLiteWriteLock     bool
	stagedSchemaCreated    bool
	stagedLockTableCreated bool
	stagedRows             map[memRowKey]memCheckpointRow
	stagedLocks            map[string]int64
	done                   bool
}

func (tx *memSQLTx) Commit() error {
	if tx.done {
		return errors.New("nex_test_sql: tx already finished")
	}
	tx.done = true
	db := tx.conn.db
	defer func() {
		db.releaseTxLocks(tx)
		tx.conn.tx = nil
	}()

	db.dataMu.Lock()
	if db.failNextCommit != nil && len(tx.stagedRows) > 0 {
		err := db.failNextCommit
		db.failNextCommit = nil
		db.dataMu.Unlock()
		db.rollbacks.Add(1)
		return err
	}
	if tx.stagedSchemaCreated {
		db.schemaCreated = true
	}
	if tx.stagedLockTableCreated {
		db.lockTableCreated = true
	}
	for k, row := range tx.stagedRows {
		db.rows[k] = memCheckpointRow{version: row.version, payload: bytes.Clone(row.payload)}
	}
	for ns, ver := range tx.stagedLocks {
		db.locks[ns] = ver
	}
	db.dataMu.Unlock()
	db.commits.Add(1)
	return nil
}

func (tx *memSQLTx) Rollback() error {
	if tx.done {
		return nil
	}
	tx.done = true
	db := tx.conn.db
	db.releaseTxLocks(tx)
	tx.conn.tx = nil
	db.rollbacks.Add(1)
	return nil
}

func normalizeSQL(q string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(q)), " ")
}

func (c *memSQLConn) assertDialectPlaceholders(norm string) error {
	switch c.db.dialect {
	case SQLDialectPostgres:
		if strings.Contains(norm, "?") {
			return fmt.Errorf("nex_test_sql(postgres): unexpected '?' placeholder in %q", norm)
		}
	case SQLDialectSQLite:
		if strings.Contains(norm, "$1") || strings.Contains(norm, "$2") || strings.Contains(norm, "$3") {
			return fmt.Errorf("nex_test_sql(sqlite): unexpected '$N' placeholder in %q", norm)
		}
	}
	return nil
}

func (c *memSQLConn) assertLockedTxForRow(namespace, id string) error {
	if c.tx == nil {
		c.db.nonTxQueries.Add(1)
		return fmt.Errorf("nex_test_sql(%s): checkpoint query executed outside active transaction", c.db.dialect)
	}
	switch c.db.dialect {
	case SQLDialectPostgres:
		wantKey := pgAdvisoryLockKey(namespace, id)
		if _, ok := c.tx.pgLocks[wantKey]; !ok {
			return fmt.Errorf("nex_test_sql(postgres): checkpoint query missing pg_advisory_xact_lock for (%q, %q)", namespace, id)
		}
	case SQLDialectSQLite:
		if !c.tx.hasSQLiteWriteLock {
			return fmt.Errorf("nex_test_sql(sqlite): checkpoint query missing immediate write lock")
		}
	}
	return nil
}

func (c *memSQLConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	norm := normalizeSQL(query)
	if err := c.assertDialectPlaceholders(norm); err != nil {
		return nil, err
	}
	db := c.db

	// PostgreSQL advisory lock
	if strings.HasPrefix(norm, "SELECT pg_advisory_xact_lock(") {
		if db.dialect != SQLDialectPostgres {
			return nil, errors.New("nex_test_sql: pg_advisory_xact_lock only valid on postgres")
		}
		if c.tx == nil {
			db.nonTxQueries.Add(1)
			return nil, errors.New("nex_test_sql: pg_advisory_xact_lock requires an active tx")
		}
		if len(args) != 1 {
			return nil, errors.New("nex_test_sql: pg_advisory_xact_lock expects 1 arg")
		}
		key, ok := args[0].Value.(int64)
		if !ok {
			return nil, fmt.Errorf("nex_test_sql: pg_advisory_xact_lock arg type %T", args[0].Value)
		}
		if err := db.acquirePGAdvisoryLock(ctx, c.tx, key); err != nil {
			return nil, err
		}
		return driver.RowsAffected(0), nil
	}

	// CREATE TABLE nex_checkpoints
	if strings.HasPrefix(norm, "CREATE TABLE IF NOT EXISTS nex_checkpoints") {
		if c.tx == nil {
			db.nonTxQueries.Add(1)
			return nil, errors.New("nex_test_sql: DDL requires active tx")
		}
		switch db.dialect {
		case SQLDialectPostgres:
			if !strings.Contains(norm, "BYTEA") || strings.Contains(norm, "BLOB") {
				return nil, fmt.Errorf("nex_test_sql(postgres): expected BYTEA column in %q", norm)
			}
			if _, ok := c.tx.pgLocks[pgSchemaInitLockKey]; !ok {
				return nil, errors.New("nex_test_sql(postgres): schema init must hold pg_advisory_xact_lock")
			}
		case SQLDialectSQLite:
			if !strings.Contains(norm, "BLOB") || strings.Contains(norm, "BYTEA") {
				return nil, fmt.Errorf("nex_test_sql(sqlite): expected BLOB column in %q", norm)
			}
			if err := db.acquireSQLiteWriteLock(ctx, c.tx); err != nil {
				return nil, err
			}
		}
		c.tx.stagedSchemaCreated = true
		return driver.RowsAffected(0), nil
	}

	// CREATE TABLE nex_checkpoint_locks (SQLite only)
	if strings.HasPrefix(norm, "CREATE TABLE IF NOT EXISTS nex_checkpoint_locks") {
		if db.dialect != SQLDialectSQLite {
			return nil, errors.New("nex_test_sql: nex_checkpoint_locks is SQLite-only")
		}
		if c.tx == nil {
			db.nonTxQueries.Add(1)
			return nil, errors.New("nex_test_sql: DDL requires active tx")
		}
		if err := db.acquireSQLiteWriteLock(ctx, c.tx); err != nil {
			return nil, err
		}
		c.tx.stagedLockTableCreated = true
		return driver.RowsAffected(0), nil
	}

	// INSERT INTO nex_checkpoint_locks ... ON CONFLICT(namespace) DO NOTHING (SQLite only)
	if strings.HasPrefix(norm, "INSERT INTO nex_checkpoint_locks") {
		if db.dialect != SQLDialectSQLite {
			return nil, errors.New("nex_test_sql: nex_checkpoint_locks insert is SQLite-only")
		}
		if c.tx == nil || len(args) != 1 {
			return nil, errors.New("nex_test_sql: invalid lock row insert")
		}
		if err := db.acquireSQLiteWriteLock(ctx, c.tx); err != nil {
			return nil, err
		}
		ns, ok := args[0].Value.(string)
		if !ok {
			return nil, errors.New("nex_test_sql: namespace must be string")
		}
		db.dataMu.Lock()
		_, exists := db.locks[ns]
		db.dataMu.Unlock()
		if !exists {
			if _, staged := c.tx.stagedLocks[ns]; !staged {
				c.tx.stagedLocks[ns] = 0
				return driver.RowsAffected(1), nil
			}
		}
		return driver.RowsAffected(0), nil
	}

	// UPDATE nex_checkpoint_locks SET version = version + 1 WHERE namespace = ? (SQLite only)
	if strings.HasPrefix(norm, "UPDATE nex_checkpoint_locks SET version = version + 1 WHERE namespace = ?") {
		if db.dialect != SQLDialectSQLite {
			return nil, errors.New("nex_test_sql: nex_checkpoint_locks update is SQLite-only")
		}
		if c.tx == nil || len(args) != 1 {
			return nil, errors.New("nex_test_sql: SQLite write lock requires active tx and namespace arg")
		}
		ns, ok := args[0].Value.(string)
		if !ok {
			return nil, errors.New("nex_test_sql: namespace must be string")
		}
		if err := db.acquireSQLiteWriteLock(ctx, c.tx); err != nil {
			return nil, err
		}
		db.dataMu.Lock()
		cur, exists := db.locks[ns]
		db.dataMu.Unlock()
		if staged, ok := c.tx.stagedLocks[ns]; ok {
			cur, exists = staged, true
		}
		if !exists {
			return driver.RowsAffected(0), nil
		}
		c.tx.stagedLocks[ns] = cur + 1
		return driver.RowsAffected(1), nil
	}

	// UPSERT INTO nex_checkpoints
	if strings.HasPrefix(norm, "INSERT INTO nex_checkpoints") {
		if len(args) != 3 {
			return nil, errors.New("nex_test_sql: upsert expects 3 args")
		}
		ns, ok1 := args[0].Value.(string)
		id, ok2 := args[1].Value.(string)
		payload, ok3 := args[2].Value.([]byte)
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("nex_test_sql: invalid upsert arg types")
		}
		if err := c.assertLockedTxForRow(ns, id); err != nil {
			return nil, err
		}
		db.dataMu.Lock()
		if !db.schemaCreated && !c.tx.stagedSchemaCreated {
			db.dataMu.Unlock()
			return nil, errors.New("nex_test_sql: nex_checkpoints table does not exist")
		}
		if db.failNextWrite != nil {
			err := db.failNextWrite
			db.failNextWrite = nil
			db.dataMu.Unlock()
			return nil, err
		}
		key := memRowKey{namespace: ns, id: id}
		cur, exists := db.rows[key]
		db.dataMu.Unlock()
		if staged, ok := c.tx.stagedRows[key]; ok {
			cur, exists = staged, true
		}
		nextVer := int64(1)
		if exists {
			nextVer = cur.version + 1
		}
		c.tx.stagedRows[key] = memCheckpointRow{
			version: nextVer,
			payload: bytes.Clone(payload),
		}
		return driver.RowsAffected(1), nil
	}

	return nil, fmt.Errorf("nex_test_sql: unsupported Exec query %q", norm)
}

func (c *memSQLConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	norm := normalizeSQL(query)
	if err := c.assertDialectPlaceholders(norm); err != nil {
		return nil, err
	}
	if len(args) != 2 {
		return nil, fmt.Errorf("nex_test_sql: expected 2 query args for %q", norm)
	}
	ns, ok1 := args[0].Value.(string)
	id, ok2 := args[1].Value.(string)
	if !ok1 || !ok2 {
		return nil, errors.New("nex_test_sql: query args must be strings")
	}
	if err := c.assertLockedTxForRow(ns, id); err != nil {
		return nil, err
	}

	db := c.db
	key := memRowKey{namespace: ns, id: id}
	db.dataMu.Lock()
	if !db.schemaCreated && !c.tx.stagedSchemaCreated {
		db.dataMu.Unlock()
		return nil, errors.New("nex_test_sql: nex_checkpoints table does not exist")
	}
	row, exists := db.rows[key]
	db.dataMu.Unlock()
	if staged, ok := c.tx.stagedRows[key]; ok {
		row, exists = staged, true
	}

	switch {
	case strings.HasPrefix(norm, "SELECT 1 FROM nex_checkpoints WHERE"):
		if !exists {
			return &memSQLRows{cols: []string{"one"}}, nil
		}
		return &memSQLRows{cols: []string{"one"}, data: [][]driver.Value{{int64(1)}}}, nil
	case strings.HasPrefix(norm, "SELECT version FROM nex_checkpoints WHERE"):
		if !exists {
			return &memSQLRows{cols: []string{"version"}}, nil
		}
		return &memSQLRows{cols: []string{"version"}, data: [][]driver.Value{{row.version}}}, nil
	case strings.HasPrefix(norm, "SELECT version, payload FROM nex_checkpoints WHERE"):
		if !exists {
			return &memSQLRows{cols: []string{"version", "payload"}}, nil
		}
		return &memSQLRows{cols: []string{"version", "payload"}, data: [][]driver.Value{{row.version, bytes.Clone(row.payload)}}}, nil
	default:
		return nil, fmt.Errorf("nex_test_sql: unsupported Query %q", norm)
	}
}

type memSQLRows struct {
	cols []string
	data [][]driver.Value
	idx  int
}

func (r *memSQLRows) Columns() []string { return r.cols }
func (r *memSQLRows) Close() error      { return nil }
func (r *memSQLRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.idx])
	r.idx++
	return nil
}

func forEachSQLDialect(t *testing.T, fn func(t *testing.T, dialect SQLDialect)) {
	t.Helper()
	for _, dialect := range []SQLDialect{SQLDialectPostgres, SQLDialectSQLite} {
		t.Run(string(dialect), func(t *testing.T) {
			fn(t, dialect)
		})
	}
}

func randomTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// ---------------------------------------------------------------------------
// 1. Fail-closed constructor validation & concurrent schema initialization
// ---------------------------------------------------------------------------

func TestSQLOpenValidationFailClosed(t *testing.T) {
	key := randomTestKey(t)
	ctx := context.Background()
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		db, backing := newTestSQLDB(t, dialect)

		validGoals, err := OpenSQLGoalStore(ctx, db, dialect, "valid-goals", key)
		if err != nil {
			t.Fatalf("OpenSQLGoalStore valid: %v", err)
		}
		validAttempts, err := OpenSQLProtocolStore(ctx, db, dialect, "valid-attempts", key)
		if err != nil {
			t.Fatalf("OpenSQLProtocolStore valid: %v", err)
		}

		badCases := []struct {
			name string
			call func() error
		}{
			{"nil_ctx", func() error { _, err := OpenSQLStore(nil, db, dialect, "ns", key); return err }},
			{"canceled_ctx", func() error { _, err := OpenSQLStore(canceledCtx, db, dialect, "ns", key); return err }},
			{"nil_db", func() error { _, err := OpenSQLStore(ctx, nil, dialect, "ns", key); return err }},
			{"bad_dialect_empty", func() error { _, err := OpenSQLStore(ctx, db, "", "ns", key); return err }},
			{"bad_dialect_mysql", func() error { _, err := OpenSQLStore(ctx, db, SQLDialect("mysql"), "ns", key); return err }},
			{"empty_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "", key); return err }},
			{"slash_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "tenant/a", key); return err }},
			{"leading_slash_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "/tenant", key); return err }},
			{"nul_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "tenant\x00a", key); return err }},
			{"newline_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "tenant\na", key); return err }},
			{"del_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "tenant\x7fa", key); return err }},
			{"c1_control_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "tenant\u0085a", key); return err }},
			{"surrounding_space_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, " tenant", key); return err }},
			{"invalid_utf8_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, "tenant\xff", key); return err }},
			{"too_long_ns", func() error { _, err := OpenSQLStore(ctx, db, dialect, strings.Repeat("a", 129), key); return err }},
			{"short_key", func() error { _, err := OpenSQLStore(ctx, db, dialect, "ns", key[:16]); return err }},
			{"long_key", func() error { _, err := OpenSQLStore(ctx, db, dialect, "ns", append(bytes.Clone(key), 1)); return err }},
			{"protocol_bad_ns", func() error { _, err := OpenSQLProtocolStore(ctx, db, dialect, "a/b", key); return err }},
			{"goal_canceled", func() error { _, err := OpenSQLGoalStore(canceledCtx, db, dialect, "g", key); return err }},
			{"accord_bad_key", func() error { _, err := OpenSQLAccordStore(ctx, db, dialect, "a", key[:31]); return err }},
			{"coord_nil_goals", func() error {
				_, err := OpenSQLCoordinationStore(ctx, db, dialect, "c", key, nil, validAttempts)
				return err
			}},
			{"coord_nil_attempts", func() error {
				_, err := OpenSQLCoordinationStore(ctx, db, dialect, "c", key, validGoals, nil)
				return err
			}},
			{"coord_bad_ns", func() error {
				_, err := OpenSQLCoordinationStore(ctx, db, dialect, "bad/ns", key, validGoals, validAttempts)
				return err
			}},
		}
		for _, tc := range badCases {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.call(); err == nil {
					t.Fatalf("expected error for %s, got nil", tc.name)
				}
			})
		}

		// Canceling the init context AFTER OpenSQLStore succeeds must NOT break store operations!
		shortCtx, shortCancel := context.WithCancel(ctx)
		s, err := OpenSQLStore(shortCtx, db, dialect, "post-cancel", key)
		if err != nil {
			t.Fatalf("OpenSQLStore: %v", err)
		}
		shortCancel()
		if _, err := s.View(Hash("nonexistent")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("View after init ctx cancel got %v, want ErrNotFound", err)
		}

		// Concurrent schema init across 10 independent pod handles succeeds cleanly.
		var wg sync.WaitGroup
		errs := make(chan error, 10)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				peerDB := openPeerSQLDB(t, backing)
				_, err := OpenSQLStore(ctx, peerDB, dialect, fmt.Sprintf("init-ns-%d", idx%3), key)
				errs <- err
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("concurrent OpenSQLStore failed: %v", err)
			}
		}
		if dialect == SQLDialectPostgres && backing.metrics().schemaInitLocks < 10 {
			t.Fatalf("expected Postgres schema init advisory locks >= 10, got %+v", backing.metrics())
		}
		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("expected 0 non-tx queries, got %d", backing.metrics().nonTxQueries)
		}
	})
}

// ---------------------------------------------------------------------------
// 2. All 5 stores on both dialects + Pod A -> Pod B stateless failover
// ---------------------------------------------------------------------------

func TestSQLStoreContractLifecycleAndPodFailover(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		key := randomTestKey(t)

		podA, err := OpenSQLStore(ctx, dbA, dialect, "contracts", key)
		if err != nil {
			t.Fatal(err)
		}
		podB, err := OpenSQLStore(ctx, dbB, dialect, "contracts", key)
		if err != nil {
			t.Fatal(err)
		}

		now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
		buyer, _ := NewIdentity()
		seller, _ := NewIdentity()
		bp, _ := buyer.Public()
		sp, _ := seller.Public()
		c, err := New("work.bounty", bp, sp, 10, map[string]string{"task": "secret-contract-spec"}, now, now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		id := c.ID()

		// Pod A creates & locks.
		if err := podA.Create(c); err != nil {
			t.Fatal(err)
		}
		if err := podB.Create(c); !errors.Is(err, ErrExists) {
			t.Fatalf("Pod B duplicate Create got %v, want ErrExists", err)
		}
		lockOp, err := podA.Prepare(id, "op-lock", "lock", "secret-evidence")
		if err != nil {
			t.Fatal(err)
		}
		lockSig := Sign(buyer, "operation", lockOp)
		lockRes, err := podA.Apply(id, lockOp, lockSig, now)
		if err != nil || lockRes.Status != StatusLocked {
			t.Fatalf("Pod A lock: res=%+v err=%v", lockRes, err)
		}

		// Fail over to stateless Pod B (zero directory copy): agree + settle.
		agreeOp, err := podB.Prepare(id, "op-agree", "agree", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := podB.Apply(id, agreeOp, Sign(seller, "operation", agreeOp), now.Add(time.Minute)); err != nil {
			t.Fatalf("Pod B agree: %v", err)
		}
		settleOp, err := podB.Prepare(id, "op-settle", "settle", "delivered-artifact")
		if err != nil {
			t.Fatal(err)
		}
		settleRes, err := podB.Apply(id, settleOp, Sign(buyer, "operation", settleOp), now.Add(2*time.Minute))
		if err != nil || settleRes.Status != StatusAccepted {
			t.Fatalf("Pod B settle: res=%+v err=%v", settleRes, err)
		}

		// Pod A immediately sees final accepted state and preserves historical exact retry.
		viewA, err := podA.View(id)
		if err != nil || viewA.Status != StatusAccepted || !viewA.Agreed || len(viewA.Receipts) != 6 {
			t.Fatalf("Pod A post-failover View: %+v err=%v", viewA, err)
		}
		retryRes, err := podA.Apply(id, lockOp, lockSig, now.Add(24*time.Hour))
		if err != nil || retryRes != lockRes {
			t.Fatalf("Pod A historical retry: got %+v %v want %+v", retryRes, err, lockRes)
		}

		// Verify raw SQL row is encrypted (zero plaintext leakage) and version bumped monotonically (1 Create + 3 Applies = 4).
		ver, payload, ok := backing.rawRow("contracts", id)
		if !ok || ver != 4 {
			t.Fatalf("raw SQL row: ok=%v version=%d want 4", ok, ver)
		}
		if bytes.Contains(payload, []byte("secret-contract-spec")) || bytes.Contains(payload, []byte("delivered-artifact")) {
			t.Fatal("plaintext leaked into SQL payload")
		}
		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("non-tx queries=%d want 0", backing.metrics().nonTxQueries)
		}
	})
}

func TestSQLProtocolStoreLifecycleFailoverAndCache(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		key := randomTestKey(t)

		podA, err := OpenSQLProtocolStore(ctx, dbA, dialect, "protocols", key)
		if err != nil {
			t.Fatal(err)
		}
		podB, err := OpenSQLProtocolStore(ctx, dbB, dialect, "protocols", key)
		if err != nil {
			t.Fatal(err)
		}

		f := newProtocolFixture(t)
		f.spec.DissentPolicy = "block"
		id, err := podA.Create(f.spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := podB.Create(f.spec); !errors.Is(err, ErrExists) {
			t.Fatalf("duplicate Create got %v want ErrExists", err)
		}

		// Pod A atomically admits + commits via Transact.
		admitStep := func(actor Identity, role string) ProtocolStep {
			return func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
				cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(actor).ID(), Action: "admit", RequestID: "admit-" + role, Height: 1}
				return cmd, Sign(actor, "protocol", cmd), true, nil
			}
		}
		v1, err := podA.Transact(id, 1,
			admitStep(f.owner, "owner"),
			admitStep(f.worker, "worker"),
			admitStep(f.witness, "witness"),
			func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
				cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f.owner).ID(), GrantID: "owner", Scope: f.spec.Scope, Action: "commit", RequestID: "commit", Height: 1}
				return cmd, Sign(f.owner, "protocol", cmd), true, nil
			},
		)
		if err != nil || v1.Phase != "working" {
			t.Fatalf("Pod A Transact: v=%+v err=%v", v1, err)
		}

		// Warm Pod B cache and verify cache hit on 2nd View (authenticating ciphertext without replay).
		if _, err := podB.View(id); err != nil {
			t.Fatal(err)
		}
		sBefore := podB.Stats()
		if _, err := podB.View(id); err != nil {
			t.Fatal(err)
		}
		sAfter := podB.Stats()
		if sAfter.CacheHits != sBefore.CacheHits+1 || sAfter.AuthDecryptOps != sBefore.AuthDecryptOps+1 || sAfter.ReplayValidationOps != sBefore.ReplayValidationOps {
			t.Fatalf("expected warm SQL cache hit with AEAD auth and zero replay: before=%+v after=%+v", sBefore, sAfter)
		}

		// Mid-batch Transact error on Pod B rolls back cleanly (zero partial persistence).
		_, err = podB.Transact(id, 5,
			func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
				cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f.worker).ID(), GrantID: "worker", Scope: f.spec.Scope, Action: "report", RequestID: "rep-rollback", Height: 5}
				cmd.Report = &WorkReport{Outcome: WorkCompleted, Stage: "v", ReasonHash: Hash("ok"), Evidence: []string{Hash("e")}}
				return cmd, Sign(f.worker, "protocol", cmd), true, nil
			},
			func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
				// Early resolve before required witness review fails with ErrProtocolEvidence!
				cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f.owner).ID(), GrantID: "owner", Scope: f.spec.Scope, Action: "resolve", RequestID: "res-early", Height: 5}
				cmd.Resolution = &Resolution{ReportHash: Hash(v.Report), Outcome: "accept", ReasonHash: Hash("r")}
				return cmd, Sign(f.owner, "protocol", cmd), true, nil
			},
		)
		if !errors.Is(err, ErrProtocolEvidence) {
			t.Fatalf("mid-batch Transact got %v want ErrProtocolEvidence", err)
		}
		vCheck, err := podA.View(id)
		if err != nil || vCheck.Phase != "working" || vCheck.Report != nil {
			t.Fatalf("rolled-back Transact leaked state: %+v err=%v", vCheck, err)
		}

		// Warm Pod A cache, then advance state on Pod B -> Pod A MUST detect bumped SQL version and complete!
		if _, err := podA.View(id); err != nil {
			t.Fatal(err)
		}
		repCmd, err := podB.Prepare(id, protocolPublic(f.worker).ID(), "worker", f.spec.Scope, "report", "rep-1", 5)
		if err != nil {
			t.Fatal(err)
		}
		repCmd.Report = &WorkReport{Outcome: WorkCompleted, Stage: "v", ReasonHash: Hash("ok"), Evidence: []string{Hash("e")}}
		if _, err := podB.Apply(id, repCmd, Sign(f.worker, "protocol", repCmd), 5); err != nil {
			t.Fatal(err)
		}

		sABefore := podA.Stats()
		finalView, err := podA.Transact(id, 8,
			func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
				if v.Phase != "review" {
					return ProtocolCommand{}, nil, false, fmt.Errorf("Pod A served stale phase %q", v.Phase)
				}
				cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f.witness).ID(), GrantID: "witness", Scope: f.spec.Scope, Action: "review", RequestID: "rev-1", Height: 8}
				cmd.Review = &WitnessReview{ReportHash: Hash(v.Report), AssessmentHash: Hash("ok")}
				return cmd, Sign(f.witness, "protocol", cmd), true, nil
			},
			func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
				cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f.owner).ID(), GrantID: "owner", Scope: f.spec.Scope, Action: "resolve", RequestID: "res-1", Height: 8}
				cmd.Resolution = &Resolution{ReportHash: Hash(v.Report), Outcome: "accept", ReasonHash: Hash("ok")}
				return cmd, Sign(f.owner, "protocol", cmd), true, nil
			},
			func(v ProtocolView) (ProtocolCommand, []byte, bool, error) {
				cmd := ProtocolCommand{ProtocolID: v.ID, Head: v.Head, Actor: protocolPublic(f.worker).ID(), GrantID: "worker", Scope: f.spec.Scope, Action: "return", RequestID: "ret-1", Height: 8}
				cmd.Return = &ReturnManifest{
					ResolutionHash: Hash(v.Resolution), ReviewsHash: Hash(v.Reviews), Evidence: v.Report.Evidence,
					Uncertainty: "bounded", SafeAssumptions: []string{"ok"},
					Artifacts: []ReturnArtifact{{ID: "answer", Commitment: Hash("ans"), ReuseRestrictions: "cite"}}, Disposition: "continue",
				}
				return cmd, Sign(f.worker, "protocol", cmd), true, nil
			},
		)
		if err != nil || finalView.Phase != "complete" {
			t.Fatalf("Pod A completion Transact: v=%+v err=%v", finalView, err)
		}
		if podA.Stats().CacheMisses <= sABefore.CacheMisses {
			t.Fatalf("expected Pod A cache miss after Pod B write: before=%+v after=%+v", sABefore, podA.Stats())
		}

		bundle, err := podB.Export(id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyProtocolBundle(bundle, id, finalView.Head); err != nil {
			t.Fatalf("VerifyProtocolBundle: %v", err)
		}
		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("non-tx queries=%d want 0", backing.metrics().nonTxQueries)
		}
	})
}

func TestSQLGoalAndCoordinationStoresFailoverSingleDB(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		if dialect == SQLDialectSQLite {
			// Exercise Go's common SQLite MaxOpenConns(1) configuration to prove
			// CoordinationStore.Claim / Finalize calling ProtocolStore NEVER deadlocks!
			dbA.SetMaxOpenConns(1)
			dbB.SetMaxOpenConns(1)
		}
		key := randomTestKey(t)

		goalsA, err := OpenSQLGoalStore(ctx, dbA, dialect, "goals", key)
		if err != nil {
			t.Fatal(err)
		}
		attemptsA, err := OpenSQLProtocolStore(ctx, dbA, dialect, "attempts", key)
		if err != nil {
			t.Fatal(err)
		}
		tasksA, err := OpenSQLCoordinationStore(ctx, dbA, dialect, "tasks", key, goalsA, attemptsA)
		if err != nil {
			t.Fatal(err)
		}

		goalsB, err := OpenSQLGoalStore(ctx, dbB, dialect, "goals", key)
		if err != nil {
			t.Fatal(err)
		}
		attemptsB, err := OpenSQLProtocolStore(ctx, dbB, dialect, "attempts", key)
		if err != nil {
			t.Fatal(err)
		}
		tasksB, err := OpenSQLCoordinationStore(ctx, dbB, dialect, "tasks", key, goalsB, attemptsB)
		if err != nil {
			t.Fatal(err)
		}

		f := newProtocolFixture(t)
		owner := protocolPublic(f.owner)
		goal := GoalSpec{
			Nonce: "sql-goal-failover", Purpose: "Coordinate across stateless pods",
			ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner},
		}
		goalID, err := goalsA.Create(goal)
		if err != nil {
			t.Fatal(err)
		}
		// Idempotent Create on Pod B succeeds cleanly.
		if gid2, err := goalsB.Create(goal); err != nil || gid2 != goalID {
			t.Fatalf("Pod B idempotent GoalStore.Create: id=%s err=%v", gid2, err)
		}

		task1 := v202MakeTask(goalID, "task-1", f, owner)
		rev1 := PlanRevision{GoalID: goalID, Head: goalID, Planner: owner.ID(), RequestID: "rev-1", Tasks: []TaskSpec{task1}}
		head1, err := goalsA.Apply(rev1, Sign(f.owner, PlanSignatureDomain, rev1))
		if err != nil {
			t.Fatal(err)
		}

		// Pod B loads task1 (warms GoalStore.cached), then Pod A appends rev2 with task2.
		if got, err := goalsB.Task(goalID, task1.ID()); err != nil || got.ID() != task1.ID() {
			t.Fatalf("Pod B Task(task1): %v", err)
		}
		if _, err := goalsB.Task(goalID, task1.ID()); err != nil {
			t.Fatal(err)
		}
		if goalsB.Stats().CacheHits < 1 {
			t.Fatalf("expected GoalStore.Task cache hit on Pod B: %+v", goalsB.Stats())
		}

		spec1 := f.spec
		spec1.Version = ProtocolVersionV2
		spec1.TaskID = task1.ID()
		spec1.Generation = 1
		spec1.Nonce = "attempt-1"
		p1, err := NewProtocol(spec1)
		if err != nil {
			t.Fatal(err)
		}
		claim1 := ClaimRequest{
			GoalID: goalID, TaskID: task1.ID(), WorkerID: protocolPublic(f.worker).ID(),
			RequestID: "claim-1", ProtocolID: p1.View().ID, LeaseUntilHeight: 41,
		}
		claimSig1 := Sign(f.owner, ClaimSignatureDomain, claim1)

		// Pod A claims task1 (creates attempt1 inside attempts namespace + writes task1 checkpoint).
		lease1, err := tasksA.Claim(claim1, claimSig1, spec1, 1)
		if err != nil {
			t.Fatalf("Pod A Claim: %v", err)
		}

		// Pod A warms DiscoverGoal cache (sees task1 active).
		discA1, missesA1, err := tasksA.DiscoverGoal(goalID, 2)
		if err != nil || missesA1 != 1 || len(discA1) != 1 || discA1[0].Status != "active" {
			t.Fatalf("Pod A DiscoverGoal 1: misses=%d disc=%+v err=%v", missesA1, discA1, err)
		}
		discA2, missesA2, err := tasksA.DiscoverGoal(goalID, 2)
		if err != nil || missesA2 != 0 || len(discA2) != 1 || discA2[0].Status != "active" {
			t.Fatalf("Pod A DiscoverGoal 2 (cached): misses=%d disc=%+v err=%v", missesA2, discA2, err)
		}

		// Fail over to Pod B: drive protocol attempt1 to accepted completion & finalize task1!
		pRun := enterProtocol(t, protocolFixture{owner: f.owner, worker: f.worker, witness: f.witness, spec: spec1})
		answerRef := testArtifactRef("sql-pod-b-answer")
		protocolApply(t, pRun, f.worker, "worker", "report", func(c *ProtocolCommand) {
			c.Report = &WorkReport{
				Outcome: WorkCompleted, Stage: "work", ReasonHash: Hash("ok"), Evidence: []string{answerRef.Digest},
				Manifest: &EvidenceManifest{MethodHash: Hash("m"), Outputs: []NamedArtifact{{Name: "answer", Ref: answerRef}}},
			}
		})
		reviewProtocol(t, pRun, f, false)
		resolveProtocol(t, pRun, f, "accept")
		protocolApply(t, pRun, f.worker, "worker", "return", func(c *ProtocolCommand) {
			m := manifestFor(pRun)
			m.Artifacts[0].Commitment = answerRef.Digest
			c.Return = &m
		})
		for _, ev := range pRun.Bundle().Events {
			if _, err := attemptsB.Apply(claim1.ProtocolID, ev.Command, ev.Signature, ev.Command.Height); err != nil {
				t.Fatalf("Pod B attempts.Apply(%s): %v", ev.Command.Action, err)
			}
		}
		pView := pRun.View()
		res1, err := tasksB.Finalize(lease1, pView.Head, pView.Height)
		if err != nil || res1.Outcome != TaskAccepted {
			t.Fatalf("Pod B Finalize: res=%+v err=%v", res1, err)
		}

		// Append rev2 with task2 depending on task1's accepted artifact on Pod A, then verify Pod B's warm GoalStore sees task2!
		task2 := v202MakeTask(goalID, "task-2", f, owner, TaskDependency{
			Input: "upstream", TaskID: task1.ID(), ProtocolID: claim1.ProtocolID,
			Head: pView.Head, Slot: "answer", Digest: answerRef.Digest, Outcome: TaskAccepted,
		})
		rev2 := PlanRevision{GoalID: goalID, Head: head1, Planner: owner.ID(), RequestID: "rev-2", Tasks: []TaskSpec{task2}}
		head2, err := goalsA.Apply(rev2, Sign(f.owner, PlanSignatureDomain, rev2))
		if err != nil {
			t.Fatal(err)
		}
		if got2, err := goalsB.Task(goalID, task2.ID()); err != nil || got2.ID() != task2.ID() {
			t.Fatalf("Pod B GoalStore.Task(task2) after Pod A rev2: %v", err)
		}
		planB, err := goalsB.View(goalID)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyGoalPlan(planB, goalID, head2); err != nil {
			t.Fatalf("VerifyGoalPlan: %v", err)
		}

		// Pod A DiscoverGoal MUST immediately detect Pod B's finalize (cache miss on bumped SQL version) and report task2 DependenciesReady=true!
		discA3, missesA3, err := tasksA.DiscoverGoal(goalID, pView.Height)
		if err != nil || missesA3 != 1 || len(discA3) != 2 {
			t.Fatalf("Pod A post-failover DiscoverGoal: misses=%d len=%d err=%v", missesA3, len(discA3), err)
		}
		if discA3[0].Status != "accepted" || !discA3[1].DependenciesReady || discA3[1].DependenciesMismatch {
			t.Fatalf("Pod A post-failover discovery mismatch: %+v", discA3)
		}

		// ExportHandoff on Pod A succeeds and verifies offline!
		handoff, err := tasksA.ExportHandoff(claim1, claimSig1)
		if err != nil {
			t.Fatalf("ExportHandoff: %v", err)
		}
		if _, err := VerifyTaskHandoff(handoff, task1.ID(), Hash(res1)); err != nil {
			t.Fatalf("VerifyTaskHandoff: %v", err)
		}
		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("non-tx queries=%d want 0", backing.metrics().nonTxQueries)
		}
	})
}

func TestSQLAccordStoreLifecycleFailoverAndRollback(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		key := randomTestKey(t)

		podA, err := OpenSQLAccordStore(ctx, dbA, dialect, "accords", key)
		if err != nil {
			t.Fatal(err)
		}
		podB, err := OpenSQLAccordStore(ctx, dbB, dialect, "accords", key)
		if err != nil {
			t.Fatal(err)
		}

		fx := newAccordFixture(t)
		id, err := podA.Create(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := podB.Create(fx.spec); !errors.Is(err, ErrExists) {
			t.Fatalf("duplicate Create got %v want ErrExists", err)
		}

		// Pod A applies vote 1 and warms cache.
		v1Cmd, err := podA.Prepare(id, fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", "v1", 2)
		if err != nil {
			t.Fatal(err)
		}
		v1Cmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r1")}
		v1Sig, err := SignAccordCommand(fx.sre.id, v1Cmd)
		if err != nil {
			t.Fatal(err)
		}
		v1Head, err := podA.Apply(id, v1Cmd, v1Sig, 2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := podA.View(id); err != nil {
			t.Fatal(err)
		}
		sBefore := podA.Stats()
		if _, err := podA.View(id); err != nil {
			t.Fatal(err)
		}
		if podA.Stats().CacheHits != sBefore.CacheHits+1 || podA.Stats().ReplayValidationOps != sBefore.ReplayValidationOps {
			t.Fatalf("expected AccordStore SQL cache hit: before=%+v after=%+v", sBefore, podA.Stats())
		}

		// Pod B mid-batch Transact error rolls back cleanly.
		_, err = podB.Transact(id, 3,
			func(v AccordView) (AccordCommand, []byte, bool, error) {
				cmd := AccordCommand{
					RequestID: "v2-rb", AccordID: v.ID, Head: v.Head, Actor: fx.safety.pub.ID(),
					GrantID: "safety-vote", Scope: fx.spec.Scope, Action: "vote", Height: 3,
					Vote: &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r2")},
				}
				sig, err := SignAccordCommand(fx.safety.id, cmd)
				return cmd, sig, true, err
			},
			func(v AccordView) (AccordCommand, []byte, bool, error) {
				cmd := AccordCommand{
					RequestID: "res-early", AccordID: v.ID, Head: v.Head, Actor: fx.security.pub.ID(),
					GrantID: "security-vote", Scope: fx.spec.Scope, Action: "resolve", Height: 3,
					Resolve: &ResolvePayload{ReasonHash: Hash("early")},
				}
				sig, err := SignAccordCommand(fx.security.id, cmd)
				return cmd, sig, true, err
			},
		)
		if !errors.Is(err, ErrAccordPhase) {
			t.Fatalf("mid-batch Accord Transact got %v want ErrAccordPhase", err)
		}

		// Pod B completes votes via Transact and resolves.
		if _, err := podB.Transact(id, 4,
			func(v AccordView) (AccordCommand, []byte, bool, error) {
				cmd := AccordCommand{
					RequestID: "v2", AccordID: v.ID, Head: v.Head, Actor: fx.safety.pub.ID(),
					GrantID: "safety-vote", Scope: fx.spec.Scope, Action: "vote", Height: 4,
					Vote: &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r2")},
				}
				sig, err := SignAccordCommand(fx.safety.id, cmd)
				return cmd, sig, true, err
			},
			func(v AccordView) (AccordCommand, []byte, bool, error) {
				cmd := AccordCommand{
					RequestID: "v3", AccordID: v.ID, Head: v.Head, Actor: fx.security.pub.ID(),
					GrantID: "security-vote", Scope: fx.spec.Scope, Action: "vote", Height: 4,
					Vote: &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r3")},
				}
				sig, err := SignAccordCommand(fx.security.id, cmd)
				return cmd, sig, true, err
			},
		); err != nil {
			t.Fatal(err)
		}
		resCmd, err := podB.Prepare(id, fx.security.pub.ID(), "security-vote", fx.spec.Scope, "resolve", "res-1", 10)
		if err != nil {
			t.Fatal(err)
		}
		resCmd.Resolve = &ResolvePayload{ReasonHash: Hash("done")}
		resSig, err := SignAccordCommand(fx.security.id, resCmd)
		if err != nil {
			t.Fatal(err)
		}
		finalHead, err := podB.Apply(id, resCmd, resSig, 10)
		if err != nil {
			t.Fatal(err)
		}

		// Pod A (with stale warm cache from v1) immediately detects bumped SQL version and sees AccordPhaseDecided!
		vA, err := podA.View(id)
		if err != nil || vA.Phase != AccordPhaseDecided || vA.Head != finalHead || vA.Outcome.WinningOptionID != "canary-rollout" {
			t.Fatalf("Pod A post-failover View: %+v err=%v", vA, err)
		}
		// Historical exact retry on Pod A returns v1Head without overwriting finalHead.
		if got, err := podA.Apply(id, v1Cmd, v1Sig, 999); err != nil || got != v1Head {
			t.Fatalf("historical retry got %s %v want %s", got, err, v1Head)
		}
		bundle, err := podA.Export(id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyAccordBundle(bundle, id, finalHead); err != nil {
			t.Fatalf("VerifyAccordBundle: %v", err)
		}
		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("non-tx queries=%d want 0", backing.metrics().nonTxQueries)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. Cross-namespace AAD, cross-ID AAD, wrong key, warm-cache tamper detection
// ---------------------------------------------------------------------------

func TestSQLSecurityAADWrongKeyAndWarmCacheTamper(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		db, backing := newTestSQLDB(t, dialect)
		key := randomTestKey(t)
		wrongKey := bytes.Clone(key)
		wrongKey[0] ^= 0x01

		// Helper verifying cross-namespace, cross-ID, wrong-key, in-place warm-cache tamper,
		// bad header, truncation, and zero-version rejection for any store.
		verifySecurity := func(
			t *testing.T,
			nsA, nsB, id string,
			viewA func(string) error,
			viewB func(string) error,
			viewWrongKey func(string) error,
			statsA func() StoreStats,
			hasCache bool,
		) {
			t.Helper()

			// Warm cache (if applicable) and verify cache hit stats.
			if err := viewA(id); err != nil {
				t.Fatalf("warm read 1: %v", err)
			}
			if hasCache {
				before := statsA()
				if err := viewA(id); err != nil {
					t.Fatalf("warm read 2: %v", err)
				}
				after := statsA()
				if after.CacheHits <= before.CacheHits || after.AuthDecryptOps <= before.AuthDecryptOps {
					t.Fatalf("expected cache hit + AEAD auth on warm read: before=%+v after=%+v", before, after)
				}
				if after.ReplayValidationOps != before.ReplayValidationOps {
					t.Fatalf("expected warm read to skip replay: before=%+v after=%+v", before, after)
				}
			}

			origVer, origPayload, ok := backing.rawRow(nsA, id)
			if !ok {
				t.Fatalf("missing raw row (%s, %s)", nsA, id)
			}

			// 1. Wrong key MUST fail with ErrCorruptStore.
			if err := viewWrongKey(id); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("wrong key got %v want ErrCorruptStore", err)
			}

			// 2. Cross-namespace AAD tamper: copy row from nsA -> nsB with identical id & key!
			backing.setRawRow(nsB, id, origVer, origPayload)
			if err := viewB(id); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("cross-namespace row copy got %v want ErrCorruptStore", err)
			}

			// 3. Cross-ID AAD tamper: copy row from id -> otherID in same namespace & key!
			otherID := Hash("relocated-id-" + nsA)
			backing.setRawRow(nsA, otherID, origVer, origPayload)
			if err := viewA(otherID); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("cross-ID row copy got %v want ErrCorruptStore", err)
			}

			// 4. In-place ciphertext tamper at SAME SQL version WITH WARM CACHE -> MUST fail with ErrCorruptStore!
			tampered := bytes.Clone(origPayload)
			tampered[len(tampered)-1] ^= 0xff
			backing.setRawRow(nsA, id, origVer, tampered)
			if err := viewA(id); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("in-place ciphertext tamper (same version, warm cache) got %v want ErrCorruptStore", err)
			}

			// 5. Truncated payload -> ErrCorruptStore.
			backing.setRawRow(nsA, id, origVer, origPayload[:12])
			if err := viewA(id); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("truncated payload got %v want ErrCorruptStore", err)
			}

			// 6. Bad storeHeader -> ErrStoreVersion.
			badHdr := bytes.Clone(origPayload)
			badHdr[0] ^= 0x01
			backing.setRawRow(nsA, id, origVer, badHdr)
			if err := viewA(id); !errors.Is(err, ErrStoreVersion) {
				t.Fatalf("bad header got %v want ErrStoreVersion", err)
			}

			// 7. Non-positive SQL version -> ErrCorruptStore.
			backing.setRawRow(nsA, id, 0, origPayload)
			if err := viewA(id); !errors.Is(err, ErrCorruptStore) {
				t.Fatalf("zero version got %v want ErrCorruptStore", err)
			}

			// Restore valid row and confirm clean recovery.
			backing.setRawRow(nsA, id, origVer, origPayload)
			if err := viewA(id); err != nil {
				t.Fatalf("recovery after restore failed: %v", err)
			}
		}

		t.Run("Store", func(t *testing.T) {
			sA, _ := OpenSQLStore(ctx, db, dialect, "sec-c-a", key)
			sB, _ := OpenSQLStore(ctx, db, dialect, "sec-c-b", key)
			sWrong, _ := OpenSQLStore(ctx, db, dialect, "sec-c-a", wrongKey)
			now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
			buyer, _ := NewIdentity()
			seller, _ := NewIdentity()
			bp, _ := buyer.Public()
			sp, _ := seller.Public()
			c, err := New("work.bounty", bp, sp, 10, "spec", now, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err := sA.Create(c); err != nil {
				t.Fatal(err)
			}
			verifySecurity(t, "sec-c-a", "sec-c-b", c.ID(),
				func(id string) error { _, err := sA.View(id); return err },
				func(id string) error { _, err := sB.View(id); return err },
				func(id string) error { _, err := sWrong.View(id); return err },
				sA.Stats, false,
			)
		})

		t.Run("ProtocolStore", func(t *testing.T) {
			sA, _ := OpenSQLProtocolStore(ctx, db, dialect, "sec-p-a", key)
			sB, _ := OpenSQLProtocolStore(ctx, db, dialect, "sec-p-b", key)
			sWrong, _ := OpenSQLProtocolStore(ctx, db, dialect, "sec-p-a", wrongKey)
			f := newProtocolFixture(t)
			id, err := sA.Create(f.spec)
			if err != nil {
				t.Fatal(err)
			}
			verifySecurity(t, "sec-p-a", "sec-p-b", id,
				func(id string) error { _, err := sA.View(id); return err },
				func(id string) error { _, err := sB.View(id); return err },
				func(id string) error { _, err := sWrong.View(id); return err },
				sA.Stats, true,
			)
		})

		t.Run("GoalStore", func(t *testing.T) {
			sA, _ := OpenSQLGoalStore(ctx, db, dialect, "sec-g-a", key)
			sB, _ := OpenSQLGoalStore(ctx, db, dialect, "sec-g-b", key)
			sWrong, _ := OpenSQLGoalStore(ctx, db, dialect, "sec-g-a", wrongKey)
			_, goal, _ := planFixture(t)
			id, err := sA.Create(goal)
			if err != nil {
				t.Fatal(err)
			}
			verifySecurity(t, "sec-g-a", "sec-g-b", id,
				func(id string) error { _, err := sA.View(id); return err },
				func(id string) error { _, err := sB.View(id); return err },
				func(id string) error { _, err := sWrong.View(id); return err },
				sA.Stats, false,
			)
		})

		t.Run("CoordinationStore", func(t *testing.T) {
			goals, _ := OpenSQLGoalStore(ctx, db, dialect, "sec-cg", key)
			attempts, _ := OpenSQLProtocolStore(ctx, db, dialect, "sec-cp", key)
			sA, _ := OpenSQLCoordinationStore(ctx, db, dialect, "sec-ct-a", key, goals, attempts)
			sB, _ := OpenSQLCoordinationStore(ctx, db, dialect, "sec-ct-b", key, goals, attempts)
			sWrong, _ := OpenSQLCoordinationStore(ctx, db, dialect, "sec-ct-a", wrongKey, goals, attempts)

			f := newProtocolFixture(t)
			owner := protocolPublic(f.owner)
			gid, err := goals.Create(GoalSpec{Nonce: "sec-coord", Purpose: "sec", ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner}})
			if err != nil {
				t.Fatal(err)
			}
			task := v202MakeTask(gid, "sec-task", f, owner)
			rev := PlanRevision{GoalID: gid, Head: gid, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{task}}
			if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
				t.Fatal(err)
			}
			spec := f.spec
			spec.Version = ProtocolVersionV2
			spec.TaskID = task.ID()
			spec.Generation = 1
			p, _ := NewProtocol(spec)
			req := ClaimRequest{GoalID: gid, TaskID: task.ID(), WorkerID: protocolPublic(f.worker).ID(), RequestID: "c1", ProtocolID: p.View().ID, LeaseUntilHeight: 41}
			if _, err := sA.Claim(req, Sign(f.owner, ClaimSignatureDomain, req), spec, 1); err != nil {
				t.Fatal(err)
			}
			verifySecurity(t, "sec-ct-a", "sec-ct-b", task.ID(),
				func(id string) error {
					if id == task.ID() {
						_, _, err := sA.DiscoverGoal(gid, 2)
						return err
					}
					_, err := sA.Current(gid, id)
					return err
				},
				func(id string) error { _, err := sB.Current(gid, id); return err },
				func(id string) error { _, err := sWrong.Current(gid, id); return err },
				sA.Stats, true,
			)
		})

		t.Run("AccordStore", func(t *testing.T) {
			sA, _ := OpenSQLAccordStore(ctx, db, dialect, "sec-a-a", key)
			sB, _ := OpenSQLAccordStore(ctx, db, dialect, "sec-a-b", key)
			sWrong, _ := OpenSQLAccordStore(ctx, db, dialect, "sec-a-a", wrongKey)
			fx := newAccordFixture(t)
			id, err := sA.Create(fx.spec)
			if err != nil {
				t.Fatal(err)
			}
			verifySecurity(t, "sec-a-a", "sec-a-b", id,
				func(id string) error { _, err := sA.View(id); return err },
				func(id string) error { _, err := sB.View(id); return err },
				func(id string) error { _, err := sWrong.View(id); return err },
				sA.Stats, true,
			)
		})

		if dialect == SQLDialectSQLite {
			t.Run("SQLiteMissingLockRowFailsClosed", func(t *testing.T) {
				s, err := OpenSQLStore(ctx, db, dialect, "lock-row-test", key)
				if err != nil {
					t.Fatal(err)
				}
				backing.deleteLockRow("lock-row-test")
				if _, err := s.View(Hash("any")); err == nil || errors.Is(err, ErrNotFound) {
					t.Fatalf("expected lock row missing error, got %v", err)
				}
			})
		}
	})
}

// ---------------------------------------------------------------------------
// 4. Bounded 256-entry FIFO cache eviction, rollback, and ErrCommitUncertain
// ---------------------------------------------------------------------------

func TestSQLCacheBoundedEvictionAndWriteCommitFaults(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		db, backing := newTestSQLDB(t, dialect)
		key := randomTestKey(t)

		// Bounded 256-entry FIFO cache on SQL ProtocolStore and AccordStore.
		pStore, err := OpenSQLProtocolStore(ctx, db, dialect, "bounded-proto", key)
		if err != nil {
			t.Fatal(err)
		}
		f := newProtocolFixture(t)
		var firstPID string
		for i := 0; i < maxCachedProtocols+20; i++ {
			spec := f.spec
			spec.Nonce = fmt.Sprintf("sql-proto-%03d", i)
			id, err := pStore.Create(spec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pStore.View(id); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				firstPID = id
			}
		}
		pStore.mu.Lock()
		pCacheLen, pOrderLen := len(pStore.cache), len(pStore.cacheOrder)
		pStore.mu.Unlock()
		if pCacheLen > maxCachedProtocols || pOrderLen > maxCachedProtocols*2 {
			t.Fatalf("ProtocolStore SQL cache bounds exceeded: cache=%d order=%d", pCacheLen, pOrderLen)
		}
		if _, err := pStore.View(firstPID); err != nil {
			t.Fatalf("reload evicted SQL protocol: %v", err)
		}

		// Write failure rolls back cleanly; commit failure returns ErrCommitUncertain + invalidates cache!
		aStore, err := OpenSQLAccordStore(ctx, db, dialect, "fault-accord", key)
		if err != nil {
			t.Fatal(err)
		}
		fx := newAccordFixture(t)
		aid, err := aStore.Create(fx.spec)
		if err != nil {
			t.Fatal(err)
		}
		// Warm cache.
		if _, err := aStore.View(aid); err != nil {
			t.Fatal(err)
		}
		cmd, err := aStore.Prepare(aid, fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", "fault-v1", 2)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("r")}
		sig, err := SignAccordCommand(fx.sre.id, cmd)
		if err != nil {
			t.Fatal(err)
		}

		// 1. Write error -> rolls back cleanly (NOT ErrCommitUncertain).
		writeFault := errors.New("injected SQL write failure")
		backing.setFailNextWrite(writeFault)
		if _, err := aStore.Apply(aid, cmd, sig, 2); !errors.Is(err, writeFault) || errors.Is(err, ErrCommitUncertain) {
			t.Fatalf("write failure got %v want wrapped writeFault (not ErrCommitUncertain)", err)
		}
		vAfterWriteErr, err := aStore.View(aid)
		if err != nil || len(vAfterWriteErr.Votes) != 0 {
			t.Fatalf("rolled-back write leaked state: %+v err=%v", vAfterWriteErr, err)
		}

		// 2. Commit error -> returns ErrCommitUncertain and leaves cache invalidated.
		backing.setFailNextCommit(errors.New("injected SQL commit drop"))
		if _, err := aStore.Apply(aid, cmd, sig, 2); !errors.Is(err, ErrCommitUncertain) {
			t.Fatalf("commit failure got %v want ErrCommitUncertain", err)
		}
		aStore.mu.Lock()
		_, stillCached := aStore.cache[aid]
		aStore.mu.Unlock()
		if stillCached {
			t.Fatal("cache entry was not invalidated before uncertain SQL commit")
		}
		// Exact retry succeeds cleanly!
		if _, err := aStore.Apply(aid, cmd, sig, 2); err != nil {
			t.Fatalf("retry after uncertain commit failed: %v", err)
		}
		vFinal, err := aStore.View(aid)
		if err != nil || len(vFinal.Votes) != 1 {
			t.Fatalf("expected 1 vote after retry, got %+v err=%v", vFinal, err)
		}
	})
}

// ---------------------------------------------------------------------------
// 5. Real blocking lock semantics + concurrent multi-pod -race stress tests
// ---------------------------------------------------------------------------

func TestSQLBlockingLocksAndMultiPodRaceStress(t *testing.T) {
	forEachSQLDialect(t, func(t *testing.T, dialect SQLDialect) {
		ctx := context.Background()
		dbA, backing := newTestSQLDB(t, dialect)
		dbB := openPeerSQLDB(t, backing)
		key := randomTestKey(t)

		t.Run("RealBlockingLocks", func(t *testing.T) {
			sA, err := OpenSQLStore(ctx, dbA, dialect, "lock-test", key)
			if err != nil {
				t.Fatal(err)
			}
			sB, err := OpenSQLStore(ctx, dbB, dialect, "lock-test", key)
			if err != nil {
				t.Fatal(err)
			}
			id1 := Hash("lock-record-1")
			id2 := Hash("lock-record-2")

			held := make(chan struct{})
			release := make(chan struct{})
			bEntered := make(chan struct{})

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sA.withLock(id1, func() error {
					close(held)
					<-release
					return nil
				})
			}()
			<-held

			// On PostgreSQL, a DIFFERENT record id2 MUST NOT be blocked by id1's advisory lock!
			if dialect == SQLDialectPostgres {
				otherDone := make(chan error, 1)
				go func() {
					otherDone <- sB.withLock(id2, func() error { return nil })
				}()
				select {
				case err := <-otherDone:
					if err != nil {
						t.Fatalf("distinct Postgres advisory lock failed: %v", err)
					}
				case <-time.After(2 * time.Second):
					close(release)
					t.Fatal("Postgres advisory lock on id1 unexpectedly blocked id2")
				}
			}

			// Same record id1 MUST block Pod B until Pod A releases!
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sB.withLock(id1, func() error {
					close(bEntered)
					return nil
				})
			}()
			select {
			case <-bEntered:
				close(release)
				t.Fatal("Pod B entered critical section while Pod A still held SQL lock")
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			select {
			case <-bEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("Pod B failed to acquire SQL lock after Pod A released")
			}
			wg.Wait()
		})

		t.Run("ConcurrentContractRetriesAndConflicts", func(t *testing.T) {
			sInit, err := OpenSQLStore(ctx, dbA, dialect, "race-contract", key)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
			buyer, _ := NewIdentity()
			seller, _ := NewIdentity()
			bp, _ := buyer.Public()
			sp, _ := seller.Public()
			c, err := New("work.bounty", bp, sp, 10, "race", now, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err := sInit.Create(c); err != nil {
				t.Fatal(err)
			}
			id := c.ID()
			op, err := sInit.Prepare(id, "lock-race", "lock", "ev")
			if err != nil {
				t.Fatal(err)
			}
			sig := Sign(buyer, "operation", op)

			const pods = 12
			results := make(chan Result, pods)
			errs := make(chan error, pods)
			var wg sync.WaitGroup
			for i := 0; i < pods; i++ {
				peerDB := openPeerSQLDB(t, backing)
				pod, err := OpenSQLStore(ctx, peerDB, dialect, "race-contract", key)
				if err != nil {
					t.Fatal(err)
				}
				wg.Add(1)
				go func(st *Store) {
					defer wg.Done()
					r, e := st.Apply(id, op, sig, now)
					results <- r
					errs <- e
				}(pod)
			}
			wg.Wait()
			close(results)
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("concurrent contract retry error: %v", err)
				}
			}
			var want Result
			for r := range results {
				if want.Head == "" {
					want = r
				}
				if r != want {
					t.Fatalf("divergent contract retry results: %+v vs %+v", r, want)
				}
			}
			v, err := sInit.View(id)
			if err != nil || len(v.Receipts) != 3 {
				t.Fatalf("expected 3 receipts after race, got %+v err=%v", v, err)
			}
		})

		t.Run("ConcurrentCoordinationClaimCASRace", func(t *testing.T) {
			goals, err := OpenSQLGoalStore(ctx, dbA, dialect, "race-goals", key)
			if err != nil {
				t.Fatal(err)
			}
			attempts, err := OpenSQLProtocolStore(ctx, dbA, dialect, "race-attempts", key)
			if err != nil {
				t.Fatal(err)
			}
			f := newProtocolFixture(t)
			owner := protocolPublic(f.owner)
			gid, err := goals.Create(GoalSpec{Nonce: "race-g", Purpose: "race", ConstraintsHash: Hash("c"), CompletionPolicyHash: Hash("p"), Planners: []Public{owner}})
			if err != nil {
				t.Fatal(err)
			}
			task := v202MakeTask(gid, "race-t", f, owner)
			rev := PlanRevision{GoalID: gid, Head: gid, Planner: owner.ID(), RequestID: "r1", Tasks: []TaskSpec{task}}
			if _, err := goals.Apply(rev, Sign(f.owner, PlanSignatureDomain, rev)); err != nil {
				t.Fatal(err)
			}

			const pods = 8
			type out struct {
				lease TaskLease
				err   error
			}
			outs := make(chan out, pods)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < pods; i++ {
				peerDB := openPeerSQLDB(t, backing)
				gPeer, _ := OpenSQLGoalStore(ctx, peerDB, dialect, "race-goals", key)
				aPeer, _ := OpenSQLProtocolStore(ctx, peerDB, dialect, "race-attempts", key)
				cPeer, err := OpenSQLCoordinationStore(ctx, peerDB, dialect, "race-tasks", key, gPeer, aPeer)
				if err != nil {
					t.Fatal(err)
				}
				spec := f.spec
				spec.Version = ProtocolVersionV2
				spec.TaskID = task.ID()
				spec.Generation = 1
				spec.Nonce = fmt.Sprintf("cand-%d", i)
				p, _ := NewProtocol(spec)
				req := ClaimRequest{
					GoalID: gid, TaskID: task.ID(), WorkerID: protocolPublic(f.worker).ID(),
					RequestID: spec.Nonce, ProtocolID: p.View().ID, ExpectedGeneration: 0, LeaseUntilHeight: 41,
				}
				sig := Sign(f.owner, ClaimSignatureDomain, req)
				wg.Add(1)
				go func(cs *CoordinationStore, r ClaimRequest, sg []byte, sp ProtocolSpec) {
					defer wg.Done()
					<-start
					l, e := cs.Claim(r, sg, sp, 1)
					outs <- out{l, e}
				}(cPeer, req, sig, spec)
			}
			close(start)
			wg.Wait()
			close(outs)

			winners, stale := 0, 0
			for o := range outs {
				if o.err == nil {
					winners++
					if o.lease.Generation != 1 {
						t.Fatalf("unexpected generation %d", o.lease.Generation)
					}
				} else if errors.Is(o.err, ErrTaskStale) {
					stale++
				} else {
					t.Fatalf("unexpected Claim race error: %v", o.err)
				}
			}
			if winners != 1 || stale != pods-1 {
				t.Fatalf("Claim CAS race: winners=%d stale=%d want 1/%d", winners, stale, pods-1)
			}
			_ = attempts
		})

		t.Run("ConcurrentAccordMultiPodRace", func(t *testing.T) {
			sInit, err := OpenSQLAccordStore(ctx, dbA, dialect, "race-accord", key)
			if err != nil {
				t.Fatal(err)
			}
			fx := newAccordFixture(t)
			rid, err := sInit.Create(fx.spec)
			if err != nil {
				t.Fatal(err)
			}
			sharedCmd, err := sInit.Prepare(rid, fx.sre.pub.ID(), "sre-vote", fx.spec.Scope, "vote", "race-shared", 2)
			if err != nil {
				t.Fatal(err)
			}
			sharedCmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("s")}
			sharedSig, _ := SignAccordCommand(fx.sre.id, sharedCmd)

			competeCmd, err := sInit.Prepare(rid, fx.safety.pub.ID(), "safety-vote", fx.spec.Scope, "vote", "race-compete", 2)
			if err != nil {
				t.Fatal(err)
			}
			competeCmd.Vote = &VotePayload{OptionID: "canary-rollout", Position: BallotApprove, RationaleHash: Hash("c")}
			competeSig, _ := SignAccordCommand(fx.safety.id, competeCmd)

			var wg sync.WaitGroup
			start := make(chan struct{})
			sharedHeads := make(chan string, 8)
			sharedErrs := make(chan error, 8)
			competeErrs := make(chan error, 4)

			for i := 0; i < 8; i++ {
				peerDB := openPeerSQLDB(t, backing)
				pod, _ := OpenSQLAccordStore(ctx, peerDB, dialect, "race-accord", key)
				wg.Add(1)
				go func(st *AccordStore) {
					defer wg.Done()
					<-start
					h, e := st.Apply(rid, sharedCmd, sharedSig, 2)
					sharedHeads <- h
					sharedErrs <- e
				}(pod)
			}
			for i := 0; i < 4; i++ {
				peerDB := openPeerSQLDB(t, backing)
				pod, _ := OpenSQLAccordStore(ctx, peerDB, dialect, "race-accord", key)
				wg.Add(1)
				go func(st *AccordStore) {
					defer wg.Done()
					<-start
					_, e := st.Apply(rid, competeCmd, competeSig, 2)
					competeErrs <- e
				}(pod)
			}
			for i := 0; i < 4; i++ {
				peerDB := openPeerSQLDB(t, backing)
				pod, _ := OpenSQLAccordStore(ctx, peerDB, dialect, "race-accord", key)
				wg.Add(1)
				go func(st *AccordStore) {
					defer wg.Done()
					<-start
					_, _ = st.View(rid)
					_, _ = st.Export(rid)
				}(pod)
			}
			close(start)
			wg.Wait()
			close(sharedHeads)
			close(sharedErrs)
			close(competeErrs)

			sharedOK, competeOK := 0, 0
			var seenHead string
			for err := range sharedErrs {
				h := <-sharedHeads
				if err == nil {
					sharedOK++
					if seenHead == "" {
						seenHead = h
					} else if seenHead != h {
						t.Fatalf("divergent exact retries: %s vs %s", seenHead, h)
					}
				} else if !errors.Is(err, ErrAccordStale) {
					t.Fatalf("unexpected shared error: %v", err)
				}
			}
			for err := range competeErrs {
				if err == nil {
					competeOK++
				} else if !errors.Is(err, ErrAccordStale) {
					t.Fatalf("unexpected competing error: %v", err)
				}
			}
			if !((sharedOK == 8 && competeOK == 0) || (sharedOK == 0 && competeOK == 4)) {
				t.Fatalf("multi-pod CAS race invariant broken: sharedOK=%d competeOK=%d", sharedOK, competeOK)
			}
			v, err := sInit.View(rid)
			if err != nil || len(v.Votes) != 1 {
				t.Fatalf("expected 1 committed vote, got %+v err=%v", v, err)
			}
		})

		t.Run("ConcurrentProtocolAndGoalMultiPodRace", func(t *testing.T) {
			pInit, err := OpenSQLProtocolStore(ctx, dbA, dialect, "race-proto", key)
			if err != nil {
				t.Fatal(err)
			}
			f := newProtocolFixture(t)
			pid, err := pInit.Create(f.spec)
			if err != nil {
				t.Fatal(err)
			}
			admitOwner, err := pInit.Prepare(pid, protocolPublic(f.owner).ID(), "", "", "admit", "admit-owner", 1)
			if err != nil {
				t.Fatal(err)
			}
			sigOwner := Sign(f.owner, "protocol", admitOwner)

			var wg sync.WaitGroup
			start := make(chan struct{})
			pHeads := make(chan string, 8)
			pErrs := make(chan error, 8)
			for i := 0; i < 8; i++ {
				peerDB := openPeerSQLDB(t, backing)
				pod, _ := OpenSQLProtocolStore(ctx, peerDB, dialect, "race-proto", key)
				wg.Add(1)
				go func(st *ProtocolStore) {
					defer wg.Done()
					<-start
					h, e := st.Apply(pid, admitOwner, sigOwner, 1)
					pHeads <- h
					pErrs <- e
				}(pod)
			}
			close(start)
			wg.Wait()
			close(pHeads)
			close(pErrs)

			var firstHead string
			for err := range pErrs {
				h := <-pHeads
				if err != nil {
					t.Fatalf("concurrent protocol exact retry failed: %v", err)
				}
				if firstHead == "" {
					firstHead = h
				} else if firstHead != h {
					t.Fatalf("divergent protocol heads: %s vs %s", firstHead, h)
				}
			}

			// Concurrent GoalStore revisions against same head: exactly 1 succeeds, others get ErrPlanHead!
			gInit, err := OpenSQLGoalStore(ctx, dbA, dialect, "race-goal-rev", key)
			if err != nil {
				t.Fatal(err)
			}
			planner, goal, taskBase := planFixture(t)
			gid, err := gInit.Create(goal)
			if err != nil {
				t.Fatal(err)
			}
			const gPods = 6
			gErrs := make(chan error, gPods)
			gStart := make(chan struct{})
			for i := 0; i < gPods; i++ {
				peerDB := openPeerSQLDB(t, backing)
				pod, _ := OpenSQLGoalStore(ctx, peerDB, dialect, "race-goal-rev", key)
				tsk := taskBase
				tsk.Nonce = fmt.Sprintf("race-task-%d", i)
				rev := PlanRevision{GoalID: gid, Head: gid, Planner: goal.Planners[0].ID(), RequestID: fmt.Sprintf("req-%d", i), Tasks: []TaskSpec{tsk}}
				sig := Sign(planner, PlanSignatureDomain, rev)
				wg.Add(1)
				go func(st *GoalStore, r PlanRevision, sg []byte) {
					defer wg.Done()
					<-gStart
					_, e := st.Apply(r, sg)
					gErrs <- e
				}(pod, rev, sig)
			}
			close(gStart)
			wg.Wait()
			close(gErrs)
			gWin, gStale := 0, 0
			for err := range gErrs {
				if err == nil {
					gWin++
				} else if errors.Is(err, ErrPlanHead) {
					gStale++
				} else {
					t.Fatalf("unexpected GoalStore CAS error: %v", err)
				}
			}
			if gWin != 1 || gStale != gPods-1 {
				t.Fatalf("GoalStore CAS race: winners=%d stale=%d want 1/%d", gWin, gStale, gPods-1)
			}
			planA, err := gInit.View(gid)
			if err != nil || len(planA.Revisions) != 1 {
				t.Fatalf("unexpected plan after race: %+v err=%v", planA, err)
			}
			gPeer, _ := OpenSQLGoalStore(ctx, dbB, dialect, "race-goal-rev", key)
			planB, err := gPeer.View(gid)
			if err != nil || !reflect.DeepEqual(planA, planB) {
				t.Fatalf("Pod A vs Pod B plan diverged: err=%v", err)
			}
		})

		if backing.metrics().nonTxQueries != 0 {
			t.Fatalf("expected 0 non-tx queries across all stress tests, got %d", backing.metrics().nonTxQueries)
		}
	})
}
