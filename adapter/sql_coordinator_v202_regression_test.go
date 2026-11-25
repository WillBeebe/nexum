package adapter

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSQLDriver models both SQLite (database-level write lock acquired on
// UPDATE inside a tx, released on commit/rollback; bare auto-commit SELECT
// holds no persistent lock) and PostgreSQL (per-scope FOR SHARE / FOR UPDATE
// row locks held until commit/rollback).
type fakeSQLRow struct {
	scope          string
	version        int64
	state          string
	generation     int64
	ownerID        string
	tokenSHA256    []byte
	sealedToken    []byte
	admission      string
	checkpointSet  bool
	checkpointGen  int64
	checkpointHead string
	fenceProof     bool
}

type fakeSQLDB struct {
	dialect SQLDialect

	mu   sync.Mutex
	cond *sync.Cond
	rows map[string]*fakeSQLRow

	// SQLite DB-level write lock owner tx (nil when unlocked).
	sqliteWriter *fakeSQLTx

	// Postgres per-scope row locks.
	pgShared map[string]map[*fakeSQLTx]bool
	pgExcl   map[string]*fakeSQLTx
}

func newFakeSQLDB(dialect SQLDialect) *fakeSQLDB {
	d := &fakeSQLDB{
		dialect:  dialect,
		rows:     map[string]*fakeSQLRow{},
		pgShared: map[string]map[*fakeSQLTx]bool{},
		pgExcl:   map[string]*fakeSQLTx{},
	}
	d.cond = sync.NewCond(&d.mu)
	return d
}

func (d *fakeSQLDB) openSQL() *sql.DB {
	db := sql.OpenDB(&fakeSQLConnector{db: d})
	db.SetMaxOpenConns(16)
	return db
}

func (d *fakeSQLDB) acquireSQLiteWrite(tx *fakeSQLTx) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for d.sqliteWriter != nil && d.sqliteWriter != tx {
		d.cond.Wait()
	}
	d.sqliteWriter = tx
}

func (d *fakeSQLDB) acquirePGShare(tx *fakeSQLTx, scope string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for d.pgExcl[scope] != nil && d.pgExcl[scope] != tx {
		d.cond.Wait()
	}
	if d.pgShared[scope] == nil {
		d.pgShared[scope] = map[*fakeSQLTx]bool{}
	}
	d.pgShared[scope][tx] = true
}

func (d *fakeSQLDB) acquirePGUpdate(tx *fakeSQLTx, scope string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		excl := d.pgExcl[scope]
		if excl != nil && excl != tx {
			d.cond.Wait()
			continue
		}
		otherShared := false
		for holder := range d.pgShared[scope] {
			if holder != tx {
				otherShared = true
				break
			}
		}
		if otherShared {
			d.cond.Wait()
			continue
		}
		d.pgExcl[scope] = tx
		return
	}
}

func (d *fakeSQLDB) releaseLocks(tx *fakeSQLTx) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sqliteWriter == tx {
		d.sqliteWriter = nil
	}
	for scope, holders := range d.pgShared {
		delete(holders, tx)
		if len(holders) == 0 {
			delete(d.pgShared, scope)
		}
	}
	for scope, holder := range d.pgExcl {
		if holder == tx {
			delete(d.pgExcl, scope)
		}
	}
	d.cond.Broadcast()
}

type fakeSQLConnector struct{ db *fakeSQLDB }

func (c *fakeSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeSQLConn{db: c.db}, nil
}
func (c *fakeSQLConnector) Driver() driver.Driver { return nil }

type fakeSQLConn struct {
	db *fakeSQLDB
	tx *fakeSQLTx
}

func (c *fakeSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *fakeSQLConn) Close() error                        { return nil }
func (c *fakeSQLConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *fakeSQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	tx := &fakeSQLTx{conn: c, staged: map[string]*fakeSQLRow{}}
	c.tx = tx
	return tx, nil
}

type fakeSQLTx struct {
	conn   *fakeSQLConn
	staged map[string]*fakeSQLRow
}

func (t *fakeSQLTx) Commit() error {
	db := t.conn.db
	db.mu.Lock()
	for k, v := range t.staged {
		cp := *v
		cp.tokenSHA256 = append([]byte(nil), v.tokenSHA256...)
		cp.sealedToken = append([]byte(nil), v.sealedToken...)
		db.rows[k] = &cp
	}
	db.mu.Unlock()
	t.conn.tx = nil
	db.releaseLocks(t)
	return nil
}

func (t *fakeSQLTx) Rollback() error {
	t.conn.tx = nil
	t.conn.db.releaseLocks(t)
	return nil
}

func (c *fakeSQLConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	q := strings.TrimSpace(query)
	switch {
	case strings.HasPrefix(q, "SELECT pg_advisory_xact_lock"):
		return driver.RowsAffected(0), nil
	case strings.HasPrefix(q, "CREATE TABLE"):
		return driver.RowsAffected(0), nil
	case strings.HasPrefix(q, "INSERT INTO nex_fence_leases"):
		if c.db.dialect == DialectSQLite && c.tx != nil {
			c.db.acquireSQLiteWrite(c.tx)
		}
		scope := args[0].Value.(string)
		version := toInt64(args[1].Value)
		state := args[2].Value.(string)
		tokSHA := toBytes(args[3].Value)
		sealed := toBytes(args[4].Value)
		adm := args[5].Value.(string)
		c.db.mu.Lock()
		_, exists := c.db.rows[scope]
		if c.tx != nil {
			if _, ok := c.tx.staged[scope]; ok {
				exists = true
			}
		}
		if !exists {
			row := &fakeSQLRow{
				scope:       scope,
				version:     version,
				state:       state,
				tokenSHA256: tokSHA,
				sealedToken: sealed,
				admission:   adm,
			}
			if c.tx != nil {
				c.tx.staged[scope] = row
			} else {
				c.db.rows[scope] = row
			}
		}
		c.db.mu.Unlock()
		return driver.RowsAffected(1), nil

	case strings.HasPrefix(q, "UPDATE nex_fence_leases SET version = version"):
		if c.db.dialect == DialectSQLite && c.tx != nil {
			c.db.acquireSQLiteWrite(c.tx)
		}
		return driver.RowsAffected(1), nil

	case strings.HasPrefix(q, "UPDATE nex_fence_leases"):
		if c.db.dialect == DialectSQLite && c.tx != nil {
			c.db.acquireSQLiteWrite(c.tx)
		}
		scope := args[11].Value.(string)
		c.db.mu.Lock()
		_, exists := c.db.rows[scope]
		if c.tx != nil {
			if _, ok := c.tx.staged[scope]; ok {
				exists = true
			}
		}
		if !exists {
			c.db.mu.Unlock()
			return driver.RowsAffected(0), nil
		}
		row := &fakeSQLRow{
			scope:          scope,
			version:        toInt64(args[0].Value),
			state:          args[1].Value.(string),
			generation:     toInt64(args[2].Value),
			ownerID:        args[3].Value.(string),
			tokenSHA256:    toBytes(args[4].Value),
			sealedToken:    toBytes(args[5].Value),
			admission:      args[6].Value.(string),
			checkpointSet:  toBool(args[7].Value),
			checkpointGen:  toInt64(args[8].Value),
			checkpointHead: args[9].Value.(string),
			fenceProof:     toBool(args[10].Value),
		}
		if c.tx != nil {
			c.tx.staged[scope] = row
		} else {
			c.db.rows[scope] = row
		}
		c.db.mu.Unlock()
		return driver.RowsAffected(1), nil
	default:
		return nil, fmt.Errorf("unexpected exec: %s", q)
	}
}

func (c *fakeSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	q := strings.TrimSpace(query)
	if !strings.HasPrefix(q, "SELECT version, state") {
		return nil, fmt.Errorf("unexpected query: %s", q)
	}
	scope := args[0].Value.(string)
	if c.db.dialect == DialectPostgres && c.tx != nil {
		if strings.HasSuffix(q, "FOR UPDATE") {
			c.db.acquirePGUpdate(c.tx, scope)
		} else if strings.HasSuffix(q, "FOR SHARE") {
			c.db.acquirePGShare(c.tx, scope)
		}
	}
	c.db.mu.Lock()
	var row *fakeSQLRow
	if c.tx != nil {
		row = c.tx.staged[scope]
	}
	if row == nil {
		row = c.db.rows[scope]
	}
	var cp *fakeSQLRow
	if row != nil {
		v := *row
		v.tokenSHA256 = append([]byte(nil), row.tokenSHA256...)
		v.sealedToken = append([]byte(nil), row.sealedToken...)
		cp = &v
	}
	c.db.mu.Unlock()
	return &fakeSQLRows{dialect: c.db.dialect, row: cp}, nil
}

type fakeSQLRows struct {
	dialect SQLDialect
	row     *fakeSQLRow
	done    bool
}

func (r *fakeSQLRows) Columns() []string {
	return []string{"version", "state", "generation", "owner_id", "token_sha256", "sealed_token", "admission", "checkpoint_set", "checkpoint_gen", "checkpoint_head", "fence_proof"}
}
func (r *fakeSQLRows) Close() error { return nil }
func (r *fakeSQLRows) Next(dest []driver.Value) error {
	if r.done || r.row == nil {
		return io.EOF
	}
	r.done = true
	dest[0] = r.row.version
	dest[1] = r.row.state
	dest[2] = r.row.generation
	dest[3] = r.row.ownerID
	dest[4] = r.row.tokenSHA256
	dest[5] = r.row.sealedToken
	dest[6] = r.row.admission
	if r.dialect == DialectPostgres {
		dest[7] = r.row.checkpointSet
		dest[10] = r.row.fenceProof
	} else {
		if r.row.checkpointSet {
			dest[7] = int64(1)
		} else {
			dest[7] = int64(0)
		}
		if r.row.fenceProof {
			dest[10] = int64(1)
		} else {
			dest[10] = int64(0)
		}
	}
	dest[8] = r.row.checkpointGen
	dest[9] = r.row.checkpointHead
	return nil
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	default:
		panic(fmt.Sprintf("unexpected int %T", v))
	}
}

func toBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	default:
		panic(fmt.Sprintf("unexpected bool %T", v))
	}
}

func toBytes(v any) []byte {
	b := v.([]byte)
	return append([]byte(nil), b...)
}

func newTestAEAD(t *testing.T, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

// Regression test for BUG-03: SQLCoordinator.Authorize on SQLite must hold a
// DB-level immediate write lock across fn() so concurrent StopAndFence +
// Activate across handles/processes cannot overlap with an in-flight callback.
func TestV202SQLiteAuthorizeLinearizability(t *testing.T) {
	ctx := context.Background()
	for _, dialect := range []SQLDialect{DialectPostgres, DialectSQLite} {
		t.Run(string(dialect), func(t *testing.T) {
			key := testKey(t)
			backend := newFakeSQLDB(dialect)
			db := backend.openSQL()
			defer db.Close()

			scope := "scope-" + string(dialect)
			coord1, err := OpenSQLCoordinator(ctx, db, dialect, scope, key)
			if err != nil {
				t.Fatal(err)
			}
			coord2, err := OpenSQLCoordinator(ctx, db, dialect, scope, key)
			if err != nil {
				t.Fatal(err)
			}
			f1, err := coord1.Issue("owner-a")
			if err != nil {
				t.Fatal(err)
			}
			if err := coord1.RecordCheckpoint("head-1"); err != nil {
				t.Fatal(err)
			}

			var gen1InFlight atomic.Bool
			entered := make(chan struct{})
			release := make(chan struct{})
			authDone := make(chan error, 1)
			go func() {
				authDone <- coord1.Authorize(f1, func() error {
					gen1InFlight.Store(true)
					close(entered)
					<-release
					gen1InFlight.Store(false)
					return nil
				})
			}()
			<-entered

			stopDone := make(chan error, 1)
			go func() {
				_, err := coord2.StopAndFence("owner-a")
				stopDone <- err
			}()

			// StopAndFence MUST block while gen-1 callback is in flight.
			select {
			case err := <-stopDone:
				close(release)
				<-authDone
				t.Fatalf("%s: StopAndFence returned prematurely while Authorize callback was in flight (err=%v)", dialect, err)
			case <-time.After(60 * time.Millisecond):
			}

			close(release)
			if err := <-authDone; err != nil {
				t.Fatalf("%s: gen-1 Authorize failed: %v", dialect, err)
			}
			if err := <-stopDone; err != nil {
				t.Fatalf("%s: StopAndFence after release failed: %v", dialect, err)
			}

			// Gen-1 must now be fenced; gen-2 activates cleanly with zero overlap.
			if err := coord1.Authorize(f1, func() error { return nil }); !errors.Is(err, ErrFenced) {
				t.Fatalf("%s: expected ErrFenced for old generation, got %v", dialect, err)
			}
			f2, err := coord2.Activate("owner-b", "head-1")
			if err != nil || f2.Generation != 2 {
				t.Fatalf("%s: Activate failed: f2=%+v err=%v", dialect, f2, err)
			}
			var ranGen2 bool
			if err := coord2.Authorize(f2, func() error {
				if gen1InFlight.Load() {
					t.Errorf("%s: gen-1 still in flight during gen-2 Authorize", dialect)
				}
				ranGen2 = true
				return nil
			}); err != nil || !ranGen2 {
				t.Fatalf("%s: gen-2 Authorize failed: err=%v ran=%v", dialect, err, ranGen2)
			}
		})
	}
}

// Regression test for BUG-04: SQLCoordinator must verify the AES-256-GCM tag
// on every read/write/authorize path (including generation == 0 genesis rows),
// failing closed with ErrCorrupt on forged rows or wrong keys.
func TestV202SQLCoordinatorAEADVerificationAndWrongKeyRefusal(t *testing.T) {
	ctx := context.Background()

	for _, dialect := range []SQLDialect{DialectPostgres, DialectSQLite} {
		t.Run("ForgedRow_"+string(dialect), func(t *testing.T) {
			key := testKey(t)
			backend := newFakeSQLDB(dialect)
			db := backend.openSQL()
			defer db.Close()

			coord, err := OpenSQLCoordinator(ctx, db, dialect, "scope-aead", key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coord.Issue("legit-owner"); err != nil {
				t.Fatal(err)
			}

			forgedToken := make([]byte, 32)
			for i := range forgedToken {
				forgedToken[i] = 0xAA
			}
			forgedSum := sha256.Sum256(forgedToken)
			backend.mu.Lock()
			row := backend.rows["scope-aead"]
			row.ownerID = "attacker"
			row.tokenSHA256 = append([]byte(nil), forgedSum[:]...)
			row.sealedToken = []byte{0x00}
			backend.mu.Unlock()

			forgedFence := Fence{
				Version:    Version,
				Generation: 1,
				Owner:      "attacker",
				Token:      forgedToken,
			}

			ranAuth := false
			authErr := coord.Authorize(forgedFence, func() error {
				ranAuth = true
				return nil
			})
			if !errors.Is(authErr, ErrCorrupt) || ranAuth {
				t.Fatalf("%s: expected Authorize ErrCorrupt without running callback, got err=%v ran=%v", dialect, authErr, ranAuth)
			}

			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			ranAuthTx := false
			authTxErr := coord.AuthorizeTx(ctx, tx, forgedFence, func(*sql.Tx) error {
				ranAuthTx = true
				return nil
			})
			_ = tx.Rollback()
			if !errors.Is(authTxErr, ErrCorrupt) || ranAuthTx {
				t.Fatalf("%s: expected AuthorizeTx ErrCorrupt without running callback, got err=%v ran=%v", dialect, authTxErr, ranAuthTx)
			}

			if _, err := coord.Current(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected Current ErrCorrupt, got %v", dialect, err)
			}
			if err := coord.RecordCheckpoint("bad-head"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected RecordCheckpoint ErrCorrupt, got %v", dialect, err)
			}
			if _, err := coord.StopAndFence("attacker"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected StopAndFence ErrCorrupt, got %v", dialect, err)
			}
		})

		t.Run("GenesisTampering_"+string(dialect), func(t *testing.T) {
			key := testKey(t)
			backend := newFakeSQLDB(dialect)
			db := backend.openSQL()
			defer db.Close()

			coord, err := OpenSQLCoordinator(ctx, db, dialect, "scope-genesis", key)
			if err != nil {
				t.Fatal(err)
			}

			// Corrupt the genesis sealed_token at generation == 0.
			backend.mu.Lock()
			backend.rows["scope-genesis"].sealedToken = []byte{}
			backend.mu.Unlock()

			if _, err := OpenSQLCoordinator(ctx, db, dialect, "scope-genesis", key); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected OpenSQLCoordinator ErrCorrupt on empty genesis sealed_token, got %v", dialect, err)
			}
			if _, err := coord.Issue("owner-a"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected Issue ErrCorrupt on tampered genesis row, got %v", dialect, err)
			}
			if _, err := coord.Current(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected Current ErrCorrupt on tampered genesis row, got %v", dialect, err)
			}
			if _, err := coord.Historical(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected Historical ErrCorrupt on tampered genesis row, got %v", dialect, err)
			}
		})

		t.Run("WrongKeyRefusal_"+string(dialect), func(t *testing.T) {
			goodKey := testKey(t)
			wrongKey := testKey(t)
			backend := newFakeSQLDB(dialect)
			db := backend.openSQL()
			defer db.Close()

			goodCoord, err := OpenSQLCoordinator(ctx, db, dialect, "scope-key", goodKey)
			if err != nil {
				t.Fatal(err)
			}
			// Opening with the wrong key even at generation 0 MUST fail with ErrCorrupt.
			if _, err := OpenSQLCoordinator(ctx, db, dialect, "scope-key", wrongKey); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected OpenSQLCoordinator with wrong key at gen 0 to fail with ErrCorrupt, got %v", dialect, err)
			}

			f1, err := goodCoord.Issue("owner-a")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenSQLCoordinator(ctx, db, dialect, "scope-key", wrongKey); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: expected OpenSQLCoordinator with wrong key at gen 1 to fail with ErrCorrupt, got %v", dialect, err)
			}

			// Even a pre-constructed wrong-key SQLCoordinator handle MUST fail closed
			// on every mutation and authorization call without modifying goodCoord's row.
			wrongCoord := &SQLCoordinator{
				db:      db,
				dialect: dialect,
				scope:   "scope-key",
				aead:    newTestAEAD(t, wrongKey),
			}
			if err := wrongCoord.RecordCheckpoint("hijacked-head"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: wrong-key RecordCheckpoint: expected ErrCorrupt, got %v", dialect, err)
			}
			if err := wrongCoord.StopAdmission(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: wrong-key StopAdmission: expected ErrCorrupt, got %v", dialect, err)
			}
			if _, err := wrongCoord.StopAndFence("owner-a"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: wrong-key StopAndFence: expected ErrCorrupt, got %v", dialect, err)
			}
			if err := wrongCoord.Authorize(f1, func() error { return nil }); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: wrong-key Authorize: expected ErrCorrupt, got %v", dialect, err)
			}
			if _, err := wrongCoord.Current(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: wrong-key Current: expected ErrCorrupt, got %v", dialect, err)
			}

			// Legitimate coordinator state remains completely intact.
			cur, err := goodCoord.Current()
			if err != nil || !FencesEqual(cur, f1) {
				t.Fatalf("%s: goodCoord.Current corrupted: cur=%+v err=%v", dialect, cur, err)
			}
			if err := goodCoord.RecordCheckpoint("good-head"); err != nil {
				t.Fatal(err)
			}
			if _, err := goodCoord.StopAndFence("owner-a"); err != nil {
				t.Fatal(err)
			}
			if _, err := wrongCoord.Activate("attacker", "good-head"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: wrong-key Activate: expected ErrCorrupt, got %v", dialect, err)
			}
			if _, err := wrongCoord.Historical(); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("%s: wrong-key Historical: expected ErrCorrupt, got %v", dialect, err)
			}
		})
	}
}

// Regression test for BUG-39: (*SQLCoordinator)(nil).StopAndFence /
// StopAndFenceContext must return ErrFenced instead of panicking.
func TestV202SQLCoordinatorStopAndFenceNilSafety(t *testing.T) {
	var nilSQL *SQLCoordinator
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("(*SQLCoordinator)(nil) panicked: %v", r)
		}
	}()
	if _, err := nilSQL.StopAndFence("owner-a"); !errors.Is(err, ErrFenced) {
		t.Fatalf("nil StopAndFence: expected ErrFenced, got %v", err)
	}
	if _, err := nilSQL.StopAndFenceContext(context.Background(), "owner-a"); !errors.Is(err, ErrFenced) {
		t.Fatalf("nil StopAndFenceContext: expected ErrFenced, got %v", err)
	}
	if err := nilSQL.ConfirmFenceProof("owner-a"); !errors.Is(err, ErrActivation) {
		t.Fatalf("nil ConfirmFenceProof: expected ErrActivation, got %v", err)
	}
}
