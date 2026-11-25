package adapter

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
)

type SQLDialect string

const (
	DialectPostgres SQLDialect = "postgres"
	DialectSQLite   SQLDialect = "sqlite"
)

const sqlSchemaAdvisoryLock int64 = 784392612

// SQLCoordinator is a distributed fencing authority backed by a shared SQL
// lease table (nex_fence_leases). On PostgreSQL, AuthorizeTx acquires FOR SHARE
// inside the caller's destination transaction while StopAndFence acquires
// FOR UPDATE, ensuring all in-flight destination mutations complete before
// StopAndFence returns and preventing stale hosts from committing afterward.
type SQLCoordinator struct {
	db       *sql.DB
	dialect  SQLDialect
	scope    string
	aead     cipher.AEAD
	sqliteMu sync.Mutex
	cfgMu    sync.RWMutex
	sealer   EpochSealer
}

var _ FenceCoordinator = (*SQLCoordinator)(nil)
var _ HandoffReady = (*SQLCoordinator)(nil)

type sqlLeaseRow struct {
	version        int
	state          string
	generation     uint64
	ownerID        string
	tokenSHA256    []byte
	sealedToken    []byte
	admission      string
	checkpointSet  bool
	checkpointGen  uint64
	checkpointHead string
	fenceProof     bool
}

// OpenSQLCoordinator initializes or opens the nex_fence_leases row for scope.
// key must be 32 random bytes and AEAD-seals the active token at rest.
func OpenSQLCoordinator(ctx context.Context, db *sql.DB, dialect SQLDialect, scope string, key []byte) (*SQLCoordinator, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if db == nil {
		return nil, ErrItem
	}
	if dialect != DialectPostgres && dialect != DialectSQLite {
		return nil, ErrItem
	}
	if err := validateID(scope); err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, ErrStorageKey
	}
	keyCopy := append([]byte(nil), key...)
	block, err := aes.NewCipher(keyCopy)
	clear(keyCopy)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &SQLCoordinator{
		db:      db,
		dialect: dialect,
		scope:   scope,
		aead:    aead,
	}
	if err := c.initSchemaAndRow(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *SQLCoordinator) Scope() string {
	if c == nil {
		return ""
	}
	return c.scope
}

// SetEpochSealer configures an optional destination epoch sealer invoked by
// StopAndFence and ConfirmFenceProof.
func (c *SQLCoordinator) SetEpochSealer(sealer EpochSealer) {
	if c == nil {
		return
	}
	c.cfgMu.Lock()
	defer c.cfgMu.Unlock()
	c.sealer = sealer
}

func (c *SQLCoordinator) currentSealer() EpochSealer {
	if c == nil {
		return nil
	}
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.sealer
}

func (c *SQLCoordinator) initSchemaAndRow(ctx context.Context) error {
	if c.dialect == DialectSQLite {
		c.sqliteMu.Lock()
		defer c.sqliteMu.Unlock()
	}
	genesisSealed, err := c.sealToken(0, "", nil)
	if err != nil {
		return err
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if c.dialect == DialectPostgres {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, sqlSchemaAdvisoryLock); err != nil {
			return err
		}
		const pgDDL = `CREATE TABLE IF NOT EXISTS nex_fence_leases (
			scope TEXT PRIMARY KEY,
			version INTEGER NOT NULL,
			state TEXT NOT NULL,
			generation BIGINT NOT NULL,
			owner_id TEXT NOT NULL,
			token_sha256 BYTEA NOT NULL,
			sealed_token BYTEA NOT NULL,
			admission TEXT NOT NULL,
			checkpoint_set BOOLEAN NOT NULL,
			checkpoint_gen BIGINT NOT NULL,
			checkpoint_head TEXT NOT NULL,
			fence_proof BOOLEAN NOT NULL
		)`
		if _, err := tx.ExecContext(ctx, pgDDL); err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO nex_fence_leases (scope, version, state, generation, owner_id, token_sha256, sealed_token, admission, checkpoint_set, checkpoint_gen, checkpoint_head, fence_proof)
			 VALUES ($1, $2, $3, 0, '', $4, $5, $6, FALSE, 0, '', FALSE)
			 ON CONFLICT (scope) DO NOTHING`,
			c.scope, Version, coordStateUnissued, []byte{}, genesisSealed, coordAdmissionStopped,
		); err != nil {
			return err
		}
	} else {
		const sqliteDDL = `CREATE TABLE IF NOT EXISTS nex_fence_leases (
			scope TEXT PRIMARY KEY,
			version INTEGER NOT NULL,
			state TEXT NOT NULL,
			generation INTEGER NOT NULL,
			owner_id TEXT NOT NULL,
			token_sha256 BLOB NOT NULL,
			sealed_token BLOB NOT NULL,
			admission TEXT NOT NULL,
			checkpoint_set INTEGER NOT NULL,
			checkpoint_gen INTEGER NOT NULL,
			checkpoint_head TEXT NOT NULL,
			fence_proof INTEGER NOT NULL
		)`
		if _, err := tx.ExecContext(ctx, sqliteDDL); err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO nex_fence_leases (scope, version, state, generation, owner_id, token_sha256, sealed_token, admission, checkpoint_set, checkpoint_gen, checkpoint_head, fence_proof)
			 VALUES (?, ?, ?, 0, '', ?, ?, ?, 0, 0, '', 0)
			 ON CONFLICT (scope) DO NOTHING`,
			c.scope, Version, coordStateUnissued, []byte{}, genesisSealed, coordAdmissionStopped,
		); err != nil {
			return err
		}
	}

	row, err := c.selectRowTx(ctx, tx, "")
	if err != nil {
		return err
	}
	if err := c.validateRow(row); err != nil {
		return err
	}
	return tx.Commit()
}

func (c *SQLCoordinator) tokenAAD(generation uint64, ownerID string) []byte {
	return []byte(fmt.Sprintf("%s/sql-fence/v1/%s/%d/%s", vaultHeader, c.scope, generation, ownerID))
}

func (c *SQLCoordinator) sealToken(generation uint64, ownerID string, token []byte) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, ErrCorrupt
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(vaultHeader), nonce...)
	out = c.aead.Seal(out, nonce, token, c.tokenAAD(generation, ownerID))
	return out, nil
}

func (c *SQLCoordinator) openToken(row sqlLeaseRow) ([]byte, error) {
	if c == nil || c.aead == nil {
		return nil, ErrCorrupt
	}
	n := c.aead.NonceSize()
	if len(row.sealedToken) < len(vaultHeader)+n+c.aead.Overhead() {
		return nil, ErrCorrupt
	}
	if string(row.sealedToken[:len(vaultHeader)]) != vaultHeader {
		return nil, ErrVersion
	}
	nonce := row.sealedToken[len(vaultHeader) : len(vaultHeader)+n]
	ct := row.sealedToken[len(vaultHeader)+n:]
	plain, err := c.aead.Open(nil, nonce, ct, c.tokenAAD(row.generation, row.ownerID))
	if err != nil {
		return nil, ErrCorrupt
	}
	if row.generation == 0 {
		if len(plain) != 0 || len(row.tokenSHA256) != 0 {
			clear(plain)
			return nil, ErrCorrupt
		}
		return plain, nil
	}
	if len(plain) != 32 || len(row.tokenSHA256) != 32 {
		clear(plain)
		return nil, ErrCorrupt
	}
	sum := sha256.Sum256(plain)
	if subtle.ConstantTimeCompare(sum[:], row.tokenSHA256) != 1 {
		clear(plain)
		return nil, ErrCorrupt
	}
	return plain, nil
}

func (c *SQLCoordinator) validateRow(row sqlLeaseRow) error {
	if row.version != Version {
		return ErrVersion
	}
	switch row.admission {
	case coordAdmissionOpen, coordAdmissionStopped:
	default:
		return ErrCorrupt
	}
	switch row.state {
	case coordStateUnissued:
		if row.generation != 0 || row.ownerID != "" || len(row.tokenSHA256) != 0 || len(row.sealedToken) == 0 || row.fenceProof || row.admission != coordAdmissionStopped || row.checkpointSet {
			return ErrCorrupt
		}
	case coordStateActive:
		if row.generation == 0 || validateID(row.ownerID) != nil || len(row.tokenSHA256) != 32 || len(row.sealedToken) == 0 || row.fenceProof {
			return ErrCorrupt
		}
	case coordStateFencedUnproven:
		if row.generation == 0 || validateID(row.ownerID) != nil || len(row.tokenSHA256) != 32 || len(row.sealedToken) == 0 || row.fenceProof || row.admission != coordAdmissionStopped {
			return ErrCorrupt
		}
	case coordStateFencedProven:
		if row.generation == 0 || validateID(row.ownerID) != nil || len(row.tokenSHA256) != 32 || len(row.sealedToken) == 0 || !row.fenceProof || row.admission != coordAdmissionStopped {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	if row.checkpointSet {
		if row.checkpointHead == "" || strings.TrimSpace(row.checkpointHead) == "" || row.checkpointGen != row.generation {
			return ErrCorrupt
		}
	}
	plain, err := c.openToken(row)
	if err != nil {
		return err
	}
	clear(plain)
	return nil
}

type sqlRowScanner interface {
	Scan(dest ...any) error
}

func (c *SQLCoordinator) scanRow(s sqlRowScanner) (sqlLeaseRow, error) {
	var (
		row      sqlLeaseRow
		gen      int64
		cpGen    int64
		cpSetInt int
		proofInt int
	)
	if c.dialect == DialectPostgres {
		err := s.Scan(
			&row.version,
			&row.state,
			&gen,
			&row.ownerID,
			&row.tokenSHA256,
			&row.sealedToken,
			&row.admission,
			&row.checkpointSet,
			&cpGen,
			&row.checkpointHead,
			&row.fenceProof,
		)
		if err != nil {
			return sqlLeaseRow{}, err
		}
	} else {
		err := s.Scan(
			&row.version,
			&row.state,
			&gen,
			&row.ownerID,
			&row.tokenSHA256,
			&row.sealedToken,
			&row.admission,
			&cpSetInt,
			&cpGen,
			&row.checkpointHead,
			&proofInt,
		)
		if err != nil {
			return sqlLeaseRow{}, err
		}
		row.checkpointSet = cpSetInt != 0
		row.fenceProof = proofInt != 0
	}
	if gen < 0 || cpGen < 0 {
		return sqlLeaseRow{}, ErrCorrupt
	}
	row.generation = uint64(gen)
	row.checkpointGen = uint64(cpGen)
	return row, nil
}

func (c *SQLCoordinator) selectRowTx(ctx context.Context, tx *sql.Tx, pgLockClause string) (sqlLeaseRow, error) {
	const cols = `SELECT version, state, generation, owner_id, token_sha256, sealed_token, admission, checkpoint_set, checkpoint_gen, checkpoint_head, fence_proof FROM nex_fence_leases WHERE scope = `
	if c.dialect == DialectPostgres {
		q := cols + `$1`
		if pgLockClause != "" {
			q += " " + pgLockClause
		}
		return c.scanRow(tx.QueryRowContext(ctx, q, c.scope))
	}
	return c.scanRow(tx.QueryRowContext(ctx, cols+`?`, c.scope))
}

func (c *SQLCoordinator) selectRowDB(ctx context.Context) (sqlLeaseRow, error) {
	const cols = `SELECT version, state, generation, owner_id, token_sha256, sealed_token, admission, checkpoint_set, checkpoint_gen, checkpoint_head, fence_proof FROM nex_fence_leases WHERE scope = `
	if c.dialect == DialectPostgres {
		return c.scanRow(c.db.QueryRowContext(ctx, cols+`$1`, c.scope))
	}
	return c.scanRow(c.db.QueryRowContext(ctx, cols+`?`, c.scope))
}

func (c *SQLCoordinator) writeRowTx(ctx context.Context, tx *sql.Tx, row sqlLeaseRow) error {
	row.version = Version
	if row.generation > uint64(math.MaxInt64) || row.checkpointGen > uint64(math.MaxInt64) {
		return ErrGenerationOverflow
	}
	if err := c.validateRow(row); err != nil {
		return err
	}
	if c.dialect == DialectPostgres {
		res, err := tx.ExecContext(
			ctx,
			`UPDATE nex_fence_leases
			 SET version = $1, state = $2, generation = $3, owner_id = $4, token_sha256 = $5, sealed_token = $6, admission = $7, checkpoint_set = $8, checkpoint_gen = $9, checkpoint_head = $10, fence_proof = $11
			 WHERE scope = $12`,
			row.version,
			row.state,
			int64(row.generation),
			row.ownerID,
			row.tokenSHA256,
			row.sealedToken,
			row.admission,
			row.checkpointSet,
			int64(row.checkpointGen),
			row.checkpointHead,
			row.fenceProof,
			c.scope,
		)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrFenced
		}
		return nil
	}
	cpInt := 0
	if row.checkpointSet {
		cpInt = 1
	}
	proofInt := 0
	if row.fenceProof {
		proofInt = 1
	}
	res, err := tx.ExecContext(
		ctx,
		`UPDATE nex_fence_leases
		 SET version = ?, state = ?, generation = ?, owner_id = ?, token_sha256 = ?, sealed_token = ?, admission = ?, checkpoint_set = ?, checkpoint_gen = ?, checkpoint_head = ?, fence_proof = ?
		 WHERE scope = ?`,
		row.version,
		row.state,
		int64(row.generation),
		row.ownerID,
		row.tokenSHA256,
		row.sealedToken,
		row.admission,
		cpInt,
		int64(row.checkpointGen),
		row.checkpointHead,
		proofInt,
		c.scope,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrFenced
	}
	return nil
}

func (c *SQLCoordinator) withWriteTx(ctx context.Context, missingErr error, fn func(tx *sql.Tx, row sqlLeaseRow) error) error {
	if c == nil || c.db == nil {
		return missingErr
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.dialect == DialectSQLite {
		c.sqliteMu.Lock()
		defer c.sqliteMu.Unlock()
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if c.dialect == DialectSQLite {
		// Upgrade deferred SQLite transaction to an immediate write lock before
		// reading so concurrent writers serialize cleanly instead of hitting
		// mid-transaction lock-upgrade failure.
		if _, err := tx.ExecContext(ctx, `UPDATE nex_fence_leases SET version = version WHERE scope = ?`, c.scope); err != nil {
			return err
		}
	}
	row, err := c.selectRowTx(ctx, tx, "FOR UPDATE")
	if errors.Is(err, sql.ErrNoRows) {
		return missingErr
	}
	if err != nil {
		return err
	}
	if err := c.validateRow(row); err != nil {
		return err
	}
	if err := fn(tx, row); err != nil {
		return err
	}
	return tx.Commit()
}

func (c *SQLCoordinator) mintRow(prevGen uint64, owner string) (sqlLeaseRow, Fence, error) {
	if prevGen >= uint64(math.MaxInt64) {
		return sqlLeaseRow{}, Fence{}, ErrGenerationOverflow
	}
	nextGen := prevGen + 1
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return sqlLeaseRow{}, Fence{}, err
	}
	sum := sha256.Sum256(token)
	sealed, err := c.sealToken(nextGen, owner, token)
	if err != nil {
		return sqlLeaseRow{}, Fence{}, err
	}
	row := sqlLeaseRow{
		version:     Version,
		state:       coordStateActive,
		generation:  nextGen,
		ownerID:     owner,
		tokenSHA256: append([]byte(nil), sum[:]...),
		sealedToken: sealed,
		admission:   coordAdmissionOpen,
	}
	fence := Fence{
		Version:    Version,
		Generation: nextGen,
		Owner:      owner,
		Token:      token,
	}
	return row, fence, nil
}

func (c *SQLCoordinator) fenceFromRow(row sqlLeaseRow) (Fence, error) {
	token, err := c.openToken(row)
	if err != nil {
		return Fence{}, err
	}
	return Fence{
		Version:    Version,
		Generation: row.generation,
		Owner:      row.ownerID,
		Token:      token,
	}, nil
}

func (c *SQLCoordinator) Current() (Fence, error) {
	if c == nil || c.db == nil {
		return Fence{}, ErrFenced
	}
	if c.dialect == DialectSQLite {
		c.sqliteMu.Lock()
		defer c.sqliteMu.Unlock()
	}
	row, err := c.selectRowDB(context.Background())
	if errors.Is(err, sql.ErrNoRows) {
		return Fence{}, ErrFenced
	}
	if err != nil {
		return Fence{}, err
	}
	if err := c.validateRow(row); err != nil {
		return Fence{}, err
	}
	if row.state != coordStateActive || row.generation == 0 || row.ownerID == "" {
		return Fence{}, ErrFenced
	}
	return c.fenceFromRow(row)
}

func (c *SQLCoordinator) Historical() (Fence, error) {
	if c == nil || c.db == nil {
		return Fence{}, ErrFenced
	}
	if c.dialect == DialectSQLite {
		c.sqliteMu.Lock()
		defer c.sqliteMu.Unlock()
	}
	row, err := c.selectRowDB(context.Background())
	if errors.Is(err, sql.ErrNoRows) {
		return Fence{}, ErrFenced
	}
	if err != nil {
		return Fence{}, err
	}
	if err := c.validateRow(row); err != nil {
		return Fence{}, err
	}
	if row.state != coordStateFencedProven && row.state != coordStateFencedUnproven {
		return Fence{}, ErrFenced
	}
	if row.generation == 0 {
		return Fence{}, ErrFenced
	}
	return c.fenceFromRow(row)
}

func (c *SQLCoordinator) Admission() string {
	if c == nil || c.db == nil {
		return coordAdmissionStopped
	}
	if c.dialect == DialectSQLite {
		c.sqliteMu.Lock()
		defer c.sqliteMu.Unlock()
	}
	row, err := c.selectRowDB(context.Background())
	if err != nil {
		return coordAdmissionStopped
	}
	if c.validateRow(row) != nil {
		return coordAdmissionStopped
	}
	if row.state == coordStateActive && row.admission == coordAdmissionOpen {
		return coordAdmissionOpen
	}
	return coordAdmissionStopped
}

func (c *SQLCoordinator) Issue(owner string) (Fence, error) {
	if err := validateID(owner); err != nil {
		return Fence{}, err
	}
	var out Fence
	err := c.withWriteTx(context.Background(), ErrActivation, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.generation >= 1 {
			if row.state == coordStateActive {
				return ErrConcurrentOwner
			}
			return ErrActivation
		}
		if row.state != coordStateUnissued {
			return ErrActivation
		}
		next, fence, err := c.mintRow(0, owner)
		if err != nil {
			return err
		}
		if err := c.writeRowTx(context.Background(), tx, next); err != nil {
			return err
		}
		out = fence
		return nil
	})
	return out, err
}

func (c *SQLCoordinator) RecordCheckpoint(head string) error {
	if head == "" || strings.TrimSpace(head) == "" {
		return ErrActivation
	}
	return c.withWriteTx(context.Background(), ErrFenced, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.state != coordStateActive || row.generation == 0 {
			return ErrFenced
		}
		row.checkpointSet = true
		row.checkpointGen = row.generation
		row.checkpointHead = head
		return c.writeRowTx(context.Background(), tx, row)
	})
}

func (c *SQLCoordinator) StopAdmission() error {
	return c.withWriteTx(context.Background(), ErrFenced, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.state == coordStateUnissued || row.generation == 0 {
			return ErrFenced
		}
		if row.admission == coordAdmissionStopped {
			return nil
		}
		row.admission = coordAdmissionStopped
		return c.writeRowTx(context.Background(), tx, row)
	})
}

func (c *SQLCoordinator) Resume() error {
	return c.withWriteTx(context.Background(), ErrFenced, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.state != coordStateActive || row.generation == 0 {
			return ErrFenced
		}
		if row.admission != coordAdmissionStopped {
			return ErrActivation
		}
		row.admission = coordAdmissionOpen
		return c.writeRowTx(context.Background(), tx, row)
	})
}

func (c *SQLCoordinator) StopAndFence(owner string) (Fence, error) {
	return c.StopAndFenceContext(context.Background(), owner)
}

func (c *SQLCoordinator) StopAndFenceContext(ctx context.Context, owner string) (Fence, error) {
	if c == nil || c.db == nil {
		return Fence{}, ErrFenced
	}
	if err := validateID(owner); err != nil {
		return Fence{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sealer := c.currentSealer()
	if sealer == nil {
		var out Fence
		err := c.withWriteTx(ctx, ErrFenced, func(tx *sql.Tx, row sqlLeaseRow) error {
			if row.state != coordStateActive || row.generation == 0 || row.ownerID != owner {
				return ErrFenced
			}
			fence, err := c.fenceFromRow(row)
			if err != nil {
				return err
			}
			row.admission = coordAdmissionStopped
			row.state = coordStateFencedProven
			row.fenceProof = true
			if err := c.writeRowTx(ctx, tx, row); err != nil {
				return err
			}
			out = fence
			return nil
		})
		return out, err
	}

	var (
		fencedGen uint64
		out       Fence
	)
	err := c.withWriteTx(ctx, ErrFenced, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.state != coordStateActive || row.generation == 0 || row.ownerID != owner {
			return ErrFenced
		}
		fence, err := c.fenceFromRow(row)
		if err != nil {
			return err
		}
		row.admission = coordAdmissionStopped
		row.state = coordStateFencedUnproven
		row.fenceProof = false
		if err := c.writeRowTx(ctx, tx, row); err != nil {
			return err
		}
		fencedGen = row.generation
		out = fence
		return nil
	})
	if err != nil {
		return Fence{}, err
	}
	if err := sealer.SealFenceEpoch(ctx, c.scope, fencedGen); err != nil {
		return Fence{}, err
	}
	err = c.withWriteTx(ctx, ErrFenced, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.generation != fencedGen || row.ownerID != owner {
			return ErrFenced
		}
		if row.state == coordStateFencedProven && row.fenceProof {
			return nil
		}
		if row.state != coordStateFencedUnproven {
			return ErrFenced
		}
		row.state = coordStateFencedProven
		row.fenceProof = true
		return c.writeRowTx(ctx, tx, row)
	})
	if err != nil {
		return Fence{}, err
	}
	return out, nil
}

// ConfirmFenceProof completes epoch sealing for an unproven fenced generation
// so Activate can proceed once destinations have sealed the old generation.
func (c *SQLCoordinator) ConfirmFenceProof(owner string) error {
	return c.ConfirmFenceProofContext(context.Background(), owner)
}

func (c *SQLCoordinator) ConfirmFenceProofContext(ctx context.Context, owner string) error {
	if c == nil || c.db == nil {
		return ErrActivation
	}
	if err := validateID(owner); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var (
		gen           uint64
		alreadyProven bool
	)
	err := c.withWriteTx(ctx, ErrActivation, func(_ *sql.Tx, row sqlLeaseRow) error {
		if row.generation == 0 || row.ownerID != owner || row.admission != coordAdmissionStopped {
			return ErrActivation
		}
		if row.state == coordStateFencedProven && row.fenceProof {
			alreadyProven = true
			return nil
		}
		if row.state != coordStateFencedUnproven {
			return ErrActivation
		}
		gen = row.generation
		return nil
	})
	if err != nil || alreadyProven {
		return err
	}
	if sealer := c.currentSealer(); sealer != nil {
		if err := sealer.SealFenceEpoch(ctx, c.scope, gen); err != nil {
			return err
		}
	}
	return c.withWriteTx(ctx, ErrActivation, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.generation != gen || row.ownerID != owner || row.admission != coordAdmissionStopped {
			return ErrActivation
		}
		if row.state == coordStateFencedProven && row.fenceProof {
			return nil
		}
		if row.state != coordStateFencedUnproven {
			return ErrActivation
		}
		row.state = coordStateFencedProven
		row.fenceProof = true
		return c.writeRowTx(ctx, tx, row)
	})
}

func (c *SQLCoordinator) DisableFenceProof() error {
	return c.withWriteTx(context.Background(), ErrActivation, func(tx *sql.Tx, row sqlLeaseRow) error {
		row.fenceProof = false
		if row.state == coordStateFencedProven {
			row.state = coordStateFencedUnproven
		}
		return c.writeRowTx(context.Background(), tx, row)
	})
}

func (c *SQLCoordinator) Activate(newOwner, observedHead string) (Fence, error) {
	if err := validateID(newOwner); err != nil {
		return Fence{}, err
	}
	if observedHead == "" {
		return Fence{}, ErrActivation
	}
	var out Fence
	err := c.withWriteTx(context.Background(), ErrActivation, func(tx *sql.Tx, row sqlLeaseRow) error {
		if row.generation == 0 || row.state == coordStateUnissued {
			return ErrActivation
		}
		if row.state != coordStateFencedProven || !row.fenceProof || row.admission != coordAdmissionStopped {
			return ErrActivation
		}
		if !row.checkpointSet || row.checkpointHead == "" || row.checkpointGen != row.generation || observedHead != row.checkpointHead {
			return ErrActivation
		}
		next, fence, err := c.mintRow(row.generation, newOwner)
		if err != nil {
			return err
		}
		if err := c.writeRowTx(context.Background(), tx, next); err != nil {
			return err
		}
		out = fence
		return nil
	})
	return out, err
}

func (c *SQLCoordinator) checkAdmit(row sqlLeaseRow, fence Fence) error {
	if err := c.validateRow(row); err != nil {
		return err
	}
	if row.state != coordStateActive || row.generation == 0 || len(row.tokenSHA256) != 32 {
		return ErrFenced
	}
	sum := sha256.Sum256(fence.Token)
	if fence.Generation != row.generation || fence.Owner != row.ownerID || len(fence.Token) != 32 || subtle.ConstantTimeCompare(sum[:], row.tokenSHA256) != 1 {
		return ErrFenced
	}
	if row.admission != coordAdmissionOpen {
		return ErrAdmissionStopped
	}
	return nil
}

// AuthorizeTx checks fence authority inside the caller's SQL transaction tx.
// On PostgreSQL it locks the scope's lease row FOR SHARE, causing concurrent
// StopAndFence calls (which lock FOR UPDATE) to wait until tx commits or rolls
// back, and rejecting any tx after StopAndFence commits. On SQLite it upgrades
// tx to an immediate write lock on the lease row before checking fence state so
// multi-connection / multi-process SQLite WAL callers achieve the same
// linearizability against StopAndFence without mid-transaction lock-upgrade races.
func (c *SQLCoordinator) AuthorizeTx(ctx context.Context, tx *sql.Tx, fence Fence, fn func(*sql.Tx) error) error {
	if c == nil || tx == nil || fn == nil {
		return ErrItem
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.dialect == DialectSQLite {
		if _, err := tx.ExecContext(ctx, `UPDATE nex_fence_leases SET version = version WHERE scope = ?`, c.scope); err != nil {
			return err
		}
	}
	row, err := c.selectRowTx(ctx, tx, "FOR SHARE")
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFenced
	}
	if err != nil {
		return err
	}
	if err := c.checkAdmit(row, fence); err != nil {
		return err
	}
	return fn(tx)
}

func (c *SQLCoordinator) Authorize(fence Fence, fn func() error) error {
	if c == nil || c.db == nil || fn == nil {
		return ErrItem
	}
	ctx := context.Background()
	if c.dialect == DialectSQLite {
		c.sqliteMu.Lock()
		defer c.sqliteMu.Unlock()
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := c.AuthorizeTx(ctx, tx, fence, func(_ *sql.Tx) error {
		return fn()
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// ReadyForHandoff reports whether this coordinator is fenced with proof,
// stopped for admission, and holding a non-empty checkpoint head for the
// fenced generation.
func (c *SQLCoordinator) ReadyForHandoff() error {
	if c == nil || c.db == nil {
		return ErrActivation
	}
	if c.dialect == DialectSQLite {
		c.sqliteMu.Lock()
		defer c.sqliteMu.Unlock()
	}
	row, err := c.selectRowDB(context.Background())
	if errors.Is(err, sql.ErrNoRows) {
		return ErrActivation
	}
	if err != nil {
		return err
	}
	if err := c.validateRow(row); err != nil {
		return err
	}
	if row.state != coordStateFencedProven || !row.fenceProof || row.admission != coordAdmissionStopped {
		return ErrActivation
	}
	if !row.checkpointSet || row.checkpointHead == "" || row.checkpointGen != row.generation {
		return ErrActivation
	}
	return nil
}
