// Run an end-to-end Nexum v2.1.0 conditional policy-graph demonstration combining:
//  1. Shared encrypted SQL checkpoint stores (Postgres dialect) across two stateless pods
//  2. Upstream ProtocolV2 task execution and portable TaskHandoff proofs
//  3. Sealed-ballot Paillier Accord with CDS94 {0,1} proofs and AccordGate conditional DAG
//  4. Durable adapter.Outbox + adapter.AccordAuthority (KindAccord) with lost-response retry
//  5. Stateless Pod B failover (zero directory copy), homomorphic GMR tally, offline
//     AccordBundle verification, AccordGate recording, DiscoverGoal branch unlocking, and
//     exclusive downstream task Claim + Commit.
//
// Simulated agents use separate Ed25519 keys and an in-process stdlib database/sql/driver
// simulating a shared PostgreSQL instance. Temporary keys and outbox directories are
// discarded on exit.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/WillBeebe/nexum/v2/adapter"
	"github.com/WillBeebe/nexum/v2/nex"
)

const (
	memPGDriverName = "policy_graph_mem_pg"
	accordScope     = "release/policy-graph"
	gateID          = "release-gate"
	outboxTenant    = "release-ops"

	nsGoals        = "policy-graph-goals"
	nsProtocols    = "policy-graph-protocols"
	nsCoordination = "policy-graph-coordination"
	nsAccords      = "policy-graph-accords"
)

// ---------------------------------------------------------------------------
// Self-contained stdlib database/sql/driver simulating shared PostgreSQL
// nex_checkpoints with blocking pg_advisory_xact_lock and atomic transactions.
// ---------------------------------------------------------------------------

var (
	memPGRegistryMu sync.Mutex
	memPGRegistry   = make(map[string]*memPGCluster)
	memPGSeq        atomic.Int64
)

func init() {
	sql.Register(memPGDriverName, &memPGDriver{})
}

type memPGRowKey struct {
	namespace string
	id        string
}

type memPGRow struct {
	version int64
	payload []byte
}

type memPGCluster struct {
	dsn string

	dataMu        sync.Mutex
	schemaCreated bool
	rows          map[memPGRowKey]memPGRow

	lockMu    sync.Mutex
	locks     map[int64]chan struct{}
	lockOwner map[int64]*memPGTx
}

func newMemPGCluster() *memPGCluster {
	dsn := fmt.Sprintf("mem-pg-%d", memPGSeq.Add(1))
	c := &memPGCluster{
		dsn:       dsn,
		rows:      make(map[memPGRowKey]memPGRow),
		locks:     make(map[int64]chan struct{}),
		lockOwner: make(map[int64]*memPGTx),
	}
	memPGRegistryMu.Lock()
	memPGRegistry[dsn] = c
	memPGRegistryMu.Unlock()
	return c
}

func (c *memPGCluster) cleanup() {
	memPGRegistryMu.Lock()
	delete(memPGRegistry, c.dsn)
	memPGRegistryMu.Unlock()
}

func (c *memPGCluster) namespaceRowCounts() map[string]int {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	counts := make(map[string]int)
	for k := range c.rows {
		counts[k.namespace]++
	}
	return counts
}

func (c *memPGCluster) acquireAdvisoryLock(ctx context.Context, tx *memPGTx, key int64) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		c.lockMu.Lock()
		waitCh, held := c.locks[key]
		if !held {
			ch := make(chan struct{})
			c.locks[key] = ch
			c.lockOwner[key] = tx
			tx.locks[key] = ch
			c.lockMu.Unlock()
			return nil
		}
		if c.lockOwner[key] == tx {
			c.lockMu.Unlock()
			return nil
		}
		c.lockMu.Unlock()
		select {
		case <-waitCh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *memPGCluster) releaseTxLocks(tx *memPGTx) {
	c.lockMu.Lock()
	defer c.lockMu.Unlock()
	for key, ch := range tx.locks {
		if c.lockOwner[key] == tx {
			delete(c.locks, key)
			delete(c.lockOwner, key)
			close(ch)
		}
	}
	tx.locks = nil
}

type memPGDriver struct{}

func (d *memPGDriver) Open(dsn string) (driver.Conn, error) {
	memPGRegistryMu.Lock()
	cluster := memPGRegistry[dsn]
	memPGRegistryMu.Unlock()
	if cluster == nil {
		return nil, fmt.Errorf("policy_graph_mem_pg: unknown DSN %q", dsn)
	}
	return &memPGConn{cluster: cluster}, nil
}

type memPGConn struct {
	cluster *memPGCluster
	tx      *memPGTx
}

func (c *memPGConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("policy_graph_mem_pg: use ExecContext/QueryContext")
}

func (c *memPGConn) Close() error {
	if c.tx != nil {
		_ = c.tx.Rollback()
	}
	return nil
}

func (c *memPGConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *memPGConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.tx != nil {
		return nil, errors.New("policy_graph_mem_pg: nested transaction on same connection")
	}
	tx := &memPGTx{
		conn:       c,
		locks:      make(map[int64]chan struct{}),
		stagedRows: make(map[memPGRowKey]memPGRow),
	}
	c.tx = tx
	return tx, nil
}

type memPGTx struct {
	conn                *memPGConn
	locks               map[int64]chan struct{}
	stagedSchemaCreated bool
	stagedRows          map[memPGRowKey]memPGRow
	done                bool
}

func (tx *memPGTx) Commit() error {
	if tx.done {
		return errors.New("policy_graph_mem_pg: transaction already finished")
	}
	tx.done = true
	cl := tx.conn.cluster
	defer func() {
		cl.releaseTxLocks(tx)
		tx.conn.tx = nil
	}()
	cl.dataMu.Lock()
	if tx.stagedSchemaCreated {
		cl.schemaCreated = true
	}
	for k, row := range tx.stagedRows {
		cl.rows[k] = memPGRow{version: row.version, payload: bytes.Clone(row.payload)}
	}
	cl.dataMu.Unlock()
	return nil
}

func (tx *memPGTx) Rollback() error {
	if tx.done {
		return nil
	}
	tx.done = true
	tx.conn.cluster.releaseTxLocks(tx)
	tx.conn.tx = nil
	return nil
}

func normSQL(q string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(q)), " ")
}

func (c *memPGConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.tx == nil {
		return nil, errors.New("policy_graph_mem_pg: write/lock requires active transaction")
	}
	norm := normSQL(query)
	switch {
	case strings.HasPrefix(norm, "SELECT pg_advisory_xact_lock("):
		if len(args) != 1 {
			return nil, errors.New("policy_graph_mem_pg: pg_advisory_xact_lock expects 1 arg")
		}
		key, ok := args[0].Value.(int64)
		if !ok {
			return nil, fmt.Errorf("policy_graph_mem_pg: lock key type %T", args[0].Value)
		}
		if err := c.cluster.acquireAdvisoryLock(ctx, c.tx, key); err != nil {
			return nil, err
		}
		return driver.RowsAffected(0), nil

	case strings.HasPrefix(norm, "CREATE TABLE IF NOT EXISTS nex_checkpoints"):
		c.tx.stagedSchemaCreated = true
		return driver.RowsAffected(0), nil

	case strings.HasPrefix(norm, "INSERT INTO nex_checkpoints"):
		if len(args) != 3 {
			return nil, errors.New("policy_graph_mem_pg: upsert expects 3 args")
		}
		ns, ok1 := args[0].Value.(string)
		id, ok2 := args[1].Value.(string)
		payload, ok3 := args[2].Value.([]byte)
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("policy_graph_mem_pg: invalid upsert arg types")
		}
		c.cluster.dataMu.Lock()
		if !c.cluster.schemaCreated && !c.tx.stagedSchemaCreated {
			c.cluster.dataMu.Unlock()
			return nil, errors.New("policy_graph_mem_pg: nex_checkpoints table does not exist")
		}
		key := memPGRowKey{namespace: ns, id: id}
		cur, exists := c.cluster.rows[key]
		c.cluster.dataMu.Unlock()
		if staged, ok := c.tx.stagedRows[key]; ok {
			cur, exists = staged, true
		}
		nextVer := int64(1)
		if exists {
			nextVer = cur.version + 1
		}
		c.tx.stagedRows[key] = memPGRow{version: nextVer, payload: bytes.Clone(payload)}
		return driver.RowsAffected(1), nil

	default:
		return nil, fmt.Errorf("policy_graph_mem_pg: unsupported Exec %q", norm)
	}
}

func (c *memPGConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(args) != 2 {
		return nil, errors.New("policy_graph_mem_pg: query expects 2 args")
	}
	ns, ok1 := args[0].Value.(string)
	id, ok2 := args[1].Value.(string)
	if !ok1 || !ok2 {
		return nil, errors.New("policy_graph_mem_pg: query args must be strings")
	}
	key := memPGRowKey{namespace: ns, id: id}
	c.cluster.dataMu.Lock()
	if !c.cluster.schemaCreated && (c.tx == nil || !c.tx.stagedSchemaCreated) {
		c.cluster.dataMu.Unlock()
		return nil, errors.New("policy_graph_mem_pg: nex_checkpoints table does not exist")
	}
	row, exists := c.cluster.rows[key]
	c.cluster.dataMu.Unlock()
	if c.tx != nil {
		if staged, ok := c.tx.stagedRows[key]; ok {
			row, exists = staged, true
		}
	}

	norm := normSQL(query)
	switch {
	case strings.HasPrefix(norm, "SELECT 1 FROM nex_checkpoints WHERE"):
		if !exists {
			return &memPGRows{cols: []string{"one"}}, nil
		}
		return &memPGRows{cols: []string{"one"}, data: [][]driver.Value{{int64(1)}}}, nil
	case strings.HasPrefix(norm, "SELECT version FROM nex_checkpoints WHERE"):
		if !exists {
			return &memPGRows{cols: []string{"version"}}, nil
		}
		return &memPGRows{cols: []string{"version"}, data: [][]driver.Value{{row.version}}}, nil
	case strings.HasPrefix(norm, "SELECT version, payload FROM nex_checkpoints WHERE"):
		if !exists {
			return &memPGRows{cols: []string{"version", "payload"}}, nil
		}
		return &memPGRows{cols: []string{"version", "payload"}, data: [][]driver.Value{{row.version, bytes.Clone(row.payload)}}}, nil
	default:
		return nil, fmt.Errorf("policy_graph_mem_pg: unsupported Query %q", norm)
	}
}

type memPGRows struct {
	cols []string
	data [][]driver.Value
	idx  int
}

func (r *memPGRows) Columns() []string { return r.cols }
func (r *memPGRows) Close() error      { return nil }
func (r *memPGRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.idx])
	r.idx++
	return nil
}

// ---------------------------------------------------------------------------
// Stateless pod bundle opening all four encrypted SQL checkpoint stores.
// ---------------------------------------------------------------------------

type podStores struct {
	db       *sql.DB
	goals    *nex.GoalStore
	attempts *nex.ProtocolStore
	tasks    *nex.CoordinationStore
	accords  *nex.AccordStore
}

func openPodStores(ctx context.Context, dsn string, key []byte) (*podStores, error) {
	db, err := sql.Open(memPGDriverName, dsn)
	if err != nil {
		return nil, err
	}
	goals, err := nex.OpenSQLGoalStore(ctx, db, nex.SQLDialectPostgres, nsGoals, key)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	attempts, err := nex.OpenSQLProtocolStore(ctx, db, nex.SQLDialectPostgres, nsProtocols, key)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	tasks, err := nex.OpenSQLCoordinationStore(ctx, db, nex.SQLDialectPostgres, nsCoordination, key, goals, attempts)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	accords, err := nex.OpenSQLAccordStore(ctx, db, nex.SQLDialectPostgres, nsAccords, key)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &podStores{
		db:       db,
		goals:    goals,
		attempts: attempts,
		tasks:    tasks,
		accords:  accords,
	}, nil
}

func (p *podStores) close() error {
	if p == nil || p.db == nil {
		return nil
	}
	return p.db.Close()
}

// ---------------------------------------------------------------------------
// Domain helpers: actors, artifacts, upstream & downstream ProtocolV2 tasks.
// ---------------------------------------------------------------------------

type actor struct {
	identity nex.Identity
	public   nex.Public
}

func newActor() (actor, error) {
	id, err := nex.NewIdentity()
	if err != nil {
		return actor{}, err
	}
	pub, err := id.Public()
	return actor{identity: id, public: pub}, err
}

type artifact struct {
	name, content, mediaType string
}

func (a artifact) named() nex.NamedArtifact {
	digest := sha256.Sum256([]byte(a.content))
	return nex.NamedArtifact{
		Name: a.name,
		Ref: nex.ArtifactRef{
			Digest:    hex.EncodeToString(digest[:]),
			Size:      uint64(len(a.content)),
			MediaType: a.mediaType,
		},
	}
}

type taskAttempt struct {
	lease     nex.TaskLease
	spec      nex.ProtocolSpec
	worker    actor
	claim     nex.ClaimRequest
	signature []byte
}

func buildAttemptClaim(goalID string, task nex.TaskSpec, owner, worker, witness actor, height uint64) (nex.ProtocolSpec, nex.ClaimRequest, []byte, error) {
	grant := func(id string, who actor, perms ...nex.ProtocolPermission) nex.RoleGrant {
		return nex.RoleGrant{
			ID:                 id,
			Actor:              who.public.ID(),
			Label:              id,
			Scope:              task.Scope,
			Permissions:        perms,
			ExpiresAtHeight:    height + 12,
			LimitsHash:         nex.Hash(task.Scope + ":" + id),
			EvidenceObligation: task.AcceptanceHash,
		}
	}
	spec := nex.ProtocolSpec{
		Version:           nex.ProtocolVersionV2,
		TaskID:            task.ID(),
		Generation:        1,
		Nonce:             task.Nonce + "-gen-1",
		Purpose:           task.Purpose,
		IntendedOutcome:   task.Purpose,
		Scope:             task.Scope,
		SpecificationHash: task.SpecificationHash,
		AcceptanceHash:    task.AcceptanceHash,
		FailurePolicyHash: task.FailurePolicyHash,
		Initiator:         owner.public.ID(),
		Participants:      []nex.Public{owner.public, worker.public, witness.public},
		Roles: []nex.RoleGrant{
			grant("owner", owner, nex.PermitCommit, nex.PermitDecide, nex.PermitReturn),
			grant("worker", worker, nex.PermitWork, nex.PermitReturn),
			grant("witness", witness, nex.PermitReview),
		},
		WorkByHeight:      height + 8,
		ReturnByHeight:    height + 12,
		RequiredWitnesses: []string{witness.public.ID()},
		DissentPolicy:     "block",
		MaxEvents:         16,
		Return: nex.ReturnRequirements{
			SuccessArtifacts:   slices.Clone(task.Outputs),
			AllowedDisposition: []string{"continue", "retry"},
		},
	}
	p, err := nex.NewProtocol(spec)
	if err != nil {
		return nex.ProtocolSpec{}, nex.ClaimRequest{}, nil, err
	}
	req := nex.ClaimRequest{
		GoalID:             goalID,
		TaskID:             task.ID(),
		WorkerID:           worker.public.ID(),
		RequestID:          spec.Nonce,
		ProtocolID:         p.View().ID,
		ExpectedGeneration: 0,
		LeaseUntilHeight:   height + 14,
	}
	sig := nex.Sign(owner.identity, nex.ClaimSignatureDomain, req)
	return spec, req, sig, nil
}

func runTaskProtocol(
	attempts *nex.ProtocolStore,
	owner, witness actor,
	a taskAttempt,
	height uint64,
	inputs []nex.NamedArtifact,
	out artifact,
	review func(string) error,
) (committedPhase string, finalHead string, err error) {
	apply := func(who actor, grant, action string, h uint64, fill func(*nex.ProtocolCommand)) (string, error) {
		scope := a.spec.Scope
		if action == "admit" {
			scope = ""
		}
		cmd, err := attempts.Prepare(a.lease.ProtocolID, who.public.ID(), grant, scope, action, action+"-"+who.public.ID()[:8], h)
		if err != nil {
			return "", err
		}
		if fill != nil {
			fill(&cmd)
		}
		return attempts.Apply(a.lease.ProtocolID, cmd, nex.Sign(who.identity, "protocol", cmd), h)
	}
	for _, participant := range []actor{owner, a.worker, witness} {
		if _, err := apply(participant, "", "admit", height, nil); err != nil {
			return "", "", err
		}
	}
	if _, err := apply(owner, "owner", "commit", height, nil); err != nil {
		return "", "", err
	}
	committedView, err := attempts.View(a.lease.ProtocolID)
	if err != nil {
		return "", "", err
	}
	committedPhase = committedView.Phase

	named := out.named()
	report := nex.WorkReport{
		Outcome:    nex.WorkCompleted,
		Stage:      "produce " + out.name,
		ReasonHash: nex.Hash(a.spec.Purpose),
		Evidence:   []string{named.Ref.Digest},
		Manifest: &nex.EvidenceManifest{
			MethodHash: nex.Hash("local fixture"),
			Inputs:     inputs,
			Outputs:    []nex.NamedArtifact{named},
		},
	}
	if _, err := apply(a.worker, "worker", "report", height, func(cmd *nex.ProtocolCommand) {
		cmd.Report = &report
	}); err != nil {
		return committedPhase, "", err
	}
	if review == nil {
		// Required witness unavailable at ReturnByHeight: close honestly as incomplete
		// while preserving the worker's partial observation artifact.
		finalHead, err = apply(owner, "owner", "incomplete", a.spec.ReturnByHeight, func(cmd *nex.ProtocolCommand) {
			cmd.Incomplete = &nex.IncompleteReturn{
				ReasonHash: nex.Hash("required safety witness did not respond before deadline"),
				Evidence:   report.Evidence,
				Artifacts:  []nex.NamedArtifact{named},
			}
		})
		return committedPhase, finalHead, err
	}
	if err := named.Ref.Verify(strings.NewReader(out.content)); err != nil {
		return committedPhase, "", err
	}
	if err := review(out.content); err != nil {
		return committedPhase, "", err
	}
	if _, err := apply(witness, "witness", "review", height, func(cmd *nex.ProtocolCommand) {
		cmd.Review = &nex.WitnessReview{
			ReportHash:     nex.Hash(report),
			AssessmentHash: nex.Hash("independent fixture check passed"),
		}
	}); err != nil {
		return committedPhase, "", err
	}
	res := &nex.Resolution{
		ReportHash: nex.Hash(report),
		Outcome:    "accept",
		ReasonHash: nex.Hash("witness confirmed output"),
	}
	if _, err := apply(owner, "owner", "resolve", height, func(cmd *nex.ProtocolCommand) {
		cmd.Resolution = res
	}); err != nil {
		return committedPhase, "", err
	}
	view, err := attempts.View(a.lease.ProtocolID)
	if err != nil {
		return committedPhase, "", err
	}
	finalHead, err = apply(a.worker, "worker", "return", height, func(cmd *nex.ProtocolCommand) {
		cmd.Return = &nex.ReturnManifest{
			ResolutionHash:  nex.Hash(res),
			ReviewsHash:     nex.Hash(view.Reviews),
			Evidence:        report.Evidence,
			Artifacts:       []nex.ReturnArtifact{{ID: named.Name, Commitment: named.Ref.Digest, ReuseRestrictions: "Verify bytes before rollout"}},
			Uncertainty:     "Review covers synthetic staging fixtures only",
			SafeAssumptions: []string{"No deployment was attempted"},
			Disposition:     "continue",
		}
	})
	return committedPhase, finalHead, err
}

// ---------------------------------------------------------------------------
// Deterministic structured report & execution driver.
// ---------------------------------------------------------------------------

type optionSummary struct {
	OptionID                string   `json:"option_id"`
	GuardPassed             bool     `json:"guard_passed"`
	ApproveCount            uint64   `json:"approve_count"`
	ApproveWeight           uint64   `json:"approve_weight"`
	DissentCount            uint64   `json:"dissent_count"`
	DissentWeight           uint64   `json:"dissent_weight"`
	VetoEffective           bool     `json:"veto_effective"`
	Eligible                bool     `json:"eligible"`
	DisqualificationReasons []string `json:"disqualification_reasons,omitempty"`
}

type gateTaskSummary struct {
	TaskName             string `json:"task_name"`
	StatusBeforeGate     string `json:"status_before_gate"`
	GatesReadyBefore     bool   `json:"gates_ready_before"`
	GatesReadyAfter      bool   `json:"gates_ready_after"`
	GatesMismatchAfter   bool   `json:"gates_mismatch_after"`
	DependenciesReady    bool   `json:"dependencies_ready"`
	DependenciesMismatch bool   `json:"dependencies_mismatch"`
}

type report struct {
	Example                     string                     `json:"example"`
	SQLDialect                  nex.SQLDialect             `json:"sql_dialect"`
	SQLNamespaces               map[string]int             `json:"sql_namespaces"`
	ZeroDirectoryCopyFailover   bool                       `json:"zero_directory_copy_failover"`
	UpstreamOutcomes            map[string]nex.TaskOutcome `json:"upstream_outcomes"`
	BallotPrivacy               nex.BallotPrivacy          `json:"ballot_privacy"`
	BallotMode                  nex.BallotMode             `json:"ballot_mode"`
	SealedBallotsRecorded       int                        `json:"sealed_ballots_recorded"`
	PlaintextVotesExposed       int                        `json:"plaintext_votes_exposed"`
	OpaqueCiphertextsVerified   int                        `json:"opaque_ciphertexts_verified"`
	OutboxLostResponseRecovered bool                       `json:"outbox_lost_response_recovered"`
	OutboxRecoveryAttempts      int                        `json:"outbox_recovery_attempts"`
	OutboxUnresolvedCount       int                        `json:"outbox_unresolved_count"`
	AccordPhase                 nex.AccordPhase            `json:"accord_phase"`
	WinningOption               string                     `json:"winning_option"`
	ParticipatingCount          uint64                     `json:"participating_count"`
	ParticipatingWeight         uint64                     `json:"participating_weight"`
	Options                     []optionSummary            `json:"options"`
	OfflineBundleVerified       bool                       `json:"offline_bundle_verified"`
	OfflineGoalPlanVerified     bool                       `json:"offline_goal_plan_verified"`
	GateRecordedPhase           nex.AccordPhase            `json:"gate_recorded_phase"`
	GateWinningOption           string                     `json:"gate_winning_option"`
	GateRetryIdempotent         bool                       `json:"gate_retry_idempotent"`
	DownstreamTasks             []gateTaskSummary          `json:"downstream_tasks"`
	FullRolloutClaimRefused     bool                       `json:"full_rollout_claim_refused"`
	HoldRemediationClaimRefused bool                       `json:"hold_remediation_claim_refused"`
	CanaryTaskClaimed           bool                       `json:"canary_task_claimed"`
	CanaryCommittedPhase        string                     `json:"canary_committed_phase"`
	CanaryFinalOutcome          nex.TaskOutcome            `json:"canary_final_outcome"`
}

type runArtifacts struct {
	report     report
	bundleJSON []byte
	accordID   string
	finalHead  string
	planJSON   []byte
	goalID     string
	planHead   string
}

func main() {
	dir, err := os.MkdirTemp("", "nex-policy-graph-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := func() error {
		defer os.RemoveAll(dir)
		return runTo(dir, os.Stdout)
	}(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runTo(dir string, out io.Writer) error {
	res, err := execute(dir)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(res.report)
}

func execute(dir string) (runArtifacts, error) {
	ctx := context.Background()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return runArtifacts{}, err
	}

	// Distinct Ed25519 identities for planning, witness review, sealed deliberation,
	// independent homomorphic tallying, and outbox response authentication.
	planner, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	witness, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	release, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	sre, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	safety, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	security, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	tallyAuthority, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	respAuthority, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}

	// Pillar 1: Shared encrypted SQL checkpoint cluster (Postgres dialect) backing Pod A & Pod B.
	cluster := newMemPGCluster()
	defer cluster.cleanup()

	podA, err := openPodStores(ctx, cluster.dsn, key)
	if err != nil {
		return runArtifacts{}, err
	}
	defer podA.close()

	// Pillar 2: Pod A creates the GoalSpec and runs three upstream ProtocolV2 tasks,
	// exporting portable TaskHandoff proofs (patch=accepted, window=accepted, safety=incomplete).
	goalID, err := podA.goals.Create(nex.GoalSpec{
		Nonce:                "release-policy-graph-v210",
		Purpose:              "Gate mutually exclusive rollout branches on sealed deliberation over verified handoffs",
		ConstraintsHash:      nex.Hash("Shared encrypted SQL checkpoints; no live deployment side effects"),
		CompletionPolicyHash: nex.Hash("Unlock exactly one downstream branch from a verified sealed AccordGate"),
		Planners:             []nex.Public{planner.public},
	})
	if err != nil {
		return runArtifacts{}, err
	}

	makeUpstreamTask := func(name, purpose, acceptance, output string) nex.TaskSpec {
		return nex.TaskSpec{
			GoalID:            goalID,
			Nonce:             name,
			Purpose:           purpose,
			Scope:             "release/" + name,
			Authority:         planner.public,
			SpecificationHash: nex.Hash(purpose),
			AcceptanceHash:    nex.Hash(acceptance),
			FailurePolicyHash: nex.Hash("Preserve partial observation when required witness is absent"),
			Outputs:           []string{output},
		}
	}

	patchTask := makeUpstreamTask("patch", "Prepare retry configuration", "Retry limit is between 1 and 3", "config")
	windowTask := makeUpstreamTask("window", "Confirm release maintenance window", "Schedules agree on Monday 16:00 UTC", "window")
	safetyTask := makeUpstreamTask("safety", "Verify staging rollback snapshot", "Independent witness confirms rollback readiness", "observation")

	rev1 := nex.PlanRevision{
		GoalID:    goalID,
		Head:      goalID,
		Planner:   planner.public.ID(),
		RequestID: "plan-upstream-1",
		Tasks:     []nex.TaskSpec{patchTask, windowTask, safetyTask},
	}
	planHead1, err := podA.goals.Apply(rev1, nex.Sign(planner.identity, nex.PlanSignatureDomain, rev1))
	if err != nil {
		return runArtifacts{}, err
	}

	const upstreamHeight = 1
	claimOn := func(stores *podStores, task nex.TaskSpec, worker, wit actor, h uint64) (taskAttempt, error) {
		spec, req, sig, err := buildAttemptClaim(goalID, task, planner, worker, wit, h)
		if err != nil {
			return taskAttempt{}, err
		}
		lease, err := stores.tasks.Claim(req, sig, spec, h)
		if err != nil {
			return taskAttempt{}, err
		}
		return taskAttempt{lease: lease, spec: spec, worker: worker, claim: req, signature: sig}, nil
	}

	patchWorker, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	windowWorker, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}
	safetyWorker, err := newActor()
	if err != nil {
		return runArtifacts{}, err
	}

	patchAttempt, err := claimOn(podA, patchTask, patchWorker, witness, upstreamHeight)
	if err != nil {
		return runArtifacts{}, err
	}
	windowAttempt, err := claimOn(podA, windowTask, windowWorker, witness, upstreamHeight)
	if err != nil {
		return runArtifacts{}, err
	}
	safetyAttempt, err := claimOn(podA, safetyTask, safetyWorker, witness, upstreamHeight)
	if err != nil {
		return runArtifacts{}, err
	}

	configArt := artifact{"config", `{"max_attempts":3}`, "application/json"}
	windowArt := artifact{"window", "Monday 16:00 UTC", "text/plain"}
	safetyArt := artifact{"observation", "No rollback snapshot is referenced in staging", "text/plain"}

	checkConfig := func(body string) error {
		var cfg struct {
			MaxAttempts int `json:"max_attempts"`
		}
		if err := json.Unmarshal([]byte(body), &cfg); err != nil {
			return err
		}
		if cfg.MaxAttempts < 1 || cfg.MaxAttempts > 3 {
			return errors.New("retry limit outside reviewed range")
		}
		return nil
	}
	checkWindow := func(body string) error {
		if body != "Monday 16:00 UTC" {
			return errors.New("window outside shared schedule")
		}
		return nil
	}

	type upstreamJob struct {
		name    string
		task    nex.TaskSpec
		attempt taskAttempt
		out     artifact
		review  func(string) error
	}
	jobs := []upstreamJob{
		{"patch", patchTask, patchAttempt, configArt, checkConfig},
		{"window", windowTask, windowAttempt, windowArt, checkWindow},
		{"safety", safetyTask, safetyAttempt, safetyArt, nil},
	}

	type jobResult struct {
		index int
		head  string
		err   error
	}
	doneCh := make(chan jobResult, len(jobs))
	for i, job := range jobs {
		go func() {
			_, head, err := runTaskProtocol(podA.attempts, planner, witness, job.attempt, upstreamHeight+1, nil, job.out, job.review)
			doneCh <- jobResult{index: i, head: head, err: err}
		}()
	}

	type verifiedUpstream struct {
		name        string
		task        nex.TaskSpec
		result      nex.TaskResult
		out         artifact
		handoffJSON []byte
	}
	var upstreamDone [3]verifiedUpstream
	for range jobs {
		jr := <-doneCh
		job := jobs[jr.index]
		if jr.err != nil {
			return runArtifacts{}, fmt.Errorf("upstream task %q: %w", job.name, jr.err)
		}
		res, err := podA.tasks.Finalize(job.attempt.lease, jr.head, safetyAttempt.spec.ReturnByHeight)
		if err != nil {
			return runArtifacts{}, fmt.Errorf("finalize %q: %w", job.name, err)
		}
		handoff, err := podA.tasks.ExportHandoff(job.attempt.claim, job.attempt.signature)
		if err != nil {
			return runArtifacts{}, fmt.Errorf("export handoff %q: %w", job.name, err)
		}
		wire, err := json.Marshal(handoff)
		if err != nil {
			return runArtifacts{}, err
		}
		upstreamDone[jr.index] = verifiedUpstream{
			name:        job.name,
			task:        job.task,
			result:      res,
			out:         job.out,
			handoffJSON: wire,
		}
	}
	patchVerified, windowVerified, safetyVerified := upstreamDone[0], upstreamDone[1], upstreamDone[2]

	// Pillar 3: Pod A creates a Sealed-Ballot Paillier Accord (BallotPrivacySealedPaillier +
	// BallotSingleChoice + mandatory safety role + 3 competing options) and registers a
	// conditional DAG PlanRevision with an AccordGate gating 3 mutually exclusive downstream tasks.
	tallyKey, err := nex.NewSealedTallyKey(2048)
	if err != nil {
		return runArtifacts{}, err
	}

	fullBinding := nex.OptionBinding{
		Kind:           nex.BindingDisposition,
		Disposition:    "continue",
		ActionHash:     nex.Hash("Execute full production rollout across all regions"),
		ParametersHash: nex.Hash(`{"mode":"full","percent":100}`),
	}
	canaryBinding := nex.OptionBinding{
		Kind:           nex.BindingDisposition,
		Disposition:    "continue",
		ActionHash:     nex.Hash("Execute bounded 5% canary rollout with heightened rollback monitoring"),
		ParametersHash: nex.Hash(`{"mode":"canary","percent":5}`),
	}
	holdBinding := nex.OptionBinding{
		Kind:           nex.BindingDisposition,
		Disposition:    "hold",
		ActionHash:     nex.Hash("Hold Monday 16:00 UTC release and remediate staging rollback snapshot"),
		ParametersHash: nex.Hash(`{"mode":"hold","reason":"missing_rollback_snapshot"}`),
	}

	accordSpec := nex.AccordSpec{
		Version:    nex.AccordVersion,
		Nonce:      "release-policy-gate-v210",
		Purpose:    "Sealed single-choice release governance Accord gating conditional DAG branches",
		Scope:      accordScope,
		PolicyHash: nex.Hash("Full rollout requires accepted safety handoff; canary requires mandatory safety & SRE sealed approval"),
		Participants: []nex.Public{
			planner.public, witness.public, release.public, sre.public, safety.public, security.public, tallyAuthority.public,
		},
		Roles: []nex.AccordRoleGrant{
			{
				ID: "attester", Actor: planner.public.ID(), Scope: accordScope,
				Permissions: []nex.AccordPermission{nex.AccordPermitAttest}, ExpiresAtHeight: 15,
				LimitsHash: nex.Hash("independent upstream handoff attester"),
			},
			{
				ID: "safety-veto", Actor: witness.public.ID(), Scope: accordScope,
				DomainRoles: []string{"safety-gate"}, Permissions: []nex.AccordPermission{nex.AccordPermitVeto},
				ExpiresAtHeight: 15, LimitsHash: nex.Hash("independent safety witness bounded evidence-cited veto"),
			},
			{
				ID: "tally-resolver", Actor: tallyAuthority.public.ID(), Scope: accordScope,
				Permissions: []nex.AccordPermission{nex.AccordPermitResolve}, ExpiresAtHeight: 20,
				LimitsHash: nex.Hash("independent Paillier tally authority and deterministic resolver"),
			},
			{
				ID: "release-voter", Actor: release.public.ID(), Scope: accordScope,
				DomainRoles: []string{"release"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("release engineering sealed ballot"),
			},
			{
				ID: "sre-voter", Actor: sre.public.ID(), Scope: accordScope,
				DomainRoles: []string{"sre"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("sre operational readiness sealed ballot"),
			},
			{
				ID: "safety-reviewer", Actor: safety.public.ID(), Scope: accordScope,
				DomainRoles: []string{"safety"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote},
				Weight: 3, ExpiresAtHeight: 15, LimitsHash: nex.Hash("safety sealed ballot"),
			},
			{
				ID: "security-reviewer", Actor: security.public.ID(), Scope: accordScope,
				DomainRoles: []string{"security"}, Permissions: []nex.AccordPermission{nex.AccordPermitVote},
				Weight: 2, ExpiresAtHeight: 15, LimitsHash: nex.Hash("security sealed ballot"),
			},
		},
		Evidence: []nex.EvidenceSlot{
			{
				ID: "patch", Kind: nex.EvidenceTaskHandoff,
				GoalID: goalID, TaskID: patchVerified.task.ID(),
				ExpectedAuthority:  planner.public.ID(),
				ExpectedResultHash: nex.Hash(patchVerified.result),
				MinGeneration:      1,
			},
			{
				ID: "window", Kind: nex.EvidenceTaskHandoff,
				GoalID: goalID, TaskID: windowVerified.task.ID(),
				ExpectedAuthority:  planner.public.ID(),
				ExpectedResultHash: nex.Hash(windowVerified.result),
				MinGeneration:      1,
			},
			{
				ID: "safety", Kind: nex.EvidenceTaskHandoff,
				GoalID: goalID, TaskID: safetyVerified.task.ID(),
				ExpectedAuthority: planner.public.ID(),
				MinGeneration:     1,
				RequiredAttester:  planner.public.ID(),
			},
		},
		Options: []nex.AccordOption{
			{
				ID: "full-rollout", Title: "Full production rollout across all regions", Priority: 1,
				Guard: nex.OptionGuard{
					AllOf: []nex.EvidencePredicate{
						{EvidenceID: "patch", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "config", Digest: configArt.named().Ref.Digest},
						{EvidenceID: "window", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "window", Digest: windowArt.named().Ref.Digest},
						{EvidenceID: "safety", Op: nex.GuardOutcomeIn, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}},
						{EvidenceID: "safety", Op: nex.GuardNoWitnessDissent},
					},
				},
				ExtraMandatoryRoles: []nex.RoleRequirement{{Role: "security", MinApprovals: 1, MinWeight: 2}},
				Binding:             fullBinding,
			},
			{
				ID: "canary-rollout", Title: "Bounded 5% canary rollout while rollback snapshot is remediated", Priority: 2,
				Guard: nex.OptionGuard{
					AllOf: []nex.EvidencePredicate{
						{EvidenceID: "patch", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "config", Digest: configArt.named().Ref.Digest},
						{EvidenceID: "window", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted}, Slot: "window", Digest: windowArt.named().Ref.Digest},
						{EvidenceID: "safety", Op: nex.GuardArtifactSlot, Outcomes: []nex.TaskOutcome{nex.TaskAccepted, nex.TaskIncomplete}, Slot: "observation", Digest: safetyArt.named().Ref.Digest},
					},
				},
				ExtraMandatoryRoles: []nex.RoleRequirement{{Role: "sre", MinApprovals: 1, MinWeight: 2}},
				Binding:             canaryBinding,
			},
			{
				ID: "hold-and-remediate", Title: "Hold release and remediate staging rollback snapshot", Priority: 3,
				Guard: nex.OptionGuard{
					AnyOf: []nex.EvidencePredicate{
						{EvidenceID: "safety", Op: nex.GuardOutcomeIn, Outcomes: []nex.TaskOutcome{nex.TaskIncomplete, nex.TaskRejected}},
						{EvidenceID: "safety", Op: nex.GuardHasWitnessDissent},
					},
				},
				Binding: holdBinding,
			},
		},
		VoteByHeight:    10,
		ResolveByHeight: 20,
		Rules: nex.DecisionRules{
			BallotMode:                 nex.BallotSingleChoice,
			BallotPrivacy:              nex.BallotPrivacySealedPaillier,
			MinParticipationCount:      3,
			MinParticipationWeight:     6,
			MinApprovalCount:           2,
			MinApprovalWeight:          5,
			MinApprovalMarginWeight:    3,
			MandatoryRoles:             []nex.RoleRequirement{{Role: "safety", MinApprovals: 1, MinWeight: 3}},
			Veto:                       nex.VetoPolicy{Mode: nex.VetoBlocking, MaxVetoesPerActor: 1, RequireEvidence: true, AllowedDomainRoles: []string{"safety-gate"}},
			TieBreak:                   nex.TieBreakLowestPriority,
			RequireIndependentResolver: true,
		},
		SealedTally: &nex.SealedTallyConfig{
			PublicKey:      tallyKey.PublicKey(),
			TallyAuthority: tallyAuthority.public.ID(),
		},
		MaxEvents: 64,
	}

	accordID, err := podA.accords.Create(accordSpec)
	if err != nil {
		return runArtifacts{}, err
	}

	// Register Revision 2 with the AccordGate and 3 mutually exclusive downstream tasks.
	patchDep := nex.TaskDependency{
		Input:      "config",
		TaskID:     patchVerified.task.ID(),
		ProtocolID: patchVerified.result.Lease.ProtocolID,
		Head:       patchVerified.result.Head,
		Slot:       "config",
		Digest:     configArt.named().Ref.Digest,
		Outcome:    nex.TaskAccepted,
	}
	windowDep := nex.TaskDependency{
		Input:      "window",
		TaskID:     windowVerified.task.ID(),
		ProtocolID: windowVerified.result.Lease.ProtocolID,
		Head:       windowVerified.result.Head,
		Slot:       "window",
		Digest:     windowArt.named().Ref.Digest,
		Outcome:    nex.TaskAccepted,
	}
	safetyDep := nex.TaskDependency{
		Input:      "observation",
		TaskID:     safetyVerified.task.ID(),
		ProtocolID: safetyVerified.result.Lease.ProtocolID,
		Head:       safetyVerified.result.Head,
		Slot:       "observation",
		Digest:     safetyArt.named().Ref.Digest,
		Outcome:    nex.TaskIncomplete,
	}

	makeGatedTask := func(name, purpose, acceptance, output, optionID, commitment string, deps []nex.TaskDependency) nex.TaskSpec {
		return nex.TaskSpec{
			GoalID:            goalID,
			Nonce:             name,
			Purpose:           purpose,
			Scope:             "release/" + name,
			Authority:         planner.public,
			SpecificationHash: nex.Hash(purpose),
			AcceptanceHash:    nex.Hash(acceptance),
			FailurePolicyHash: nex.Hash("Abort downstream branch and preserve diagnostic record"),
			Outputs:           []string{output},
			Dependencies:      deps,
			GateDependencies: []nex.TaskGateDependency{
				{
					GateID:             gateID,
					RequiredPhase:      nex.AccordPhaseDecided,
					OptionID:           optionID,
					ExpectedCommitment: commitment,
				},
			},
		}
	}

	fullRolloutTask := makeGatedTask(
		"full-rollout-task",
		"Execute full production rollout across all regions",
		"All regions healthy after full rollout",
		"full-report",
		"full-rollout",
		fullBinding.Commitment(),
		[]nex.TaskDependency{patchDep, windowDep},
	)
	canaryRolloutTask := makeGatedTask(
		"canary-rollout-task",
		"Execute bounded 5% canary rollout with heightened rollback monitoring",
		"Canary error budget remains green while staging snapshot is remediated",
		"canary-report",
		"canary-rollout",
		canaryBinding.Commitment(),
		[]nex.TaskDependency{patchDep, windowDep, safetyDep},
	)
	holdRemediationTask := makeGatedTask(
		"hold-remediation-task",
		"Hold release and remediate missing staging rollback snapshot",
		"Staging rollback snapshot verified before rescheduling release",
		"remediation-report",
		"hold-and-remediate",
		holdBinding.Commitment(),
		[]nex.TaskDependency{safetyDep},
	)

	rev2 := nex.PlanRevision{
		GoalID:    goalID,
		Head:      planHead1,
		Planner:   planner.public.ID(),
		RequestID: "plan-policy-gates-2",
		Gates: []nex.AccordGate{
			{
				ID:             gateID,
				GoalID:         goalID,
				AccordID:       accordID,
				Purpose:        "Unlock exactly one rollout branch from the sealed release governance Accord",
				AllowedOptions: []string{"full-rollout", "canary-rollout", "hold-and-remediate"},
			},
		},
		Tasks: []nex.TaskSpec{fullRolloutTask, canaryRolloutTask, holdRemediationTask},
	}
	planHead2, err := podA.goals.Apply(rev2, nex.Sign(planner.identity, nex.PlanSignatureDomain, rev2))
	if err != nil {
		return runArtifacts{}, err
	}

	// Pillar 4: Submit upstream attestations, bounded veto, and encrypted CDS94 {0,1} sealed
	// ballots through adapter.Outbox + adapter.AccordAuthority (KindAccord), exercising a
	// simulated lost response (DropNext: true) recovered via exact signed retry.
	fixedNow := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	outbox, err := adapter.OpenOutbox(filepath.Join(dir, "outbox"), key)
	if err != nil {
		return runArtifacts{}, err
	}
	outbox.SetNow(func() time.Time { return fixedNow })

	var accordHeight atomic.Uint64
	accordAuth := &adapter.AccordAuthority{
		Tenant: outboxTenant,
		Store:  podA.accords,
		Height: func() uint64 { return accordHeight.Load() },
	}

	submitViaOutbox := func(who actor, grant, action, reqID string, h uint64, dropFirst bool, fill func(*nex.AccordCommand)) (adapter.AuthenticatedResponse, int, error) {
		accordHeight.Store(h)
		cmd, err := podA.accords.Prepare(accordID, who.public.ID(), grant, accordScope, action, reqID, h)
		if err != nil {
			return adapter.AuthenticatedResponse{}, 0, err
		}
		if fill != nil {
			fill(&cmd)
		}
		sig, err := nex.SignAccordCommand(who.identity, cmd)
		if err != nil {
			return adapter.AuthenticatedResponse{}, 0, err
		}
		raw, err := adapter.EncodeAccord(cmd, sig)
		if err != nil {
			return adapter.AuthenticatedResponse{}, 0, err
		}
		item := adapter.OutboundItem{
			Version:      adapter.Version,
			Tenant:       outboxTenant,
			AgreementID:  accordID,
			OperationID:  reqID,
			Kind:         adapter.KindAccord,
			SignedObject: raw,
			Destination:  "accord-sql-pod-a",
			CreatedAt:    fixedNow,
		}
		if err := outbox.Enqueue(item); err != nil {
			return adapter.AuthenticatedResponse{}, 0, err
		}
		if dropFirst {
			accordAuth.DropNext = true
			if _, err := outbox.Reconcile(outboxTenant, reqID, accordAuth); !errors.Is(err, adapter.ErrLostResponse) {
				return adapter.AuthenticatedResponse{}, 0, fmt.Errorf("expected ErrLostResponse on %s, got %v", reqID, err)
			}
			mid, err := outbox.Get(outboxTenant, reqID)
			if err != nil {
				return adapter.AuthenticatedResponse{}, 0, err
			}
			if mid.Status != adapter.StatusUnknown || mid.Attempts != 1 {
				return adapter.AuthenticatedResponse{}, 0, fmt.Errorf("unexpected mid-retry outbox state: status=%q attempts=%d", mid.Status, mid.Attempts)
			}
		}
		resp, err := outbox.Reconcile(outboxTenant, reqID, accordAuth)
		if err != nil {
			return adapter.AuthenticatedResponse{}, 0, fmt.Errorf("reconcile %s: %w", reqID, err)
		}
		if err := outbox.RecordVerified(outboxTenant, reqID, resp, respAuthority.public, adapter.SignAuthorityResponse(respAuthority.identity, resp)); err != nil {
			return adapter.AuthenticatedResponse{}, 0, fmt.Errorf("record verified %s: %w", reqID, err)
		}
		rec, err := outbox.Get(outboxTenant, reqID)
		if err != nil {
			return adapter.AuthenticatedResponse{}, 0, err
		}
		return resp, rec.Attempts, nil
	}

	// Attest all three wire-decoded TaskHandoff proofs via KindAccord outbox.
	for i, vu := range upstreamDone {
		var wireHandoff nex.TaskHandoff
		if err := json.Unmarshal(vu.handoffJSON, &wireHandoff); err != nil {
			return runArtifacts{}, err
		}
		if _, _, err := submitViaOutbox(planner, "attester", "attest", "attest-"+vu.name, uint64(i+1), false, func(cmd *nex.AccordCommand) {
			cmd.Attest = &nex.AttestPayload{EvidenceID: vu.name, Handoff: &wireHandoff}
		}); err != nil {
			return runArtifacts{}, err
		}
	}

	// Independent safety witness casts an evidence-cited blocking veto on full-rollout.
	if _, _, err := submitViaOutbox(witness, "safety-veto", "veto", "veto-safety-full", 4, false, func(cmd *nex.AccordCommand) {
		cmd.Veto = &nex.VetoPayload{
			OptionID:    "full-rollout",
			ReasonHash:  nex.Hash("Blocking full rollout due to incomplete staging rollback handoff"),
			EvidenceIDs: []string{"safety"},
		}
	}); err != nil {
		return runArtifacts{}, err
	}

	// Four voters submit encrypted CDS94 {0,1} sealed ballots (single-choice).
	// Safety's ballot exercises DropNext: true lost-response recovery through Outbox.Reconcile.
	type sealedVoteStep struct {
		who       actor
		grant     string
		reqID     string
		height    uint64
		dropFirst bool
		choices   map[string]nex.BallotPosition
		rationale string
	}
	voteSteps := []sealedVoteStep{
		{
			who: release, grant: "release-voter", reqID: "sealed-vote-release", height: 5,
			choices: map[string]nex.BallotPosition{
				"full-rollout":   nex.BallotApprove,
				"canary-rollout": nex.BallotDissent,
			},
			rationale: "Prefer full rollout if rollback check were waived",
		},
		{
			who: safety, grant: "safety-reviewer", reqID: "sealed-vote-safety", height: 6, dropFirst: true,
			choices: map[string]nex.BallotPosition{
				"full-rollout":   nex.BallotDissent,
				"canary-rollout": nex.BallotApprove,
			},
			rationale: "5% canary keeps blast radius contained while staging rollback is restored",
		},
		{
			who: sre, grant: "sre-voter", reqID: "sealed-vote-sre", height: 7,
			choices: map[string]nex.BallotPosition{
				"canary-rollout": nex.BallotApprove,
			},
			rationale: "SRE can monitor 5% canary and trigger rapid rollback",
		},
		{
			who: security, grant: "security-reviewer", reqID: "sealed-vote-security", height: 8,
			choices: map[string]nex.BallotPosition{
				"canary-rollout": nex.BallotApprove,
			},
			rationale: "Retry limits are within reviewed bounds; canary preserves containment",
		},
	}

	var safetyRecoveryAttempts int
	var lostResponseRecovered bool
	for _, vs := range voteSteps {
		sealedPayload, err := nex.EncryptSealedBallot(accordSpec, accordID, vs.who.public.ID(), vs.choices, nex.Hash(vs.rationale))
		if err != nil {
			return runArtifacts{}, fmt.Errorf("encrypt sealed ballot %s: %w", vs.reqID, err)
		}
		resp, attempts, err := submitViaOutbox(vs.who, vs.grant, "vote", vs.reqID, vs.height, vs.dropFirst, func(cmd *nex.AccordCommand) {
			cmd.Vote = &nex.VotePayload{Sealed: sealedPayload}
		})
		if err != nil {
			return runArtifacts{}, err
		}
		if vs.dropFirst {
			safetyRecoveryAttempts = attempts
			lostResponseRecovered = attempts == 2 && resp.ReceiptHead != ""
		}
	}

	unresolvedOutbox, err := outbox.Unresolved(outboxTenant)
	if err != nil {
		return runArtifacts{}, err
	}

	// Prove individual ballots remain opaque Paillier ciphertexts during voting (zero plaintext votes).
	openView, err := podA.accords.View(accordID)
	if err != nil {
		return runArtifacts{}, err
	}
	if openView.Phase != nex.AccordPhaseOpen || len(openView.Votes) != 0 || len(openView.SealedBallots) != 4 {
		return runArtifacts{}, fmt.Errorf("unexpected open sealed accord view: phase=%q votes=%d sealed=%d",
			openView.Phase, len(openView.Votes), len(openView.SealedBallots))
	}
	opaqueCiphertexts := 0
	for _, sb := range openView.SealedBallots {
		for _, ob := range sb.Options {
			if len(ob.ApproveCT) < 256 || len(ob.DissentCT) < 256 {
				return runArtifacts{}, fmt.Errorf("expected opaque 2048-bit Paillier ciphertexts, got lens %d/%d",
					len(ob.ApproveCT), len(ob.DissentCT))
			}
			opaqueCiphertexts += 2
		}
	}

	// Pillar 5: Stateless Pod Failover (Pod A closes; Pod B opens brand-new SQL store handles
	// against the SAME shared SQL DB with ZERO directory copy!).
	if err := podA.close(); err != nil {
		return runArtifacts{}, err
	}
	podB, err := openPodStores(ctx, cluster.dsn, key)
	if err != nil {
		return runArtifacts{}, err
	}
	defer podB.close()

	// Verify the GoalPlan offline directly from Pod B's SQL-backed GoalStore.
	goalPlan, err := podB.goals.View(goalID)
	if err != nil {
		return runArtifacts{}, err
	}
	if err := nex.VerifyGoalPlan(goalPlan, goalID, planHead2); err != nil {
		return runArtifacts{}, fmt.Errorf("VerifyGoalPlan failed on Pod B: %w", err)
	}
	planJSON, err := json.Marshal(goalPlan)
	if err != nil {
		return runArtifacts{}, err
	}

	// Snapshot DiscoverGoal on Pod B BEFORE recording the AccordGate resolution.
	beforeDisc, _, err := podB.tasks.DiscoverGoal(goalID, 14)
	if err != nil {
		return runArtifacts{}, err
	}
	beforeByName := make(map[string]nex.TaskDiscovery, len(beforeDisc))
	for _, d := range beforeDisc {
		beforeByName[d.Task.Nonce] = d
	}

	// Pod B exports the open sealed AccordBundle, runs SealedTallyKey.TallyAccord (GMR-hardened
	// he.ProveEqual proofs over homomorphic aggregates), and resolves the Accord at height 10.
	preResolveBundle, err := podB.accords.Export(accordID)
	if err != nil {
		return runArtifacts{}, err
	}
	tallyProof, err := tallyKey.TallyAccord(preResolveBundle)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("TallyAccord failed on Pod B: %w", err)
	}
	resolveCmd, err := podB.accords.Prepare(accordID, tallyAuthority.public.ID(), "tally-resolver", accordScope, "resolve", "resolve-sealed-release", 10)
	if err != nil {
		return runArtifacts{}, err
	}
	resolveCmd.Resolve = &nex.ResolvePayload{
		ReasonHash:  nex.Hash("Voting window closed; apply verified GMR homomorphic tally"),
		SealedTally: tallyProof,
	}
	resolveSig, err := nex.SignAccordCommand(tallyAuthority.identity, resolveCmd)
	if err != nil {
		return runArtifacts{}, err
	}
	finalHead, err := podB.accords.Apply(accordID, resolveCmd, resolveSig, 10)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("Pod B resolve failed: %w", err)
	}

	// Export the terminal AccordBundle across a JSON wire boundary and verify offline with ZERO private keys.
	finalBundle, err := podB.accords.Export(accordID)
	if err != nil {
		return runArtifacts{}, err
	}
	bundleJSON, err := json.Marshal(finalBundle)
	if err != nil {
		return runArtifacts{}, err
	}
	var wireBundle nex.AccordBundle
	if err := json.Unmarshal(bundleJSON, &wireBundle); err != nil {
		return runArtifacts{}, err
	}
	verifiedView, err := nex.VerifyAccordBundle(wireBundle, accordID, finalHead)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("offline VerifyAccordBundle failed: %w", err)
	}
	if verifiedView.Outcome == nil || verifiedView.Phase != nex.AccordPhaseDecided || len(verifiedView.Votes) != 0 {
		return runArtifacts{}, fmt.Errorf("unexpected verified sealed view: phase=%q votes=%d", verifiedView.Phase, len(verifiedView.Votes))
	}

	// Pod B records the offline-verified AccordBundle on the AccordGate (plus idempotent exact retry).
	gateRes, err := podB.tasks.RecordAccord(goalID, gateID, wireBundle, finalHead)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("RecordAccord failed on Pod B: %w", err)
	}
	gateResRetry, err := podB.tasks.RecordAccord(goalID, gateID, wireBundle, finalHead)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("RecordAccord retry failed: %w", err)
	}
	gateRetryOK := gateResRetry == gateRes

	// Pod B runs DiscoverGoal proving ONLY canary-rollout-task unlocked while
	// full-rollout-task and hold-remediation-task show GatesMismatch: true.
	afterDisc, _, err := podB.tasks.DiscoverGoal(goalID, 14)
	if err != nil {
		return runArtifacts{}, err
	}
	afterByName := make(map[string]nex.TaskDiscovery, len(afterDisc))
	for _, d := range afterDisc {
		afterByName[d.Task.Nonce] = d
	}

	// Prove Claim refuses full-rollout-task and hold-remediation-task with ErrTaskDependency.
	fullSpec, fullReq, fullSig, err := buildAttemptClaim(goalID, fullRolloutTask, planner, sre, safety, 14)
	if err != nil {
		return runArtifacts{}, err
	}
	_, fullClaimErr := podB.tasks.Claim(fullReq, fullSig, fullSpec, 14)
	if !errors.Is(fullClaimErr, nex.ErrTaskDependency) {
		return runArtifacts{}, fmt.Errorf("full-rollout-task Claim got %v, want ErrTaskDependency", fullClaimErr)
	}

	holdSpec, holdReq, holdSig, err := buildAttemptClaim(goalID, holdRemediationTask, planner, sre, safety, 14)
	if err != nil {
		return runArtifacts{}, err
	}
	_, holdClaimErr := podB.tasks.Claim(holdReq, holdSig, holdSpec, 14)
	if !errors.Is(holdClaimErr, nex.ErrTaskDependency) {
		return runArtifacts{}, fmt.Errorf("hold-remediation-task Claim got %v, want ErrTaskDependency", holdClaimErr)
	}

	// Pod B claims, commits, completes, and finalizes the unlocked canary-rollout-task.
	canaryAttempt, err := claimOn(podB, canaryRolloutTask, sre, safety, 14)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("canary-rollout-task Claim failed: %w", err)
	}
	canaryReportArt := artifact{
		name:      "canary-report",
		content:   `{"mode":"canary","percent":5,"error_budget":"green"}`,
		mediaType: "application/json",
	}
	canaryCommittedPhase, canaryHead, err := runTaskProtocol(
		podB.attempts,
		planner,
		safety,
		canaryAttempt,
		15,
		[]nex.NamedArtifact{configArt.named(), windowArt.named(), safetyArt.named()},
		canaryReportArt,
		func(body string) error {
			if !strings.Contains(body, `"error_budget":"green"`) {
				return errors.New("canary error budget not green")
			}
			return nil
		},
	)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("canary-rollout-task protocol failed: %w", err)
	}
	canaryResult, err := podB.tasks.Finalize(canaryAttempt.lease, canaryHead, 16)
	if err != nil {
		return runArtifacts{}, fmt.Errorf("canary-rollout-task Finalize failed: %w", err)
	}

	// Assemble deterministic structured report.
	optSummaries := make([]optionSummary, 0, len(verifiedView.Outcome.Tallies))
	for _, t := range verifiedView.Outcome.Tallies {
		optSummaries = append(optSummaries, optionSummary{
			OptionID:                t.OptionID,
			GuardPassed:             t.GuardPassed,
			ApproveCount:            t.ApproveCount,
			ApproveWeight:           t.ApproveWeight,
			DissentCount:            t.DissentCount,
			DissentWeight:           t.DissentWeight,
			VetoEffective:           t.VetoEffective,
			Eligible:                t.Eligible,
			DisqualificationReasons: slices.Clone(t.DisqualificationReasons),
		})
	}

	downstreamNames := []string{"canary-rollout-task", "full-rollout-task", "hold-remediation-task"}
	downstreamSummaries := make([]gateTaskSummary, 0, len(downstreamNames))
	for _, name := range downstreamNames {
		bef := beforeByName[name]
		aft := afterByName[name]
		downstreamSummaries = append(downstreamSummaries, gateTaskSummary{
			TaskName:             name,
			StatusBeforeGate:     bef.Status,
			GatesReadyBefore:     bef.GatesReady,
			GatesReadyAfter:      aft.GatesReady,
			GatesMismatchAfter:   aft.GatesMismatch,
			DependenciesReady:    aft.DependenciesReady,
			DependenciesMismatch: aft.DependenciesMismatch,
		})
	}

	rep := report{
		Example:                   "policy-graph",
		SQLDialect:                nex.SQLDialectPostgres,
		SQLNamespaces:             cluster.namespaceRowCounts(),
		ZeroDirectoryCopyFailover: true,
		UpstreamOutcomes: map[string]nex.TaskOutcome{
			"patch":  patchVerified.result.Outcome,
			"window": windowVerified.result.Outcome,
			"safety": safetyVerified.result.Outcome,
		},
		BallotPrivacy:               nex.BallotPrivacySealedPaillier,
		BallotMode:                  nex.BallotSingleChoice,
		SealedBallotsRecorded:       len(openView.SealedBallots),
		PlaintextVotesExposed:       len(verifiedView.Votes),
		OpaqueCiphertextsVerified:   opaqueCiphertexts,
		OutboxLostResponseRecovered: lostResponseRecovered,
		OutboxRecoveryAttempts:      safetyRecoveryAttempts,
		OutboxUnresolvedCount:       len(unresolvedOutbox),
		AccordPhase:                 verifiedView.Phase,
		WinningOption:               verifiedView.Outcome.WinningOptionID,
		ParticipatingCount:          verifiedView.Outcome.ParticipatingCount,
		ParticipatingWeight:         verifiedView.Outcome.ParticipatingWeight,
		Options:                     optSummaries,
		OfflineBundleVerified:       true,
		OfflineGoalPlanVerified:     true,
		GateRecordedPhase:           gateRes.Phase,
		GateWinningOption:           gateRes.WinningOptionID,
		GateRetryIdempotent:         gateRetryOK,
		DownstreamTasks:             downstreamSummaries,
		FullRolloutClaimRefused:     errors.Is(fullClaimErr, nex.ErrTaskDependency),
		HoldRemediationClaimRefused: errors.Is(holdClaimErr, nex.ErrTaskDependency),
		CanaryTaskClaimed:           canaryAttempt.lease.Generation == 1,
		CanaryCommittedPhase:        canaryCommittedPhase,
		CanaryFinalOutcome:          canaryResult.Outcome,
	}

	return runArtifacts{
		report:     rep,
		bundleJSON: bundleJSON,
		accordID:   accordID,
		finalHead:  finalHead,
		planJSON:   planJSON,
		goalID:     goalID,
		planHead:   planHead2,
	}, nil
}
