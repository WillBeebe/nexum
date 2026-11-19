# Nexum

Nexum is an agreement framework for agents. **nex** is its Go client and local
command-line demonstration. Agents sign commands that bind agreement terms and
the current receipt head; the kernel enforces the permitted transitions.

Experimental release **v2.0.1**, licensed under [Apache-2.0](LICENSE).
The source and tagged Go module are publicly available.

See [Go installation and downstream usage](docs/INSTALL.md) for library imports,
command installation and publication prerequisites.

## Run locally

Requires Go 1.25 or newer. From this source directory:

```sh
go test ./...
go run ./cmd/nex demo
go run ./examples/work-bounty
go run ./examples/compute-lease
go run ./examples/delegation
go run ./examples/knowledge-exchange
go run ./examples/collective-fund
go run ./examples/return-handoff
go run ./examples/reconcile-handoff
go run ./examples/coordination
```

The five collaboration labs plus the return, reconcile, and coordination
examples use the real Nexum implementation through `nex`. They need no hosted
service, model key or GPU. The Go import path is
`github.com/WillBeebe/nexum/v2/nex`. Pin `v2.0.1` for this release. See
[the design](docs/TECHNICAL_DESIGN.md) for API usage, architecture, trust
boundaries and known limitations.

## What works here

- Signed local agreement commands: lock, consent, verified-evidence settlement,
  rejection and expiry, with terminal-state and stale-command checks.
- Amount-free Protocol agreements (`ProtocolVersion` v1 and `ProtocolVersionV2`):
  admission, scoped roles, work and failure reports, content-addressed evidence
  manifests, independent witness review, resolution, required return, and
  explicit `incomplete` deadline closeout.
- Multi-agent coordination (`GoalStore`, `CoordinationStore`) and portable
  independently verifiable `TaskHandoff` proofs.
- HPKE-wrapped content keys for consent-gated encrypted artifacts.
- Additive Paillier ciphertext aggregation and equality proof verification
  (`SealedProofBundle` / `l2.ProfileSealedSettlement`).
- Core council, delegation and workflow state machines, with Format 2 mode
  commitment and Format 0 replay tests.
- Local batch commitments and proof-of-work verification primitives.
- Optional sender adapter for exact-command reconcile, durable outbox admission
  gating, and local/SQL fenced owner replacement (`DurableCoordinator`,
  `SQLCoordinator`).

## Limits

This is experimental software, not production custody or a deployed consensus
network. The host can inspect memory and keys. Local receipt chains are not an
independent trust anchor. Callers serialize contract access and supply the clock.
The original collaboration labs keep state in memory. Store-backed agreements
recover across local process restarts. Evidence citations do not verify themselves.
No general FHE, GPU execution, remote service or experimental rekey protocol is
included. The cryptography has not received an independent security audit.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before preparing a contribution. Existing
third-party terms remain applicable; see [THIRD_PARTY.md](THIRD_PARTY.md).

## Durable integration

Version 0.2.0 added encrypted local agreement storage and signed operation
IDs for safe retries. Version 0.3.0 added `ProtocolStore` and the optional
sender adapter. Version 2.0.0 adds `ProtocolVersionV2` (reviewed artifact
manifests and explicit `incomplete` closeouts), `GoalStore` / `CoordinationStore`
/ portable `TaskHandoff` verification, durable/SQL fence coordinators, and
canonical JSON receipt commitments under module path
`github.com/WillBeebe/nexum/v2`. See [durable agreements](docs/DURABLE_AGREEMENTS.md),
`go run ./examples/durable-retry`, `go run ./examples/reconcile-handoff`, and
`go run ./examples/coordination`.
