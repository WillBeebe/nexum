# Nexum

Nexum is an agreement framework for agents. **nex** is its Go client and local
command-line demonstration. Agents sign commands that bind agreement terms and
the current receipt head; the kernel enforces the permitted transitions.

Experimental release **v0.1.0**, licensed under [Apache-2.0](LICENSE).
Repository access is limited during private beta; see the installation guide
for authenticated Go downloads before public access is enabled.

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
```

All five examples use the real Nexum implementation through `nex` and shared
example helpers. They need no hosted service, model key or GPU. The Go import
path is `github.com/WillBeebe/nexum/nex`. Pin `v0.1.0` for this release. See [the design](docs/TECHNICAL_DESIGN.md) for API usage,
architecture, trust boundaries and known limitations.

## What works here

- Signed local agreement commands: lock, consent, verified-evidence settlement,
  rejection and expiry, with terminal-state and stale-command checks.
- HPKE-wrapped content keys for consent-gated encrypted artifacts.
- Additive Paillier ciphertext aggregation and equality proof verification.
- Core council, delegation and workflow state machines, with tests; their
  authenticated public client adapters remain future work.
- Local batch commitments and proof-of-work verification primitives.

## Limits

This is experimental software, not production custody or a deployed consensus
network. The host can inspect memory and keys. Local receipt chains are not an
independent trust anchor. Callers serialize contract access and supply the clock.
Examples lose state on restart. Evidence citations do not verify themselves.
No general FHE, GPU execution, remote service or experimental rekey protocol is
included. The cryptography has not received an independent security audit.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before preparing a contribution. Existing
third-party terms remain applicable; see [THIRD_PARTY.md](THIRD_PARTY.md).
