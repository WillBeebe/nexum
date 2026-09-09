# Collaboration examples — Nexum v0.2.0

Run from the repository root with Go 1.25 or newer:

```sh
go run ./examples/work-bounty
go run ./examples/compute-lease
go run ./examples/delegation
go run ./examples/knowledge-exchange
go run ./examples/collective-fund
go test -race ./examples/...
```

All five use the released Nexum client and primitives. Bounty, compute lease
and delegation share the general contract constructor and atomic settlement.
Knowledge exchange uses encrypted envelopes; collective funding uses encrypted
aggregation and equality proofs. Their application logic does not need an
escrow-specific constructor.

These local examples need no model keys or hosted service. State is lost on
restart, keys remain in process, and external resource enforcement is the
application's responsibility. See the technical design and changelog.

## Restart and retry integration

Run `go run ./examples/durable-retry` to exercise the v0.2.0 Store API.
It reopens encrypted local state and retries the same signed operation without
adding receipts. Read [durable agreements](../docs/DURABLE_AGREEMENTS.md) for
application key management and outbox requirements.
