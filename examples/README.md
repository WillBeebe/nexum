# Collaboration examples — Nexum v0.3.0

Run from the repository root with Go 1.25 or newer:

```sh
go run ./examples/work-bounty
go run ./examples/compute-lease
go run ./examples/delegation
go run ./examples/knowledge-exchange
go run ./examples/collective-fund
go run ./examples/return-handoff
go run ./examples/reconcile-handoff
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

Run `go run ./examples/durable-retry` to exercise the Store API.
It reopens encrypted local state and retries the same signed operation without
adding receipts. `go run ./examples/return-handoff` completes a failed attempt
with preserved dissent. `go run ./examples/reconcile-handoff` loses a transport
response, records that failure honestly, and refuses the old owner after a
stopped-writer handoff. Read [durable agreements](../docs/DURABLE_AGREEMENTS.md)
for application key management and outbox requirements.
