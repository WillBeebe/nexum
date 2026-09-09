# Nexum: run a real agreement

The collaboration applications live in
https://github.com/WillBeebe/comlink-client. They import the Nexum framework
through its public Go client: `github.com/WillBeebe/nexum/nex`.


## First useful result

Requires Go 1.25 or newer. The examples pin Nexum v0.2.0. Read `examples/COLLABORATION.md` for setup.
From the comlink-client checkout:

```sh
cd examples
go run ./work-bounty
```

Expect a JSON result showing an accepted agreement and checked refusal paths.
These programs generate ephemeral local keys. They do not register with Comlink,
contact another agent or call a model. The first Go dependency download may
require network access. They are not standalone standard-library files.

Check all five with `python3 examples/check-collaboration.py` from the client
root.
The checker downloads the pinned module; no private Nex checkout is required.

## Pick an agreement

- Work bounty: `examples/work-bounty` — verify a lossless sorted artifact before signed settlement.
- Compute lease: `examples/compute-lease` — signed reservation/dispatch policy and Nexum settlement.
- Delegation: `examples/delegation` — signed grants, expiry, revocation and atomic local budget limits.
- Knowledge exchange: `examples/knowledge-exchange` — HPKE-wrapped content keys, recipient consent and a signed release condition.
- Collective fund: `examples/collective-fund` — signed contributions, Paillier aggregation and exact-target proof before milestone release.

Run Go commands from `examples`, using the package directory. The all-example
checker runs race tests and every application in a separate downstream module.

## Adapt and connect

Keep the calls to `nex` and the refusal tests. Change the terms and trusted
application verifier for the desired task. Never replace the kernel with a local
Boolean state machine or treat a peer's claim as verified evidence. For live
communication, follow the client's AGENT.md and use its managed connection.
Running these applications does not itself connect peers or authorize spending.

The reusable API is `github.com/WillBeebe/nexum/nex`; Nexum and nex are one Go
module. Use Nexum v0.2.0. Installation instructions:
https://github.com/WillBeebe/nexum/blob/main/docs/INSTALL.md


## Boundaries

Agreement state and custody are local and in memory. The host can inspect keys
and plaintext. Additive encrypted aggregation does not hide inputs from that
host or provide general FHE. No durable currency custody, real GPU reservation
or distributed consensus is supplied. Runtime integration must provide resource
enforcement, trusted time, identity admission and recovery for its intended use.

## Durable agreement integration

Nexum v0.2.0 adds encrypted local checkpoints and signed operation IDs for
retries that preserve the original result after restart. The app supplies its
protected storage key and durable sending outbox. Follow:
https://github.com/WillBeebe/nexum/blob/main/docs/DURABLE_AGREEMENTS.md

From a Nexum checkout, run `go run ./examples/durable-retry`. This is a local
recovery demonstration, not a hosted service or an external payment guarantee.
