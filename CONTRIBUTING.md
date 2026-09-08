# Contributing to Nexum

Nexum provides reusable digital agreements for agent communication,
collaboration and shared work. Contributions should make those agreements
easier to use, verify and enforce.

## Licensing and contribution terms

Nexum is licensed under [Apache-2.0](LICENSE). Unless you explicitly state
otherwise, a contribution intentionally submitted for inclusion is provided
under Apache-2.0, as described in section 5 of that license. Contributors retain
copyright; no copyright assignment or separate contributor agreement is required.

You must have the right to submit your work under these terms, including any
required employer permission. Preserve third-party licenses, notices and
attribution, and identify the source and license of copied or adapted material.
The canonical repository is https://github.com/WillBeebe/nexum.

## What to contribute

- Agreement transitions, verification, receipts and settlement correctness.
- A public API backed by the actual Nexum kernel.
- Real integrations and runnable examples, documentation and useful tests.
- Reproducible performance improvements with accurate security limitations.

The five collaboration examples must use Nexum's real implementation. Keep
application-specific predicates in the examples; do not copy or recreate the
kernel to make an example standalone. Do not claim general FHE, GPU execution,
distributed enforcement or durability from a local demonstration that lacks it.

Comlink's entire implementation remains private, including Comlink-specific
code located in this checkout. Operational infrastructure, unpublished research,
credentials, private keys, operator topology, private endpoints, customer data
and transcripts are outside the public contribution scope. Use synthetic
fixtures. Never copy private material into a public issue, patch or test log.

## Preparing a change

1. For substantial API, protocol or cryptography changes, discuss the concrete
   problem and proposed behavior with maintainers before a large implementation.
2. Keep the patch focused. Explain the trigger, behavior before and after,
   compatibility implications and any migration required.
3. Add meaningful regression coverage for changed behavior, including refusal
   paths when authorization, replay, budget or terminal transitions are involved.
4. Format changed Go code with `gofmt` and run `go test ./...`. Mac development
   must remain supported without a GPU, service credentials or paid resources.
5. Run the affected examples. For concurrency changes, run applicable race tests.
   For performance claims, include the workload, hardware and measured results.
6. State what was tested and any remaining limitations in the change description.

Use cost, effort and budget for metering. Preserve lock, accept, reject and
terminal no-takeback behavior. No mainnet keys or token-launch features are
needed to contribute. Keep generated artifacts and unrelated changes out of patches.

## Review and community

Maintainers decide what enters the canonical project and may request revisions
or decline changes. Contributions do not confer release authority. Review the
code and evidence respectfully; explain disagreements in concrete terms.
AI-assisted contributions are welcome when the submitting contributor reviews
the work, verifies its behavior and provenance, and takes responsibility for it.
Never give an external model private data without authorization.

Upstream fixes are encouraged. Apache-2.0 does not require upstream contributions. A pull request is not a
substitute for complying with applicable licenses.

## Security reports

Do not disclose an exploitable vulnerability or sensitive reproduction publicly.
Report privately to the repository maintainer through your established private
contact during private beta. A public security reporting channel will be listed
before public access is enabled. Do not put sensitive details in public issues.
