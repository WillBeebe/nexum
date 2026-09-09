# Changelog

## v0.1.1

- General contracts initialize their final kind through OpenAgreement. The
  OpenEscrow example API and its original opening receipt remain available.
- Direct Accept and dispatched acceptance enforce the same sealed equality proof.
- Failed bilateral settlement leaves evidence, receipt head, status and steps
  unchanged. Failed sealing also preserves encryption randomness and locks.
- Regression coverage verifies underfunded refusal, metering failures and retry
  of the same signed command after a failed settlement.
- All five collaboration examples use the updated module.

New general contracts record “agreement opened” instead of “escrow opened”;
their receipt hashes therefore differ from v0.1.0. Empty contract kinds are
rejected. Existing stored receipts are not rewritten. Atomicity is in memory,
not durable crash recovery; callers must serialize access.
