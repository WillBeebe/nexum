// Package nex is the local Nexum client: signed agreement commands, receipt
// verification, consent-gated encrypted artifacts and additive settlement.
// It uses the same kernel as Nexum's internal callers. No service is required.
//
// Contract callers must serialize access and supply a trusted clock. Identity
// keys and custody remain in the caller's process. This package does not provide
// durable currency custody, distributed consensus or protection from its host.
package nex
