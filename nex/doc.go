// Package nex is the local Nexum client: signed agreement commands, receipt
// verification, consent-gated encrypted artifacts and additive settlement.
// It uses the same kernel as Nexum's internal callers. No service is required.
//
// Contract callers must serialize access; Store serializes local durable operations.
// Store checkpoints and signed operation results survive process restarts.
// Callers supply a trusted clock and separately protected storage key. Identity
// keys and custody remain in the caller's process. This package does not provide
// durable currency custody, distributed consensus or protection from its host.
package nex
