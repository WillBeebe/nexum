// Package adapter is a sender contract around existing Nexum stores: persist
// the exact signed command before submit, reconcile lost responses by replaying
// those bytes, keep external effects distinct from agreement state, and require
// a fenced owner for compute replacement.
//
// It does not replace Store or ProtocolStore, invent a completion ledger, or
// provide distributed consensus. Fleet coordination is out of scope.
package adapter
