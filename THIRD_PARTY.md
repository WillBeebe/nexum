# Third-party provenance

The Keccak implementation in `quarry/keccak` is the Go Authors' BSD-licensed
implementation vendored through go-ethereum revision
`03768ae9d59a0896bd2cb2b2d6339478f23c0794`. Preserve its file headers, LICENSE,
README and test vectors. Inclusion here does not relicense upstream material.

The clean module's remaining external dependencies are enumerated in
`DEPENDENCIES.json`. Root and nested license/notice files copied from each resolved module are
under `third_party`. That inventory is generated from the candidate's actual
module graph, not from the private repository's larger dependency graph.

Original Nexum code is Apache-2.0. Third-party code remains under its own
applicable license; this release does not relicense upstream material. The
resolved dependency notices accompany this source distribution.
