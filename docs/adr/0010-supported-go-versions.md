# ADR 0010: Supported Go versions

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | ADR-0011 |

## Context

Recorded retrospectively for the first public release. `go.mod` declares
`go 1.26.0`. The tests depend on `testing/synctest` with its stable API
(`synctest.Test`, `synctest.Wait`), available since Go 1.25, which sets the
lowest possible floor. Upstream Go supports the two most recent major
releases; at the time of writing those are 1.27 (`stable`) and 1.26
(`oldstable`). The direct dependencies require at most Go 1.25.

## Decision drivers

- D1: Security fixes in the standard library (crypto, net/http, encoding/xml)
  only ship for supported Go releases.
- D2: Tests need `testing/synctest` (Go ≥ 1.25).
- D3: Do not lower the floor below what the code was written and tested
  against.

## Considered options

1. **Keep the floor at 1.26 (the existing `go` directive); test the floor,
   `oldstable` and `stable` (chosen)**
   - Pro: matches the code as built; every tested version is upstream
     supported.
   - Con: excludes Go 1.25 users although synctest would allow it.
2. **Lower the floor to 1.25**
   - Pro: wider reach.
   - Con: 1.25 is no longer supported upstream; would need re-validation
     and CI on an unsupported release.
3. **Track only `stable`**
   - Pro: least CI.
   - Con: breaks users one release behind.

## Decision

We will support Go 1.26 and later, keeping `go 1.26.0` in `go.mod`, and test
in CI on `1.26.x`, `oldstable` and `stable`. While 1.26 is `oldstable` the
first two coincide; the floor entry keeps the minimum covered when 1.28 is
released. Raising the floor (for example when 1.26 leaves upstream support)
is a minor-release change recorded in the changelog and in a new ADR.

## Consequences

### Positive
- `testing/synctest` is always available.

### Negative
- One duplicated matrix entry until the next Go release.

### Follow-ups
- Revisit when Go 1.28 is released.

## Links

- https://go.dev/doc/devel/release#policy
