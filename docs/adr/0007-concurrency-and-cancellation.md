# ADR 0007: Concurrency and cancellation model

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001, ADR-0005, ADR-0008 |

## Context

Recorded retrospectively for the first public release. Authenticators run on
every request of a server, typically from many goroutines and often from
several processes against one store. Two classes of race matter for
security: a one-time value accepted twice, and two refresh-token rotations
both succeeding (which would hide token theft).

The code shows:

- Authenticators and providers (`jwt.Verifier`, `apitoken.Manager`,
  `oidc.Provider`, `oauth2.Provider`, `saml.Provider`, `magiclink.Service`,
  `session.Manager`, `device.Client`, `cedar.Engine`, `sso.Registry`) hold
  only immutable configuration after construction and are safe for
  concurrent use when the stores and callbacks they are given are.
- In-memory stores guard their maps with a `sync.Mutex` and copy values in
  and out.
- Single use is delegated to the store contract: `Consume` must remove and
  return atomically; `Create`/`Put` must be create-only (`ErrReplay`).
- Session rotation acquires a distributed-coordination lease on
  `auth/session/<id>` (owner `Options.ManagerID`, TTL 10 s, waiting), loads
  the session under the lease, checks the refresh digest, aborts if the lease
  was lost, and writes with `Store.CompareAndSwap(id, version, fence, next)`,
  which must reject stale versions (`ErrReplay`) and stale fencing tokens
  (`coordination.ErrLeaseLost`). Release errors fail the rotation closed.
- Every blocking or I/O operation takes `context.Context` first, checks
  `ctx.Err()` before work, passes the context to stores, key sources, HTTP
  clients and mappers, and returns the caller's `ctx.Err()` unchanged when the
  context ends (instead of a sanitized error). `device.Client.Poll` waits for
  the polling interval while honouring the context.

## Decision drivers

- D1: Exactly one winner for any one-time value, across processes.
- D2: No in-library background goroutines or global state.
- D3: Cancellation must be distinguishable from rejection.

## Considered options

1. **Stateless components; atomicity in store contracts; lease plus fenced
   CAS for rotation (chosen)**
   - Pro: works across processes with any store that offers atomic
     delete-and-return and compare-and-swap; no hidden goroutines.
   - Con: correctness depends on caller-implemented stores honouring the
     contracts.
2. **In-library locking only (mutexes)**
   - Pro: simple.
   - Con: correct only within one process.
3. **Version-checked CAS without a lease for rotation**
   - Pro: one dependency fewer.
   - Con: exclusion would rest on the store alone; the lease serializes the
     whole read-check-write sequence across processes, and its fencing token
     lets the store reject a write from a holder that paused past its lease.

## Decision

We will keep components free of mutable shared state, require atomic consume
and create-only semantics from every store, serialize session rotation with a
fenced coordination lease and a version-checked compare-and-swap, and treat
`context.Context` as the only cancellation mechanism, returning `ctx.Err()`
as is.

## Consequences

### Positive
- Concurrent-winner tests (`TestMagicLinkHasExactlyOneConcurrentWinner`,
  `TestRotateUsesLeaseAndHasExactlyOneConcurrentWinner`,
  `TestCompleteConsumesBeforeExchangeAndAllowsOnlyOneCallback`) state the
  guarantee directly and run under the race detector.

### Negative
- Session rotation needs a coordination backend even in single-process
  deployments (an in-memory one suffices).

### Follow-ups
- A conformance suite for store atomicity (ADR-0008).

## Links

- github.com/justusschock/distributed-coordination
