# ADR 0008: Caller-owned stores with in-memory reference implementations

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | ADR-0005, ADR-0007 |

## Context

Recorded retrospectively for the first public release. API tokens, sessions,
revocations, magic links, OAuth/OIDC callback state and SAML requests must
persist somewhere, and deployments use very different databases. The code
defines a small interface per stateful package and a process-local
implementation:

| Package | Contract | Reference implementation |
|---|---|---|
| `apitoken` | `Store` (Create, Get, ListByPrincipal, Revoke, TouchLastUsed) plus `ValidRecord` / `ValidID` helpers for implementers | `MemoryStore` |
| `session` | `Store` (Create, Get, CompareAndSwap, ListByPrincipal), `RevocationStore` | `MemoryStore`, `MemoryRevocationStore` |
| `magiclink` | `Store` (Create, Consume) | `MemoryStore` |
| `oidc` (shared with `oauth2`) | `StateStore` (Put, Consume) with `Pending` and `Secret` | `MemoryStateStore` |
| `saml` | `RequestStore` (Put, Consume) | `MemoryRequestStore` |
| `metadata` | `go-cache` `Cache[string, Document]` and a `Loader` | (any go-cache backend) |
| `authorization` | `PolicySource`, `EntitySource` | (caller supplied) |

The persisted types are plain Go structs (`apitoken.Record`,
`session.Session`, `magiclink.Record`, `oidc.Pending`, `saml.Request`); the
library defines no serialization format. Their security-relevant content
(digests, not secrets) is fixed by ADR-0005. The library re-validates
everything it reads back (`ValidRecord`, `validateSession`,
`validateTransition`, record/principal checks), so a corrupted or tampered
store row fails closed.

## Decision drivers

- D1: Any database; no driver dependencies in the library.
- D2: A store bug or corruption must not authenticate anyone.
- D3: Tests and single-process tools need zero setup.

## Considered options

1. **Small per-package interfaces, memory implementations, re-validation on
   read (chosen)**
   - Pro: no storage dependencies; easy to implement; defensive against bad
     rows.
   - Con: atomicity and create-only behaviour are contracts the library
     cannot check.
2. **Ship database adapters (SQL, Redis)**
   - Pro: ready to use.
   - Con: drivers and schemas in a security library; many more dependencies.
3. **Serialize everything into one generic key-value interface**
   - Pro: one contract.
   - Con: CAS, atomic consume and listing semantics differ per use; a generic
     interface would hide them.

## Decision

We will define one minimal store interface per stateful package, document
its atomicity requirements on the interface, ship a mutex-guarded in-memory
implementation for tests and single-process callers, and re-validate every
value read from a store. Storage formats are the caller's choice; the
persisted Go types are public API.

## Consequences

### Positive
- Consumers persist records in their own database (for example as documents)
  using `apitoken.ValidRecord` to reject corrupt input.

### Negative
- There is no public conformance suite yet, so durable implementations must
  be tested by their authors against the documented contracts.

### Follow-ups
- Add public `storetest`-style conformance suites for the store interfaces
  (atomic consume, create-only, CAS/fence semantics) in a future minor
  release, through a new ADR.

## Links

- ADR-0005, ADR-0007
