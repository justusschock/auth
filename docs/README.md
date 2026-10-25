# auth documentation

Requirements (PRDs) and architecture decision records (ADRs) for auth. The
process is described in [ADR-0001](adr/0001-record-architecture-decisions.md)
and [AGENTS.md](../AGENTS.md); new documents start from the
[PRD template](prd/TEMPLATE.md) or the [ADR template](adr/TEMPLATE.md).

Requirement area code: `AUTH` (`FR-AUTH-NN`, `NFR-AUTH-NN`).

## Product requirements

| PRD | Title | Status | Implementation |
|---|---|---|---|
| [0001](prd/0001-auth.md) | auth authentication and authorization library | Accepted | Complete |

## Architecture decisions

| ADR | Title | Status |
|---|---|---|
| [0001](adr/0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](adr/0002-package-and-api-shape.md) | Independent protocol packages around neutral contracts | Accepted |
| [0003](adr/0003-dependency-policy.md) | Dependency policy | Accepted |
| [0004](adr/0004-error-semantics.md) | Fail-closed, sanitized sentinel errors | Accepted |
| [0005](adr/0005-secret-handling-and-comparisons.md) | Secret generation, storage, key handling and comparisons | Accepted |
| [0006](adr/0006-expiry-clock-skew-and-ttls.md) | Expiry, clock-skew and TTL rules | Accepted |
| [0007](adr/0007-concurrency-and-cancellation.md) | Concurrency and cancellation model | Accepted |
| [0008](adr/0008-pluggable-stores.md) | Caller-owned stores with in-memory reference implementations | Accepted |
| [0009](adr/0009-public-api-boundary.md) | Public API boundary | Accepted |
| [0010](adr/0010-supported-go-versions.md) | Supported Go versions | Accepted |
| [0011](adr/0011-testing-strategy.md) | Testing strategy | Accepted |
| [0012](adr/0012-typed-request-entities-and-structured-policies.md) | Typed request entities and structured Cedar policies | Accepted |

ADR-0005 and ADR-0006 together are the library's security model; see also
[SECURITY.md](../SECURITY.md).
