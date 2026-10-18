# ADR 0009: Public API boundary

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | ADR-0002, ADR-0006, ADR-0011 |

## Context

Recorded retrospectively for the first public release, when the exported
surface was reviewed package by package. Everything exported outside
`internal/` is public API under semver. Known consumers import
`authentication`, `authentication/apitoken`, `authentication/device`,
`authentication/jwt`, `authentication/middleware`, `authorization` and
`authorization/cedar`, including `apitoken.ValidRecord`, `apitoken.Record`,
`apitoken.Store`, `apitoken.ScopeTrait`, `apitoken.TokenIDTrait`,
`apitoken.ErrNotFound`, `device.Error`, `jwt.KeySource` and
`jwt.ClaimsMapper`. None uses the session test hooks described below.

The review found two candidates for removal:

1. `Clock func() time.Time` fields in `apitoken.Options`, `jwt.Options`,
   `magiclink.Options`, `oauth2.Options`, `oidc.Options`, `saml.Options` and
   `session.Options`. The repository's own tests used them to pin "now";
   `testing/synctest` now gives tests deterministic time without them. They
   are, however, ordinary configuration: a caller can supply a trusted or
   shared time source (for example one clock for a whole service, or a
   clock that fails closed when time synchronisation is lost), and a
   service that already injects time elsewhere can keep doing so.
2. `session.MemoryStore.FailNextCompareAndSwap` and
   `ObservedGetWhileLocked`, test instrumentation on a public type, backed by
   an unexported context marker set by `Manager.Rotate` in production code.

## Decision drivers

- D1: The public surface is exactly what users need.
- D2: No production code paths that exist only for tests.
- D3: Never break known consumers or remove reasonable configuration
  without need.
- D4: Security-relevant behaviour is configured explicitly by the caller,
  never through test hooks.

## Considered options

For `Clock`:

1. **Keep `Clock` as documented public configuration (chosen)**
   - Pro: no breaking change; callers keep control over the time source; a
     nil `Clock` still means `time.Now`, so the default is unchanged.
   - Con: a caller-supplied clock moves every expiry check, so it must be
     trusted like the stores and key sources the caller already supplies.
2. **Remove `Clock`; packages always read `time.Now`**
   - Pro: smaller API.
   - Con: breaking change; takes away a legitimate integration point only
     because the repository's own tests no longer need it.
3. **Unexport the fields and set them from `export_test.go`**
   - Pro: tests unchanged.
   - Con: keeps test-only state in production structs.

For the session test hooks:

1. **Remove them; test with synctest and a test-side wrapper store
   (chosen)**
   - Pro: production code free of test markers; `MemoryStore` is a plain
     `Store`.
   - Con: breaking change for anyone calling the hooks (no known consumer).
2. **Keep them**
   - Pro: no break.
   - Con: test instrumentation on a public type and a context marker in the
     rotation path.

## Decision

We will expose the following public API, and nothing else:

| Package | Public | Why |
|---|---|---|
| `authentication` | `Principal`, `Credential`, `CredentialKindJWT`, `CredentialKindBearer`, `ValidatePrincipal`, `Authenticator`, `FederatedProvider`, `BeginRequest`, `Redirect`, `Callback`, `Chain`, `ContextWithPrincipal`, `PrincipalFromContext`, sentinel errors | Contracts every package and consumer shares |
| `authentication/jwt` | `Verifier`, `NewVerifier`, `Options`, `KeySource`, `ClaimsMapper` | Verifier configuration and extension points |
| `authentication/apitoken` | `Manager`, `NewManager`, `Options`, `IssueRequest`, `Identity`, `IdentityFromPrincipal`, `Record`, `Store`, `MemoryStore`, `NewMemoryStore`, `ValidRecord`, `ValidID`, `ErrNotFound`, `CredentialKind`, `Method`, `ScopeTrait`, `TokenIDTrait` | Token lifecycle and the store contract; validation helpers for store implementers |
| `authentication/middleware` | `HTTP`, `Option`, `WithRealm`, `WithCookie`, `WithAnonymous`, `WithMaxTokenBytes`, `CredentialFromAuthorizationHeader`, `MaxAuthorizationBytes`, `SourceAttribute`, `SourceAuthorization`, `SourceCookie` | Transport adapters |
| `authentication/oidc` | `Provider`, `New`, `Options`, `StateStore`, `MemoryStateStore`, `NewMemoryStateStore`, `Pending`, `Secret`, `NewSecret`, `StateDigest` | Provider plus callback-state contract shared with `oauth2` and `device` |
| `authentication/oauth2` | `Provider`, `New`, `Options`, `UserInfoMapper` | Provider |
| `authentication/saml` | `Provider`, `New`, `Options`, `Claims`, `ClaimsMapper`, `Request`, `RequestStore`, `MemoryRequestStore`, `NewMemoryRequestStore` | Provider and request-state contract |
| `authentication/sso` | `Registry`, `NewRegistry`, `Registration` | Provider selection |
| `authentication/metadata` | `Cache`, `NewCache`, `Document`, `Loader`, `LoaderFunc` | Metadata cache |
| `authentication/magiclink` | `Service`, `NewService`, `Options`, `Link`, `Record`, `Store`, `MemoryStore`, `NewMemoryStore` | Links and the store contract |
| `authentication/device` | `Client`, `New`, `Options`, `Authorization`, `Error`, `ErrAccessDenied`, `ErrServer` | Device grant client |
| `authentication/session` | `Manager`, `NewManager`, `Options`, `Session`, `ClientInfo`, `Store`, `RevocationStore`, `MemoryStore`, `NewMemoryStore`, `MemoryRevocationStore`, `NewMemoryRevocationStore` | Session lifecycle and store contracts |
| `authorization` | `Request`, `Entity`, `Decision`, `Authorizer`, `PolicySource`, `EntitySource`, sentinel errors | Authorization contracts |
| `authorization/cedar` | `Engine`, `New`, `Options` | Cedar implementation |

Internal:

| Package | Contents | Why internal |
|---|---|---|
| `internal/authtest` | `HandlerTransport`, `Client`: in-memory HTTP transport | Test helper used only by this repository's tests |

`Options.Clock` stays public in `apitoken`, `jwt`, `magiclink`, `oauth2`,
`oidc`, `saml` and `session`. A nil `Clock` selects `time.Now`, and every
time check and stored timestamp uses the clock's value converted to UTC.
Time-dependent tests run in `testing/synctest` bubbles (ADR-0011) rather
than through it; one test per package checks that a supplied `Clock` is
honoured (FR-AUTH-27).

Removed in this release (breaking, `v0.x`):

- `session.MemoryStore.FailNextCompareAndSwap`,
  `session.MemoryStore.ObservedGetWhileLocked` and the internal lease
  context marker; tests use a wrapper store that checks the fake
  coordinator's lease state instead.

Likewise, `Options.Random` readers stay public: they are documented as
requiring a cryptographically secure source, and let callers plug in a
hardware or audited entropy source.

## Consequences

### Positive
- No exported identifier exists only for tests.
- Callers keep control over the time source; the default is unchanged.

### Negative
- A supplied `Clock` is trusted: a wrong clock moves every expiry check.
  The field documentation says what each package uses it for.
- Callers of the removed session test hooks must drop those calls (compile
  error, no behaviour change otherwise).

### Follow-ups
- Store conformance suites, when added, will be public (ADR-0008).

## Links

- [CHANGELOG.md](../../CHANGELOG.md)
