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
`jwt.ClaimsMapper`. None set a `Clock` option or use the session test hooks.

The review found two kinds of exported implementation detail:

1. `Clock func() time.Time` fields in `apitoken.Options`, `jwt.Options`,
   `magiclink.Options`, `oauth2.Options`, `oidc.Options`, `saml.Options` and
   `session.Options`. They existed so tests could pin "now"; no consumer set
   them, and `testing/synctest` now gives tests deterministic time without
   them.
2. `session.MemoryStore.FailNextCompareAndSwap` and
   `ObservedGetWhileLocked`, test instrumentation on a public type, backed by
   an unexported context marker set by `Manager.Rotate` in production code.

## Decision drivers

- D1: The public surface is exactly what users need.
- D2: No production code paths that exist only for tests.
- D3: Never break known consumers.
- D4: Security-relevant behaviour must not be overridable through test hooks
  (a caller-supplied clock can move every expiry check).

## Considered options

1. **Remove the test-only identifiers; test with synctest and test-side
   wrappers (chosen)**
   - Pro: smaller API; no clock injection that could be misused to disable
     expiry; production code free of test markers.
   - Con: breaking change for anyone who set `Clock` (no known consumer).
2. **Keep `Clock` as a feature ("trusted time source")**
   - Pro: no break; lets callers verify historic tokens.
   - Con: no consumer needs it; widens the attack surface of every expiry
     rule; still requires tests to go through it.
3. **Unexport the fields and set them from `export_test.go`**
   - Pro: tests unchanged.
   - Con: keeps test-only state in production structs.

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

Removed in this release (breaking, `v0.x`):

- `Clock` from `apitoken.Options`, `jwt.Options`, `magiclink.Options`,
  `oauth2.Options`, `oidc.Options`, `saml.Options`, `session.Options`; the
  packages use `time.Now`.
- `session.MemoryStore.FailNextCompareAndSwap`,
  `session.MemoryStore.ObservedGetWhileLocked` and the internal lease
  context marker; tests use a wrapper store that checks the fake
  coordinator's lease state instead.

`Options.Random` readers stay public: they are not time-related, are
documented as requiring a cryptographically secure source, and let callers
plug in a hardware or audited entropy source.

## Consequences

### Positive
- No exported identifier exists only for tests.
- Expiry rules cannot be bypassed through configuration.

### Negative
- Callers who set `Clock` must delete that field (compile error, no
  behaviour change otherwise).

### Follow-ups
- Store conformance suites, when added, will be public (ADR-0008).

## Links

- [CHANGELOG.md](../../CHANGELOG.md)
