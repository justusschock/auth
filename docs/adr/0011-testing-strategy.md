# ADR 0011: Testing strategy

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001, ADR-0004, ADR-0006, ADR-0009, ADR-0010 |

## Context

Recorded retrospectively for the first public release. The library's value
is in what it rejects. Its history is dominated by `test:` commits that pin
security regressions before fixes. Much of the behaviour is time-dependent
(expiry, skew, TTLs, polling intervals) or concurrent (single use, rotation
races), and federated flows talk HTTP to identity providers.

## Decision drivers

- D1: Every rejection rule and boundary has a test that fails without it.
- D2: Deterministic tests: no wall-clock sleeps, no flaky boundaries.
- D3: Tests must run offline and without opening sockets where possible.
- D4: Untrusted-input parsers are exercised beyond hand-written cases.

## Considered options

1. **Black-box unit tests per package; `testing/synctest` for time and
   concurrency; in-memory HTTP; fuzz targets for parsers; architecture tests
   for dependencies (chosen)**
   - Pro: deterministic virtual time makes exact boundaries testable (the
     last valid nanosecond and the first invalid one); no injected clocks in
     the API (ADR-0009); no network.
   - Con: code inside a bubble must not block on real I/O, which forces
     in-memory transports.
2. **Injected fake clocks**
   - Pro: works on any Go version.
   - Con: test-only API surface on security components; every package must
     thread the clock through.
3. **Integration tests against real identity providers**
   - Pro: realistic.
   - Con: slow, credentials in CI, non-deterministic; the protocol libraries
     already test interoperability.

## Decision

We will test as follows:

- **Unit tests** in `_test` packages through the public API, one file per
  package area; internal tests (`token_internal_test.go`) only where a
  property cannot be observed externally (constant-time digest comparison,
  token parsing).
- **`testing/synctest`** for every test whose outcome depends on time or
  goroutine interleaving: `time.Now` is fixed inside the bubble and
  `time.Sleep` advances virtual time instantly, so tests walk across expiry,
  skew and TTL boundaries exactly (for example
  `TestVerifierExpiryAndClockSkewOverTime`, `TestConsumeHonorsTTLBoundary`,
  `TestAuthenticateExpiry`, `TestPollStopsAtAuthorizationExpiry`,
  `TestCompleteAssertionLifetimeWithSkewOverTime`) and concurrent-winner
  tests run deterministically. Subtests wrap their own bubble (`t.Run` is not
  allowed inside one).
- **In-memory HTTP** (`internal/authtest`) for OIDC, OAuth2 and device
  endpoints; tests pass the client through `oauth2.HTTPClient` or
  `Options.HTTPClient`. `device.TestLoopbackServer` is the one deliberate
  real-socket test, outside any bubble, and needs local port binding.
- **Exact sentinel assertions** (`err != authentication.ErrUnauthenticated`)
  where sanitization is the property under test (ADR-0004), plus checks that
  no secret appears in error strings or formatted values.
- **Fuzz targets** for untrusted input: `FuzzJWTBytes`,
  `FuzzSAMLResponseBytes`, `FuzzMagicLinkTokens`, `FuzzAPITokens`,
  `FuzzAuthorizationHeader`, `FuzzCedarContext`, `FuzzParseToken`; their seed
  corpora run with every `go test`.
- **Architecture tests** (`separation_test.go`): authentication and
  authorization stay independent, middleware stays standard-library only,
  and direct dependencies match ADR-0003.
- **Examples** are tests (`// Output:`), and the root `Example` is the README
  quick start.
- **Race detector** always: CI runs `go test -race`; releases are checked
  with `-count=3`.
- **Traceability**: tests verifying a PRD requirement cite its ID in a
  comment.

## Consequences

### Positive
- Boundaries are asserted to the nanosecond without flakiness.
- The suite runs offline in seconds (SAML key generation dominates).

### Negative
- `TestLoopbackServer` fails in sandboxes that forbid binding local ports.
- No shared store conformance suite yet (ADR-0008).

### Follow-ups
- Store conformance suites (ADR-0008).

## Links

- https://pkg.go.dev/testing/synctest
