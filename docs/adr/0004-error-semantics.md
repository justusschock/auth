# ADR 0004: Fail-closed, sanitized sentinel errors

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001, ADR-0005 |

## Context

Recorded retrospectively for the first public release. Authentication errors
travel to logs, HTTP responses and metrics. Errors from stores, parsers, key
sources or identity providers can contain tokens, assertions, request
parameters echoed by a server, or database details. Detailed rejection
reasons also help attackers probe which check failed.

The code consistently:

- declares a small set of sentinels: `authentication.ErrInvalidPrincipal`,
  `ErrInvalidCredential`, `ErrUnauthenticated`, `ErrExpired`, `ErrReplay`,
  `ErrInvalidCallback`, `ErrProviderNotFound`, `ErrUnsupportedCredential`;
  `authorization.ErrInvalidConfiguration`, `ErrInvalidRequest`, `ErrSource`,
  `ErrInvalidSource`; package-specific `apitoken.ErrNotFound`,
  `device.ErrAccessDenied`, `device.ErrServer` and the typed `*device.Error`
  (which unwraps to `ErrUnauthenticated` and keeps only a validated OAuth
  error code and HTTP status);
- maps every store, parser, key-source and mapper error to one of them
  (`sanitize`, `sanitizeStoreError`, `sanitizeStateStoreError`), passing
  through only known sentinels and the caller's own `ctx.Err()`;
- returns the generic `ErrUnauthenticated` for every verification failure
  (bad signature, wrong audience, nonce mismatch, ...), and distinguishes
  only states a caller must act on: `ErrExpired` (re-authenticate),
  `ErrReplay` (one-time value reused), `ErrInvalidCallback` /
  `ErrInvalidCredential` (malformed input or configuration);
- uses `ErrUnsupportedCredential` to mean "not mine": `Chain` tries the next
  authenticator only on that error, so a recognised but invalid credential
  never falls through to a weaker authenticator;
- treats every non-nil authorization error as "deny", and forces
  `Decision.Allowed = false` when Cedar reports evaluation errors.

## Decision drivers

- D1: No credential material or backend detail in any error.
- D2: Callers need to tell "expired", "replayed" and "malformed" apart from
  "rejected".
- D3: Ambiguity must never authorize.
- D4: Errors must be testable with `errors.Is`.

## Considered options

1. **Fixed sentinels, sanitized at every boundary, fail closed (chosen)**
   - Pro: nothing sensitive can leak through wrapping; uniform handling.
   - Con: less diagnostic detail for operators; debugging relies on the
     caller's own store and provider logs.
2. **Wrapped errors with context (`fmt.Errorf("...: %w", err)`)**
   - Pro: rich diagnostics.
   - Con: wrapped messages may contain secrets or echo attacker input;
     reveals which check failed.
3. **Typed error structs with reason codes for every check**
   - Pro: machine-readable detail.
   - Con: same oracle problem; larger API.

## Decision

We will return only the sentinels above (and the caller's context errors)
from authentication and authorization operations, mapping any other error to
the closest sentinel without wrapping it. Verification failures collapse to
`ErrUnauthenticated`. Constructors report invalid options with
`ErrInvalidCredential`, `ErrInvalidCallback` or
`ErrInvalidConfiguration`. The only wrapped errors are `device.ErrServer`
errors for transport failures and OpenID Connect discovery, which wrap the
URL or discovery error of a request that carries no secret; device and token
endpoint response bodies, which may echo the device code, are never
included. Tests assert exact sentinels
(`err != ErrUnauthenticated`), which is why errorlint's comparison check is
disabled for test files.

## Consequences

### Positive
- `TestAuthenticationErrorsDoNotContainCredentials`, the
  `...SanitizesStoreErrors` tests and the fuzz targets can assert that no
  input leaks into errors.
- Composition through `Chain` is safe by construction.

### Negative
- Operators get little detail from the library; they must log at their
  stores and identity providers.
- Wrapping a sentinel in a future change is a behaviour change that needs an
  ADR.

### Follow-ups
- None.

## Links

- `authentication/errors.go`, `authorization/errors.go`
