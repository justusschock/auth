# ADR 0006: Expiry, clock-skew and TTL rules

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001, ADR-0005, ADR-0009, ADR-0011 |

## Context

Recorded retrospectively for the first public release. Every credential in
the library has a lifetime, and federated protocols compare timestamps made
by another machine's clock. Off-by-one boundaries, unbounded skew or
lifetimes, and time zones are classic sources of authentication bypasses.
This ADR records the rules as implemented.

### Common rules

- All lifetimes use half-open intervals: a value is valid while
  `now < ExpiresAt` and expired from `now == ExpiresAt` on
  (`authentication.ErrExpired`).
- Library-produced times are UTC; `authentication.ValidatePrincipal`
  rejects principals whose `AuthenticatedAt` or `ExpiresAt` is not UTC, is
  zero, is unordered, or has `AuthenticatedAt > now`.
- `now` is `time.Now()`, read once per operation; there is no injectable
  clock (ADR-0009).
- Clock skew is explicit, bounded per protocol and never applied to
  library-minted state (magic links, OAuth/SAML request state, API tokens,
  sessions), whose times come from the same process.
- One-time state is consumed before its expiry is checked (ADR-0005).

### Per package

| Package | Lifetime / TTL | Skew |
|---|---|---|
| `jwt` | `exp` and `iat` required; `exp − iat ≤ Options.MaxLifetime` (required); `nbf ≤ exp`; `iat < exp` | `Options.ClockSkew` (default 0) applied to `exp`, `nbf` and `iat`-in-the-future checks |
| `apitoken` | `Options.MaxTTL` bounds `IssueRequest.TTL` (default 365 days); expired from `ExpiresAt` | none |
| `magiclink` | `Options.TTL`, at most 15 minutes | none |
| `oidc`, `oauth2` | callback state expires after `Options.StateTTL` (default 10 minutes); ID token `exp`/`iat` checked by go-oidc and again by `ValidatePrincipal` | as configured in the caller's go-oidc verifier |
| `saml` | pending request 10 minutes; assertion lifetime = min(`Conditions/@NotOnOrAfter`, bearer `SubjectConfirmationData/@NotOnOrAfter`, `AuthnStatement/@SessionNotOnOrAfter`) | `Options.AllowedClockSkew` (default 2 minutes, never negative) on `NotBefore`, `NotOnOrAfter` and issue instants |
| `device` | `expires_in` required; polling stops with `ErrExpired` at the expiry; default interval 5 s, `slow_down` adds 5 s, interval ≤ 1 h | none |
| `session` | `Options.Lifetime` ≤ 24 h; a session whose stored lifetime exceeds the manager's is rejected; the principal must still be valid | none |
| `authentication` | `Principal` validity window | none |

### Skew normalization of returned principals

A principal accepted *because of* skew would itself be invalid at `now`
(issued in the future, or already expired). Both `jwt` and `saml` therefore
return principals that satisfy `ValidatePrincipal(principal, now)`:

- `jwt` clamps `AuthenticatedAt` to `now` when `iat` is in the future within
  skew, and sets `ExpiresAt` to `now + 1ns` when `exp` has passed within
  skew.
- `saml` extends the principal's `ExpiresAt` by the skew only when the
  signed expiry has already passed; `AuthnInstant` must not be in the future
  at all.

### Issue instants (SAML)

Response and assertion `IssueInstant` must be no later than `now + skew` and
no earlier than `now − (10 minutes + skew)`. The bearer
`SubjectConfirmationData` must not carry `NotBefore`.

### Independence from library globals

crewjam/saml validates times with process-global variables (`TimeNow`,
`Clock`, `MaxIssueDelay`, `MaxClockSkew`). `saml` does not use its
high-level response parser; it validates signatures with goxmldsig using its
own clock and applies the rules above itself, so other code changing those
globals cannot widen this provider's acceptance window
(`TestCompleteIgnoresCrewjamTemporalGlobals`).

## Decision drivers

- D1: No boundary ambiguity: tests can state the last valid instant.
- D2: Skew only where clocks genuinely differ, and always bounded.
- D3: Every lifetime has an upper bound.
- D4: Returned principals are valid for downstream checks at the time they
  are returned.

## Considered options

1. **Half-open intervals, per-protocol bounded skew, normalized principals
   (chosen)**
   - Pro: precise, testable boundaries; skew cannot leak into downstream
     authorization or session checks.
   - Con: a principal accepted within skew has a slightly shortened or
     clamped lifetime.
2. **Global skew setting applied everywhere**
   - Pro: one knob.
   - Con: widens windows for library-minted state that needs none; couples
     protocols.
3. **Closed intervals (`now <= ExpiresAt`)**
   - Pro: matches some specifications' wording.
   - Con: inconsistent with JWT `exp` and SAML `NotOnOrAfter` semantics,
     which are exclusive.

## Decision

We will treat expiry as exclusive, bound every lifetime and TTL as in the
table, apply clock skew only to timestamps produced by another party and only
up to the configured, bounded amount, normalize principals accepted within
skew so they validate at `now`, and keep SAML time checks independent of
crewjam/saml's globals. Changing any bound, default or boundary needs a
superseding ADR.

## Consequences

### Positive
- Each rule has a synctest test that walks virtual time up to and across its
  boundary (ADR-0011).

### Negative
- Callers needing longer magic links or sessions than the hard bounds must
  change the library through an ADR.

### Follow-ups
- None.

## Links

- RFC 7519 §4.1.4–4.1.6; SAML 2.0 Core §2.5.1, Profiles §4.1.4.2; RFC 8628
  §3.5
