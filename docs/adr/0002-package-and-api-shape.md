# ADR 0002: Independent protocol packages around neutral contracts

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001, ADR-0003, ADR-0008 |

## Context

Recorded retrospectively for the first public release. The library covers
many protocols (JWT, OIDC, OAuth 2.0, SAML, API tokens, magic links, device
grant, sessions) and Cedar authorization. Applications typically need two or
three of them, and each pulls in different third-party code (XML signature
validation, OAuth clients, a policy engine). The code shows a consistent
shape:

- `authentication` defines `Credential`, `Principal`, `Authenticator`,
  `FederatedProvider` (Begin/Complete), `BeginRequest`, `Redirect`,
  `Callback`, `Chain` and context helpers; every protocol package implements
  one of the two interfaces.
- `authorization` defines `Request`, `Entity`, `Decision`, `Authorizer`,
  `PolicySource`, `EntitySource`; `authorization/cedar` implements it.
- Neither tree imports the other.
- Constructors take an `Options` struct, validate it completely and return
  an error (`New`, `NewVerifier`, `NewManager`, `NewService`); only the HTTP
  middleware uses functional options (`WithRealm`, `WithCookie`, ...) and
  panics on programmer errors, like `net/http` constructors.
- Values crossing the API are copied (`Clone` methods), so callers and
  authenticators never share mutable maps, slices or byte buffers.
- No generics in the API; interfaces are small (one to five methods).

## Decision drivers

- D1: Import only what you use; keep heavy dependencies out of unrelated
  packages.
- D2: Applications must be able to combine authenticators and swap
  authorizers without adapters.
- D3: Misconfiguration must fail at construction, not at the first request.
- D4: No aliasing bugs between caller-owned and library-owned state in
  security decisions.

## Considered options

1. **One package per protocol around small neutral contracts (chosen)**
   - Pro: dependency isolation (SAML's XML stack is only linked when `saml`
     is imported); uniform composition through `Chain` and
     `FederatedProvider`; authorization usable without authentication and
     vice versa.
   - Con: many packages; some small helpers (URL and text validation) are
     duplicated per package to keep them independent.
2. **A single `auth` package / framework with pluggable strategies**
   - Pro: one import, one configuration object.
   - Con: every user links every protocol's dependencies; strategies couple to
     a framework lifecycle; harder to audit.
3. **Generic authenticator types (`Authenticator[C, P]`)**
   - Pro: protocol-specific credential types.
   - Con: no common `Chain` or middleware without type erasure; the
     byte-token-plus-kind `Credential` already covers every transport.
4. **Functional options everywhere**
   - Pro: extensible without breaking struct literals.
   - Con: required fields are not visible in the type; validation of
     combinations is harder to document. Kept only for the middleware, whose
     options are all optional.

## Decision

We will keep one package per protocol under `authentication/` and the
authorization engine under `authorization/`, all built on the neutral
contracts in `authentication` and `authorization`. Constructors take
validated `Options` structs and return errors; values are cloned at API
boundaries; the two trees stay independent (enforced by
`TestAuthenticationAndAuthorizationAreIndependent`).

## Consequences

### Positive
- Each package can be adopted, audited and replaced on its own.
- `Chain`, `middleware.HTTP` and `sso.Registry` work with any implementation.

### Negative
- Adding a field to an `Options` struct is source compatible, but removing
  one is a breaking change (see ADR-0009).
- Small validation helpers are repeated across packages.

### Follow-ups
- Consider consolidating repeated URL/text validation into an `internal/`
  package once the behaviour is pinned by tests in every package.

## Links

- `separation_test.go`
