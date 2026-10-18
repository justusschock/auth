# ADR 0003: Dependency policy

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | ADR-0002 |

## Context

Recorded retrospectively for the first public release. Authentication code is
where hand-rolled cryptography and protocol parsing are most dangerous, yet
every dependency also enlarges the attack and maintenance surface. The module
imports these modules directly (and nothing else outside the standard
library):

| Module | Used by | Why |
|---|---|---|
| `github.com/golang-jwt/jwt/v5` | `jwt` | JWS parsing and signature verification, registered-claim validation with leeway |
| `golang.org/x/oauth2` | `oauth2`, `oidc`, `device` | Authorization code exchange, PKCE, RFC 8628 polling (pending / slow_down handling) |
| `github.com/coreos/go-oidc/v3` | `oidc`, `device` | ID token verification (JWKS, signatures) and discovery |
| `github.com/crewjam/saml` | `saml` | SAML message types, AuthnRequest construction and signing |
| `github.com/russellhaering/goxmldsig` | `saml` | XML signature validation against metadata certificates |
| `github.com/beevik/etree` | `saml` | XML tree handling for signature validation |
| `github.com/mattermost/xml-roundtrip-validator` | `saml` | Rejects XML that does not round-trip (signature-wrapping defence) |
| `github.com/cedar-policy/cedar-go` | `authorization/cedar` | Cedar policy parsing and evaluation |
| `github.com/justusschock/cache` | `metadata` | Cache contract for provider metadata |
| `github.com/justusschock/distributed-coordination` | `session` | Leases with fencing tokens for refresh-token rotation |

## Decision drivers

- D1: Never implement signature verification, XML canonicalisation or a
  policy language in this module.
- D2: Keep each dependency confined to the package that needs it (ADR-0002).
- D3: Keep the transport layer free of protocol code.
- D4: Make adding a dependency a visible, reviewed decision.

## Considered options

1. **Standard library first; vetted, widely used libraries for protocol and
   crypto work; own libraries for cache and coordination contracts (chosen)**
   - Pro: security-critical parsing comes from maintained, reviewed
     projects; contracts for cache and leases are shared with other
     libraries of the same author instead of being redefined.
   - Con: transitive dependencies (go-jose, x/crypto, ...) must be tracked;
     crewjam/saml has process-global time settings, which `saml` therefore
     bypasses (ADR-0006).
2. **Implement protocols on the standard library only**
   - Pro: no third-party code.
   - Con: XML signatures, JOSE and Cedar are large, subtle specifications;
     reimplementing them is the larger risk.
3. **Depend on a full identity framework**
   - Pro: more features.
   - Con: far larger surface, framework lifecycle, harder to keep packages
     independent.

## Decision

We will use the standard library first and only the third-party modules in
the table above, each imported only by the packages listed. The
`authentication/middleware` package uses only the standard library and
`authentication` (`TestMiddlewareUsesOnlyStandardLibrary`). Direct imports are
checked against this list by `TestDirectDependenciesAreAllowlisted`; adding a
module needs a new ADR and an update of that test. Versions of
`github.com/justusschock/go-*` modules are managed in lockstep with those
libraries' releases; Dependabot proposes updates of everything else weekly.

## Consequences

### Positive
- The dependency surface is explicit and enforced in CI.
- Importing `jwt` or `apitoken` does not link the SAML or Cedar stacks.

### Negative
- Security fixes in dependencies must be picked up promptly (Dependabot,
  `go mod verify` in CI).

### Follow-ups
- Re-evaluate crewjam/saml if an alternative without process-global state
  becomes viable.

## Links

- `separation_test.go`
