# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is `0`, a minor release may break the API.

## [Unreleased]

## [0.2.0] - 2026-10-25

### Added

- `authorization/cedar`: `Policy`, `Effect` (`Permit`, `Forbid`) and
  `Policies`, a policy source that builds Cedar policies from the same
  principal, action and resource values a request uses. Every policy names
  a resource type; every entity is validated and every ID escaped
  (ADR-0012).

### Changed

- **Breaking:** `authorization.Request` uses the distinct types
  `authorization.Principal{Type, ID}`, `authorization.Action{ID}` and
  `authorization.Resource{Type, ID}`, so the compiler rejects mixed-up
  fields. `authorization.Entity` is removed; replace `authorization.Entity{...}`
  with the type of the field it is assigned to and drop `Type: "Action"` from
  actions, whose Cedar type is always `Action` (ADR-0012).

## [0.1.0] - 2026-10-18

First public release.

### Added

- Protocol-neutral contracts: `authentication.Credential`, `Principal`,
  `Authenticator`, `FederatedProvider` and `Chain`, and
  `authorization.Request`, `Decision` and `Authorizer`; the two packages do
  not import each other.
- `authentication/jwt`: a strict `Verifier` with required issuer, audience,
  algorithm allowlist, key IDs, maximum lifetime and explicit clock skew.
- `authentication/apitoken`: long-lived API tokens stored only as SHA-256 or
  peppered HMAC-SHA256 digests, with scopes, expiry, revocation and a
  `MemoryStore`.
- `authentication/middleware`: standard-library `HTTP` middleware with
  RFC 6750 challenges and `CredentialFromAuthorizationHeader` for other
  transports.
- Federated login: `authentication/oidc` and `authentication/oauth2`
  (authorization code with PKCE) and `authentication/saml` (SAML 2.0 service
  provider), with provider selection in `authentication/sso` and a
  metadata cache in `authentication/metadata`.
- `authentication/magiclink`: single-use magic links with bounded TTLs and
  exact redirect URIs.
- `authentication/device`: an OAuth 2.0 device authorization grant
  (RFC 8628) client.
- `authentication/session`: durable sessions with rotating refresh tokens,
  replay detection under a distributed lease, and session and principal
  revocation.
- `authorization/cedar`: a Cedar policy `Engine` with request-scoped
  entities, bounded inputs and default-deny on any evaluation error.
- Fail-closed sentinel errors such as `authentication.ErrUnauthenticated`,
  `ErrExpired` and `ErrReplay`.
- Security policy in `SECURITY.md`; requirements and architecture decision
  records under `docs/`.

Requires Go 1.26 or newer.

[Unreleased]: https://github.com/justusschock/auth/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/justusschock/auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/justusschock/auth/releases/tag/v0.1.0
