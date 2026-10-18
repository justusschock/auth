# Changelog

All notable changes to this module are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
module follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While the major version is 0, a minor release may contain breaking changes;
they are listed here and backed by an ADR.

## [Unreleased]

Preparation for the first public release.

### Removed (breaking)

- `Clock func() time.Time` fields from `apitoken.Options`, `jwt.Options`,
  `magiclink.Options`, `oauth2.Options`, `oidc.Options`, `saml.Options` and
  `session.Options`. They existed only so tests could pin the current time;
  the packages now use `time.Now` and the tests use `testing/synctest`
  (ADR-0009). Remove the field from option literals; no other change is
  needed.
- `session.MemoryStore.FailNextCompareAndSwap` and
  `session.MemoryStore.ObservedGetWhileLocked`, test instrumentation that is
  now implemented inside the tests (ADR-0009).

### Added

- Package documentation and doc comments for every exported identifier, and
  runnable examples (`Example`, `apitoken.ExampleManager`,
  `middleware.ExampleHTTP`).
- `SECURITY.md` with the private vulnerability reporting process; `NOTICE`.
- `docs/`: retrospective PRD (requirements `FR-AUTH-*`, `NFR-AUTH-*`) and
  ADRs, including the security model (secret handling, constant-time
  comparisons, expiry, clock-skew and TTL rules).
- `testing/synctest` tests for JWT expiry with clock skew, the magic-link TTL
  boundary, OIDC/OAuth2 state expiry, the SAML request TTL and assertion
  lifetime with skew, and the session lifetime boundary.
- A test that keeps direct third-party imports to the allowlist in ADR-0003.

### Changed

- Minimum Go version is 1.26 (unchanged `go` directive), recorded in ADR-0010;
  CI tests 1.26, oldstable and stable.
- CI uses only public dependencies, pins every action to a commit SHA, runs
  golangci-lint and checks that `go.mod` is tidy; Dependabot keeps Go modules
  and actions current.
- OIDC and OAuth2 tests serve token endpoints in memory instead of on
  loopback sockets.

### Fixed

- `saml` compares the XML decoder's end-of-input error with `errors.Is`.

## [0.4.0] and earlier

Released before this changelog was kept; see the Git history for
`v0.2.0`, `v0.3.0` and `v0.4.0`.

[Unreleased]: https://github.com/justusschock/go-auth/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/justusschock/go-auth/releases/tag/v0.4.0
