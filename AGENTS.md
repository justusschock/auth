# AGENTS.md

Rules for anyone, human or agent, changing go-auth. They are binding. If a
change has to break one, say so in the pull request and, where it is a design
decision, record it in an ADR.

go-auth is a set of independent Go packages for authentication (JWT, OIDC,
OAuth 2.0, SAML, API tokens, magic links, device grant, sessions) and Cedar
authorization behind protocol-neutral contracts. Its requirements and design
decisions are recorded in [docs/](docs/README.md).

This is security-sensitive code. Never weaken a check (signature, issuer,
audience, nonce, state, PKCE, expiry, clock skew, single use, revocation,
input bounds, constant-time comparison, error sanitization) as a side effect
of a refactor. A deliberate change to the security model needs a new ADR
superseding [ADR-0005](docs/adr/0005-secret-handling-and-comparisons.md) or
[ADR-0006](docs/adr/0006-expiry-clock-skew-and-ttls.md). Vulnerabilities are
reported privately ([SECURITY.md](SECURITY.md)), never in public issues or
pull requests.

## Docs first

No behaviour is added or changed before the documents that govern it say so.

- **PRDs** (`docs/prd/NNNN-title.md`, from [the template](docs/prd/TEMPLATE.md))
  state *what* the library does: problem, use cases, goals and non-goals,
  functional requirements `FR-<AREA>-NN`, non-functional requirements
  `NFR-<AREA>-NN`, API sketch, acceptance criteria mapped to named tests, open
  questions. This library's area code is `AUTH`.
- **ADRs** (`docs/adr/NNNN-title.md`, MADR style, from
  [the template](docs/adr/TEMPLATE.md)) state *how and why*: context, decision
  drivers, considered options with pros and cons, decision, consequences.
- **Lifecycle.** New PRDs and ADRs start as `Proposed` and are reviewed in a
  pull request; merged, they become `Accepted`. Implementation follows
  acceptance — for small changes in the same pull request, as separate
  commits, documents first.
- A decision made while implementing gets a new ADR **in the same pull
  request as the code**. Changing public API, adding a dependency, changing a
  wire or persistence format, or changing error, concurrency or cancellation
  semantics always needs one. So does any change to token formats, digests,
  comparisons, expiry or clock-skew rules.
- **Accepted ADRs are never edited**, except for their status line. To change
  a decision, add a new ADR with `Supersedes: ADR-NNNN` and set the old one to
  `Superseded by ADR-MMMM`.
- PRDs are kept current: a pull request that changes behaviour updates the
  requirements it touches. Requirement IDs are never reused or renumbered.
- [docs/README.md](docs/README.md) indexes every PRD and ADR with its status;
  update it whenever a document is added or changes status.
- **Traceability.** Tests cite the requirement they verify in a comment
  (`// FR-AUTH-03`). Every functional requirement has at least one test.

## Public API

- The public API is every exported identifier outside `internal/`. It is
  documented, covered by tests and examples, and changed only through an ADR.
- Implementation details live under `internal/` or stay unexported. Do not
  export something only to test it; test from inside the package instead.
  Options exist for callers, not for tests: do not add clock or similar
  test-only injection points (use `testing/synctest`).
- Test helpers used only by this repository live in `internal/`.
- Versioning follows semver. While the major version is `0`, a minor release
  may break the API; every break is listed in `CHANGELOG.md` and backed by an
  ADR.

## Layout

Single module `github.com/justusschock/go-auth`; the root holds only
module-level tests and the README example.

- `authentication/`: neutral contracts (`Credential`, `Principal`,
  `Authenticator`, `FederatedProvider`), `Chain`, principal context helpers,
  sentinel errors.
- `authentication/jwt/`: strict signed-JWT verifier.
- `authentication/apitoken/`: API token manager, `Store` contract,
  `MemoryStore`.
- `authentication/middleware/`: `net/http` middleware and `Authorization`
  header parser; standard library and `authentication` only.
- `authentication/oidc/`: OIDC authorization code + PKCE provider and the
  callback state types shared with `oauth2` and `device`.
- `authentication/oauth2/`: plain OAuth 2.0 authorization code + PKCE
  provider.
- `authentication/saml/`: SAML 2.0 service provider.
- `authentication/sso/`: provider selection by name or e-mail domain.
- `authentication/metadata/`: provider metadata cache on go-cache.
- `authentication/magiclink/`: single-use magic links.
- `authentication/device/`: RFC 8628 device authorization client.
- `authentication/session/`: durable sessions with lease-protected rotation.
- `authorization/`: authorization contracts.
- `authorization/cedar/`: Cedar engine.
- `internal/authtest/`: in-memory HTTP transport for tests (not public).

`authentication/...` and `authorization/...` never import each other
(enforced by `separation_test.go`).

## Engineering rules

1. **Small, explicit contracts.** Every exported type and function documents
   its behaviour, errors, concurrency safety and cancellation.
2. **Dependencies.** Standard library first. Third-party modules only where
   [ADR-0003](docs/adr/0003-dependency-policy.md) allows them; a new
   dependency needs an ADR and an entry in
   `TestDirectDependenciesAreAllowlisted`. `authentication/middleware` stays
   standard-library only.
3. **Errors.** Sentinel errors are part of the API; test with `errors.Is`.
   Authenticators return the exact sentinel and never wrap store, parser or
   key-source errors, which could carry secrets
   ([ADR-0004](docs/adr/0004-error-semantics.md)).
4. **Context.** Operations that block or do I/O take `ctx context.Context`
   first and honour cancellation.
5. **No logging in the library.** Report through return values; never write
   to stdout/stderr or a global logger, and never put credential material in
   errors or `String` output.
6. **Concurrency.** Every exported type states whether it is safe for
   concurrent use; tests run with the race detector.
7. **Randomness.** Secrets come from `crypto/rand` (256 bits); comparisons of
   presented secrets against stored ones are constant time.

## Testing

- Unit tests for every package; examples (`example_test.go`) for public entry
  points. The root `Example` is the README quick start: keep them in sync.
- **`testing/synctest`** for anything involving time or concurrency
  (expiry, clock skew, TTLs, polling intervals, leases, goroutine
  coordination). No real `time.Sleep` waits in tests. HTTP endpoints are
  served in memory with `internal/authtest` so tests can run in bubbles; the
  only real-socket test is `device.TestLoopbackServer`.
- Security regressions get a test that fails without the fix; fuzz targets
  (`security_test.go`, `FuzzParseToken`) cover parsers of untrusted input.
- Stores you add must satisfy the documented contract (atomic consume,
  `ErrReplay` on duplicates); there is no shared conformance suite yet.
- Tests are deterministic and pass with `go test -race -count=3 ./...`.

## Workflow

- Branch from `main`, open a pull request, merge only with green CI. Nothing
  is pushed to `main` directly.
- Commit subjects use conventional-commit prefixes (`feat:`, `fix:`,
  `refactor:`, `docs:`, `test:`, `ci:`, `chore:`; `!` for breaking changes)
  and say what changed; the body says why.
- Before opening a pull request:

  ```sh
  gofmt -l .                     # prints nothing
  go vet ./...
  go test -race -count=1 ./...
  golangci-lint run ./...
  go mod tidy && git diff --exit-code go.mod go.sum
  ```

  The repository has a single module. `.pre-commit-config.yaml` runs gofmt,
  vet and tests as optional local hooks.
- CI workflows pin every action to a full commit SHA, use only `push` and
  `pull_request` triggers (never `pull_request_target`) and read-only
  permissions. Dependabot keeps Go modules and actions current.
- Releases are tags `vX.Y.Z` on `main`, with the changelog section as release
  notes.
