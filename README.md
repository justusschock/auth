# go-auth

Composable authentication and Cedar-based authorization for OIDC, OAuth2, SAML, JWT, SSO, and magic links.

> **Status:** Initial implementation is available.

Module path: `github.com/justusschock/go-auth`

## Scope

Independently importable authentication and authorization packages with identities, sessions, OIDC, OAuth2, SAML, JWT, magic links, Cedar policies, and revocation.

This library is private and intended for reuse by future Go projects.

## Target platform dependencies

Required imports:

- [`go-cache`](https://github.com/justusschock/go-cache)
- [`go-distributed-coordination`](https://github.com/justusschock/go-distributed-coordination)

Optional adapter imports:

None currently planned.

Optional integrations must remain one-way: concrete adapters import their neutral contracts, never the reverse.

## Design constraints

- Keep public contracts independent of product-specific resource types.
- Keep the dependency graph acyclic; imports point toward lower-level mechanisms.
- Put generic lifecycle transfer in `go-lifecycle/handoff` and finite resource-right transfer in `go-resources/handoff`.
- Use `go-cache` only for reconstructible, disposable state, never correctness-critical state.

## Composing authenticators

`authentication.Chain(a, b, ...)` tries authenticators in order. An
authenticator that does not handle a credential returns
`authentication.ErrUnsupportedCredential` and the next one is tried; the first
other result (success or failure) wins, so a recognized but invalid credential
never falls through. `authentication.ContextWithPrincipal` and
`authentication.PrincipalFromContext` carry the authenticated principal
through request contexts. `jwt.Verifier` rejects foreign kinds with
`ErrUnauthenticated`, so place it last in a chain.

## API tokens

`authentication/apitoken` issues personal and service tokens of the form
`<prefix>_<id>_<secret>` (for example `dtc_<26 chars>_<52 chars>`). The ID is
128 random bits and the secret 256 random bits from `crypto/rand`, both
lowercase base32 without padding.

- Only a digest of the whole token is stored: HMAC-SHA256 keyed with
  `Options.Pepper` (32-1024 bytes, kept outside the token database) or, without
  a pepper, SHA-256. The 256-bit secret makes an unpeppered digest infeasible to
  brute-force; the pepper additionally keeps a leaked database from confirming
  tokens. Rotating the pepper invalidates every token.
- Digests are compared with `crypto/subtle` before revocation or expiry are
  inspected, and errors never contain token material.
- `Manager` implements `authentication.Authenticator` for credentials of kind
  `apitoken` or `bearer` with its prefix, and returns
  `ErrUnsupportedCredential` for everything else. The rebuilt principal carries
  the issuing identity, `Methods: ["apitoken"]`, and the traits
  `apitoken.ScopeTrait` (`"scope"`) and `apitoken.TokenIDTrait`.
- `Store` is the persistence contract; `MemoryStore` is for tests and
  single-process use. Last-used updates are throttled and best effort.

```go
manager, _ := apitoken.NewManager(apitoken.Options{Store: store, Prefix: "dtc", Pepper: pepper})
token, record, _ := manager.Issue(ctx, apitoken.IssueRequest{
	Principal: apitoken.IdentityFromPrincipal(user),
	Name:      "ci",
	Scopes:    []string{"runs:write"},
	TTL:       90 * 24 * time.Hour,
})
```

## HTTP middleware

`authentication/middleware` depends only on the standard library and the
authentication contracts.

```go
auth := authentication.Chain(apiTokens, jwtVerifier)
handler := middleware.HTTP(mux, auth, middleware.WithRealm("dtc"))
```

`HTTP` reads one `Authorization: Bearer` header (or, with `WithCookie`, one
cookie), answers 401/400 with an RFC 6750 `WWW-Authenticate` challenge and a
generic body, and stores the principal in the request context. `WithAnonymous`
lets requests without any credential through. Cookie authentication requires
CSRF protection by the caller.

`middleware.CredentialFromAuthorizationHeader` parses the same header value for
other transports such as gRPC `authorization` metadata. JWS-shaped tokens get
kind `jwt`, everything else kind `bearer`.

## Device authorization for CLIs

`authentication/device` is an RFC 8628 client built on `golang.org/x/oauth2`:

```go
client, _ := device.New(ctx, device.Options{Issuer: issuer, ClientID: "dtc-cli", Scopes: []string{"offline_access"}})
authorization, _ := client.Start(ctx)
fmt.Printf("Open %s and enter %s\n", authorization.VerificationURI, authorization.UserCode)
token, idToken, err := client.Poll(ctx, authorization)
```

`Poll` keeps waiting on `authorization_pending`, waits 5 seconds longer after
`slow_down`, and maps `expired_token` (or reaching the expiry) to
`authentication.ErrExpired` and `access_denied` to `device.ErrAccessDenied`.
Server-provided codes and URIs are validated as printable ASCII and https (or
loopback http) before they are shown. The ID token is returned unverified; the
receiving server must verify it.

## Development

Install and run the repository hooks:

```bash
pre-commit install
pre-commit run --all-files
```

Once the module implementation exists, run its Go checks with:

```bash
go test ./...
```

Local implementation plans live under `docs/` and are intentionally excluded from Git.

## License

Apache License 2.0. See [LICENSE](LICENSE).
