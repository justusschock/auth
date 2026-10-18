# go-auth

go-auth is a set of small, independently importable Go packages for
authenticating users and services (JWT, OpenID Connect, OAuth 2.0, SAML 2.0,
API tokens, magic links, device authorization, server-side sessions) and for
authorizing requests with [Cedar](https://www.cedarpolicy.com/) policies. It is
for Go services and CLIs that want strict, fail-closed building blocks behind
protocol-neutral interfaces instead of a framework.

## Features

- **Protocol-neutral contracts**: `authentication.Credential`, `Principal`,
  `Authenticator`, `FederatedProvider`, `Chain` and request-context helpers;
  `authorization.Request`, `Decision` and `Authorizer`. Authentication and
  authorization do not import each other.
- **JWT verification** with required issuer, audience, algorithm allowlist,
  key IDs, maximum lifetime and explicit clock skew.
- **API tokens** (`<prefix>_<id>_<secret>`, 256-bit secrets) stored only as
  SHA-256 or peppered HMAC-SHA256 digests, compared in constant time, with
  scopes, expiry, revocation and throttled last-used tracking.
- **HTTP middleware** (standard library only) with RFC 6750 challenges, and an
  `Authorization` header parser for other transports such as gRPC.
- **Federated login**: OpenID Connect and OAuth 2.0 authorization code flow
  with PKCE, nonce and single-use hashed state; SAML 2.0 service provider with
  signed requests and strict response validation; SSO provider selection by
  name or e-mail domain; cached provider metadata.
- **Single-use magic links** with bounded TTLs and exact redirect URIs.
- **Device authorization grant** (RFC 8628) client for command-line tools.
- **Durable sessions** with rotating refresh tokens, replay detection under a
  distributed lease, and session and principal revocation.
- **Cedar authorization** with request-scoped entities, bounded inputs and
  default-deny on any evaluation error.

## Installation

```sh
go get github.com/justusschock/go-auth@latest
```

Requires Go 1.26 or later.

## Quick start

Authenticate a JWT and authorize the principal with a Cedar policy (from
[`example_test.go`](example_test.go)):

```go
ctx := context.Background()
key := []byte("example-key-with-at-least-32-bytes")

// Authentication: a strict JWT verifier.
verifier, err := authjwt.NewVerifier(authjwt.Options{
	Issuer:      "https://issuer.example",
	Audiences:   []string{"example-api"},
	Algorithms:  []string{"HS256"},
	Keys:        exampleKeys{key: key},
	ClockSkew:   time.Minute,
	MaxLifetime: 15 * time.Minute,
})
if err != nil {
	panic(err)
}

// A token as an identity provider would issue it.
now := time.Now()
token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{
	"iss": "https://issuer.example",
	"sub": "alice",
	"aud": []string{"example-api"},
	"iat": now.Add(-time.Minute).Unix(),
	"exp": now.Add(5 * time.Minute).Unix(),
})
token.Header["kid"] = "example-key"
signed, err := token.SignedString(key)
if err != nil {
	panic(err)
}

principal, err := verifier.Authenticate(ctx, authentication.Credential{
	Kind:  authentication.CredentialKindJWT,
	Token: []byte(signed),
})
if err != nil {
	panic(err)
}
fmt.Println("authenticated:", principal.ID)

// Authorization: Cedar policies evaluated per request, default deny.
engine, err := authcedar.New(authcedar.Options{
	Policies: examplePolicies(`permit(principal == User::"alice", action == Action::"read", resource);`),
	Entities: exampleEntities{},
})
if err != nil {
	panic(err)
}
for _, action := range []string{"read", "delete"} {
	decision, err := engine.Authorize(ctx, authorization.Request{
		Principal: authorization.Entity{Type: "User", ID: principal.Subject},
		Action:    authorization.Entity{Type: "Action", ID: action},
		Resource:  authorization.Entity{Type: "Document", ID: "report"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s allowed: %v\n", action, decision.Allowed)
}
// Output:
// authenticated: https://issuer.example|alice
// read allowed: true
// delete allowed: false
```

`exampleKeys`, `examplePolicies` and `exampleEntities` are three-line
implementations of `jwt.KeySource`, `authorization.PolicySource` and
`authorization.EntitySource`; see the example file. More runnable examples live
next to the packages (for example `apitoken.ExampleManager` and
`middleware.ExampleHTTP`).

Composing authenticators for an HTTP API:

```go
tokens, _ := apitoken.NewManager(apitoken.Options{Store: store, Prefix: "app", Pepper: pepper})
handler := middleware.HTTP(mux, authentication.Chain(tokens, jwtVerifier), middleware.WithRealm("app"))
```

`Chain` tries authenticators in order; one that does not recognise a credential
returns `authentication.ErrUnsupportedCredential` and the next is tried, while
any other result wins, so a recognised but invalid credential never falls
through. `jwt.Verifier` rejects every non-JWT credential, so place it last.

## Packages

Module path: `github.com/justusschock/go-auth`. The module root has no Go
package; import the packages below.

| Package | Purpose |
|---|---|
| `authentication` | Credential, Principal, Authenticator, FederatedProvider contracts; `Chain`; principal context helpers; sentinel errors |
| `authentication/jwt` | Strict signed-JWT `Verifier` |
| `authentication/apitoken` | Long-lived API tokens: `Manager`, `Store` contract, `MemoryStore` |
| `authentication/middleware` | `net/http` middleware and `Authorization` header parser (standard library only) |
| `authentication/oidc` | OpenID Connect authorization code + PKCE provider; shared callback state types (`StateStore`, `Pending`, `Secret`) |
| `authentication/oauth2` | Plain OAuth 2.0 authorization code + PKCE provider with a required user-info mapper |
| `authentication/saml` | SAML 2.0 service provider (SP-initiated, HTTP-Redirect request, HTTP-POST response) |
| `authentication/sso` | Provider selection by name or e-mail domain |
| `authentication/metadata` | Validated provider metadata cache on top of go-cache |
| `authentication/magiclink` | Single-use magic links |
| `authentication/device` | OAuth 2.0 device authorization grant (RFC 8628) client |
| `authentication/session` | Durable sessions with lease-protected refresh-token rotation and revocation |
| `authorization` | Request, Decision, Authorizer and policy/entity source contracts |
| `authorization/cedar` | Cedar `Engine` |

Packages under `internal/` are not part of the API and may change at any time.

## Design and guarantees

- **Fail closed.** Every malformed, ambiguous, oversized or unverifiable input
  is rejected. Verification failures surface as a few sentinel errors
  (`authentication.ErrUnauthenticated`, `ErrExpired`, `ErrReplay`, ...;
  `authorization.ErrInvalidRequest`, ...) that never contain credential
  material or backend detail; test them with `errors.Is`. A non-nil
  authorization error always means "not allowed".
- **Secrets.** Tokens, refresh tokens, magic links and callback state are
  generated from `crypto/rand` (256 bits) and stored only as digests; secrets
  that must be stored (nonce, PKCE verifier, device code) are wrapped in a
  redacting `oidc.Secret`. Presented API and refresh tokens are compared in
  constant time. See [SECURITY.md](SECURITY.md).
- **Time.** Expiry is checked against `time.Now`; clock skew is explicit and
  bounded per protocol, and one-time state is consumed before it is checked so
  an expired or invalid value cannot be retried.
- **Concurrency.** Authenticators, providers and in-memory stores are safe for
  concurrent use (given concurrency-safe stores you supply). Single-use state
  relies on atomic `Consume` in the store contracts; session rotation is
  serialized by a [go-distributed-coordination](https://github.com/justusschock/go-distributed-coordination)
  lease and a fenced compare-and-swap. Blocking operations take a
  `context.Context` and honour cancellation.
- **Storage is yours.** Each stateful package defines a small `Store`
  interface and ships a process-local `Memory*` implementation for tests and
  single-process use; production deployments plug in a durable store.
- **Stability.** The module is `v0.x`: minor releases may break the API. Every
  break is listed in [CHANGELOG.md](CHANGELOG.md).

## Documentation

- [docs/README.md](docs/README.md): the product requirements (PRD) and
  architecture decision records (ADRs), including the security model.
- API reference on [pkg.go.dev](https://pkg.go.dev/github.com/justusschock/go-auth).

## Contributing

Contributions are welcome through pull requests; nothing is pushed to `main`
directly. Read [AGENTS.md](AGENTS.md) first: it holds the rules for every
change (docs first, public API policy, testing with `testing/synctest`, and the
checks to run). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), never in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
