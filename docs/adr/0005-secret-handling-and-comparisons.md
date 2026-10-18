# ADR 0005: Secret generation, storage, key handling and comparisons

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-10-18 |
| Deciders | Justus Perillieux |
| Supersedes | — |
| Related | PRD-0001, ADR-0004, ADR-0006, ADR-0008 |

## Context

Recorded retrospectively for the first public release. Several packages mint
bearer secrets (API tokens, refresh tokens, magic links, OAuth state), keep
secrets a protocol needs later (nonce, PKCE verifier, device code), or hold
keys (SAML service-provider key, API token pepper, JWT verification keys).
A leak of the backing store, a log line or a timing side channel must not
turn into account takeover. This ADR records the security model as
implemented.

### Secret generation

All secrets are 256 bits read with `io.ReadFull` from `crypto/rand.Reader`
(or the `Options.Random` reader a caller supplies, documented as having to be
cryptographically secure). A short read fails the operation closed
(`ErrInvalidCredential` / `ErrInvalidCallback`) before anything is stored.

| Secret | Format | Stored as |
|---|---|---|
| API token | `<prefix>_<id>_<secret>`: prefix 2–16 `[a-z0-9]` starting with a letter; 128-bit ID and 256-bit secret in lowercase RFC 4648 base32 without padding (26 + 52 chars) | `Record.Digest` = HMAC-SHA256(pepper, `"go-auth/apitoken/v1\x00"` ‖ token) when `Options.Pepper` (32–1024 bytes) is set, else SHA-256 of the same input |
| Session refresh token | 32 bytes base64url (43 chars) | `Session.RefreshDigest` = SHA-256(token) |
| Session ID | `sess_` + 32 bytes base64url | as is (an identifier, not a credential) |
| Magic-link token | 32 bytes base64url (43 chars) | `Record.Digest` = SHA-256(token); the digest is the store key |
| OIDC/OAuth2 state | 32 bytes base64url | `Pending.Digest` = SHA-256(state) (`oidc.StateDigest`); the digest is the store key |
| OIDC nonce, PKCE verifier | 32 bytes base64url each, independent of the state | `oidc.Secret` in `Pending` (needed again at Complete) |
| SAML RelayState, request ID | 32 bytes base64url from `crypto/rand`; ID from crewjam/saml | in `saml.Request` (needed again at Complete) |
| Device code | issued by the server | `oidc.Secret` in `device.Authorization` |

Unkeyed SHA-256 is sufficient for 256-bit random secrets (no feasible
brute force). The API-token pepper additionally prevents a leaked token
table from confirming guessed or leaked tokens; it must be kept outside that
table, and rotating it invalidates every token. The digest covers the whole
token, binding it to its prefix and ID, under a versioned domain-separation
string.

Raw secrets are returned exactly once (`apitoken.Manager.Issue`,
`session.Manager.Create`/`Rotate`, `magiclink.Service.Issue`,
`Redirect.StateID`). Records returned by `apitoken.Manager` have a zeroed
`Digest`. `oidc.Secret` formats as `[REDACTED]` for `%v`, `%+v`, `%#v` and
`String`, and is only readable through `Bytes` or `MarshalBinary` for
caller-owned durable stores. The HTTP middleware clears the token buffer
after authentication.

### Comparisons

- A presented API token is hashed and compared with the stored digest using
  `crypto/subtle.ConstantTimeCompare`, before revocation or expiry are looked
  at, so callers without the secret learn nothing about the record's state.
  `TestDigestComparisonsAreConstantTime` inspects the package source and
  fails if digests are compared any other way.
- A presented refresh token is hashed and compared with the stored digest in
  constant time inside `Rotate`.
- Magic links and OAuth state are looked up by the SHA-256 digest of the
  presented value; the store lookup is by an unpredictable key, so timing
  reveals nothing about stored secrets.
- Nonce, issuer and audience checks on an already signature-verified ID token
  are ordinary comparisons: their inputs are signed by the identity provider,
  not attacker-chosen.

### Key handling

- JWT keys come from a caller `KeySource` by a validated `kid` (required,
  at most 256 bytes); key-source errors are never shown. Algorithms are an
  explicit allowlist and `none` is rejected even if listed.
- The SAML service-provider key must be RSA of at least 2048 bits, validate,
  and match a currently valid certificate; it and the identity provider
  metadata are deep-copied at construction so later caller mutation has no
  effect. Requests are signed with RSA-SHA256. Response signatures are
  validated only against signing certificates from the configured metadata
  that are valid at construction and at verification time.
- The API-token pepper is copied at construction.
- OIDC ID-token signatures are verified by the caller-supplied go-oidc
  `IDTokenVerifier`; without one, `Complete` fails closed.

### Single use and redirects

One-time values (OAuth state, SAML requests, magic links) are consumed
atomically from the store *before* any other validation, so an expired,
mismatched or otherwise invalid value is burned and cannot be retried, and
concurrent presentations have exactly one winner. Redirect URIs and the SAML
ACS URL must match a registered value exactly; https is required (http only
on loopback hosts for OAuth/OIDC redirects and endpoints).

### Input bounds

Every untrusted input is size-bounded before it is parsed: JWTs (32 KiB
default), Authorization headers (16 KiB) and middleware tokens (8 KiB
default), API tokens (exact length), SAML responses (1 MiB default, checked
on the encoded length first; XML depth ≤ 32, ≤ 256 elements, no DTDs or
processing instructions, unique IDs, exactly one unencrypted assertion),
Cedar policies and entities (1 MiB each), principal traits and methods,
device codes and URIs (printable ASCII only, so they are safe to show in a
terminal).

## Decision drivers

- D1: A leaked store must not yield usable credentials.
- D2: No timing oracle on secret comparison.
- D3: Secrets must not appear in logs, errors or formatted values.
- D4: One-time values must be single use under concurrency.

## Considered options

1. **Random 256-bit bearer secrets, digest-only storage, constant-time
   digest comparison, consume-before-validate (chosen)**
   - Pro: store leaks are harmless for tokens, links and state; simple
     formats; no key management for most secrets.
   - Con: lost tokens cannot be recovered or shown again; peppered API
     tokens die with the pepper.
2. **Encrypted secrets at rest**
   - Pro: tokens could be displayed again.
   - Con: key management; a leaked key exposes every token.
3. **Self-contained signed tokens (JWT) for API tokens and links**
   - Pro: no store lookup.
   - Con: revocation and single use still need state; larger tokens;
     signing-key compromise is total.
4. **Password-hashing functions (bcrypt, argon2) for token digests**
   - Pro: slows brute force.
   - Con: unnecessary for 256-bit random secrets and costly on every request.

## Decision

We will generate every library-minted secret with 256 bits from a
cryptographically secure reader, store only SHA-256 (or peppered HMAC-SHA256
for API tokens) digests where the secret is not needed again, wrap secrets
that are needed again in the redacting `oidc.Secret`, compare presented
secrets with stored digests in constant time, consume one-time state before
validating it, and bound every untrusted input before parsing. Changing a
token format, digest construction or domain-separation string is a
persistence-format change and needs a superseding ADR.

## Consequences

### Positive
- Store, log and error leaks do not expose usable secrets.
- Formats are documented and stable for durable store implementations.

### Negative
- Stores implemented by callers must honour the atomic-consume and
  create-only contracts (ADR-0008); the library cannot enforce them.
- `Options.Random` lets a caller weaken entropy; it is documented as
  requiring a secure source.

### Follow-ups
- A public store conformance suite would let durable implementations prove
  the atomicity contracts (see ADR-0008).

## Links

- [SECURITY.md](../../SECURITY.md)
- RFC 6749, RFC 7636 (PKCE), RFC 6750, RFC 8628
