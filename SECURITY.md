# Security policy

auth verifies credentials and makes authorization decisions, so security
reports are handled with priority.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a
vulnerability.**

Report it privately through GitHub's security advisories:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**
   (`https://github.com/justusschock/auth/security/advisories/new`).
3. Describe the issue, the affected package(s) and version or commit, and how
   to reproduce it. A minimal test case or proof of concept helps most.
   Never include real credentials, keys or tokens.

You will get an acknowledgement within 7 days. We will agree on a fix and a
disclosure date with you, publish a GitHub security advisory together with the
fixed release, and credit you unless you prefer otherwise.

## Supported versions

The library is pre-1.0. Security fixes are made on `main` and released in the
next `v0.x` version; older minor versions are not patched. Always use the
latest release.

## Scope

In scope is any way to make a package in this module:

- accept a credential, token, assertion, callback or session it should reject
  (signature, issuer, audience, nonce, state, PKCE, expiry or clock-skew
  checks, replay or single-use guarantees, revocation);
- allow an authorization request that its Cedar policies deny, or allow one
  despite an evaluation error;
- disclose secrets (tokens, refresh tokens, device codes, nonces, PKCE
  verifiers, pepper or key material) through errors, formatting or storage;
- leak secrets through timing where the library promises constant-time
  comparison;
- consume unbounded memory or CPU on attacker-controlled input.

Out of scope: vulnerabilities in dependencies that do not affect how this
module uses them (report those upstream), weaknesses that require a caller to
violate a documented contract (for example a `Store` that does not consume
atomically or a non-cryptographic `Random` reader), and missing CSRF
protection for cookie authentication, which the middleware documents as the
caller's responsibility.

The security model is recorded in [ADR-0005](docs/adr/0005-secret-handling-and-comparisons.md)
and [ADR-0006](docs/adr/0006-expiry-clock-skew-and-ttls.md).
