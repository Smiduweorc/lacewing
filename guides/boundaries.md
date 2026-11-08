---
title: Boundaries
---

# Boundaries

Lacewing does:

- Verifying a signed JWT against a profile: `typ`, issuer, audience, algorithm allowlist, key source, age and claims.
- Signing and encrypting JWTs that a Lacewing profile will accept.
- Key import and generation, bound to one algorithm each.
- Fetching and caching a JWKS, bounded in size, time and fetch rate.
- A revocation hook, and an in-memory store for one process.
- Reading a token from a cookie or an `Authorization: Bearer` header, and writing the cookie.
- The checks packages built on Lacewing need to agree on, through `lacewing/extension`.

Not included:

- DPoP-bound tokens. Use [Antlion](https://github.com/Smiduweorc/antlion), which wraps a Lacewing profile.
- mTLS-bound tokens. The binding lives in the TLS layer, which a library behind a proxy never sees; handle it wherever your TLS terminates.
- Running an authorization server (logins, PKCE, consent). Use an OpenID provider such as oidc-provider or Keycloak.
- A once-only (jti-seen) cache. Which store, which TTL and what happens when it is down depend on your deployment; build it with `unsafeClaimValidators` ([Lifetimes and revocation](./lifetimes-and-revocation.md)).
- A shared revocation store. `MemoryRevocationStore` is per process; put Redis or your database behind the `RevocationStore` interface.
- Retrying a failed JWKS fetch on a schedule. Lacewing fetches at most once per cooldown and fails closed; wrap the endpoint with Firefly or your own scheduler.
- Logging and metrics. Lacewing never logs; feed your logger from `onEvent` ([Errors, events and time](./operations.md)).
- Keys in an HSM or a secrets manager. Use `unsafeCustomKeySource` ([Verifying](./verifying.md)).
- Where a browser keeps the token. That is your frontend's job; use the `HttpOnly` cookie helper ([Transport](./transport.md)).
- CommonJS and Node before 24.
