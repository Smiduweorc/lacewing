---
title: Boundaries
---

# Boundaries

**What Lacewing owns, what it will never do, and where that work goes instead.**

## What this layer owns

- Verifying a signed JWT against a profile: `typ`, issuer, audience, algorithm allowlist, key source, age and claims.
- Signing and encrypting JWTs that a Lacewing profile will accept.
- Key import and generation, bound to one algorithm each.
- Fetching and caching a JWKS, bounded in size, time and fetch rate.
- A revocation hook, and an in-memory store for one process.
- Reading a token from a cookie or an `Authorization: Bearer` header, and writing the cookie.
- The policy packages built on Lacewing share, through `lacewing/extension`.

## What this layer never does

| Excluded | Why | Where it goes |
| --- | --- | --- |
| DPoP-bound tokens | Proof-of-possession is a second check with its own state (a replay store, nonces) | [Antlion](https://github.com/Smiduweorc/antlion), which wraps a Lacewing profile |
| mTLS-bound tokens | The binding lives in the TLS layer, which a library behind a proxy never sees | Whatever terminates your TLS |
| Running an authorization server (issuing from logins, PKCE, consent) | A different product with different state | An OpenID provider: oidc-provider, Keycloak, and the rest |
| A once-only (jti-seen) cache | Which store, which TTL and what happens when it is down are your deployment's decisions | Your store, through `unsafeClaimValidators` ([Lifetimes and revocation](./lifetimes-and-revocation.md)) |
| A shared revocation store | Lacewing is one process, said out loud | Your Redis or database, behind the `RevocationStore` interface |
| Retrying a failed JWKS fetch on a schedule | Retry policy is the caller's, and Lacewing fetches once per cooldown and fails closed | Firefly, or your own scheduler, around the endpoint |
| Logging and metrics | A library does not own the terminal | Your logger, fed by `onEvent` ([Errors, events and time](./operations.md)) |
| Keys in an HSM or a secrets manager | Lacewing cannot know how your key service authenticates | `unsafeCustomKeySource` ([Verifying](./verifying.md)) |
| Where a browser keeps the token | Lacewing never runs in your frontend | Your frontend; use the `HttpOnly` cookie helper ([Transport](./transport.md)) |
| CommonJS and Node before 24 | ESM and the Node 24 WebCrypto surface are the floor | Nowhere |
