# Lacewing
![Logo](./assets/logo.png)

**Lacewing is an opinionated JWT library that makes common JWT security mistakes impossible by construction.**

Instead of exposing low-level primitives and trusting you to compose them correctly, Lacewing provides secure verification profiles, safe defaults, mandatory claim validation, built-in revocation support, secure cookie helpers, and a curated algorithm set - everything [RFC 8725 (JWT Best Current Practices)](https://datatracker.ietf.org/doc/html/rfc8725) says an application MUST or SHOULD do is enforced by the type system, enforced at runtime, or impossible to express.

**Batteries loaded (RFC 8725).** Out of the box:

- **Verification profiles** - the only way to verify; `typ`, issuer, audience, algorithm allowlist and key source are structurally mandatory
- **Remote JWKS** with caching, rotation handling, and `kid` hygiene
- **Token revocation** - unique `jti` on every token, pluggable `RevocationStore`, in-memory store included
- **Secure cookie + bearer helpers** - `HttpOnly; Secure; SameSite` enforced, strict RFC 6750 parsing
- **Access/refresh token presets** - mutually exclusive by `typ`, shipped rather than left as homework
- **Encrypted JWTs (JWE)** with the same profile discipline
- **Payload hygiene scanning** at sign time (passwords, card numbers, PEM keys never leave in plaintext)
- **Typed errors** with machine-readable codes and no attacker-facing oracle

## Requirements

- Node **>= 24**
- **ESM** only
- **TypeScript-first** (full types shipped; the branded `VerifiedJwt`/`UntrustedJwt` types are part of the security model)

## Installation

```bash
npm install lacewing
```

## Quick start

The complete lifecycle - generate a key, sign, define a profile once, verify everywhere:

```ts
import { SignJWT, defineProfile, jwtVerify, generateKeyPair } from "lacewing";

const { publicKey, privateKey } = await generateKeyPair(); // EdDSA by default

const token = await new SignJWT("at+jwt")
	.issuer("https://auth.example.com")
	.audience("https://api.example.com")
	.subject("user-42")
	.expiresIn("10m")
	.sign(privateKey);

const profile = defineProfile({
	typ: "at+jwt",
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	algorithms: ["EdDSA"],
	keys: publicKey,
	maxTokenAge: "10m",
});

const { payload } = await jwtVerify(token, profile); // VerifiedJwt - every check passed
```

A runnable version of everything in this README ships with the repo: `npm run demo`.

## Concepts

**Profiles are the central abstraction.** Configuration is something you create once - not something every endpoint reinvents. A profile names the expected `typ`, the trusted issuer, the required audience, an explicit algorithm allowlist, and the key source bound to that issuer. `jwtVerify(token, profile)` is the *only* verify path: there is no `decode()`, no `ignoreExpiration`, no "accept whatever the header says" mode. If any check fails you get a typed error (`JWTExpired`, `AlgorithmNotAllowed`, `JWTClaimValidationFailed`, ...) and no partial result.

**Built on jose.** Lacewing does not reimplement cryptography. It is a hardened policy layer over [jose](https://github.com/panva/jose) - the audited, maintained, runtime-portable JOSE implementation - so the novel code is the policy, not the crypto. Tokens Lacewing signs or encrypts are standard JWTs/JWEs that jose (and any other conforming implementation) can consume, and the conformance suite proves it against the RFC 7515/7516/7519 worked examples plus tokens produced by OpenSSL and python-cryptography.

## Usage

### Verify: a profile backed by a remote JWKS

This is what real deployments should look like, so it's the first example:

```ts
import { defineProfile, jwtVerify, createRemoteJWKSet } from "lacewing";

const accessToken = defineProfile({
	typ: "at+jwt",
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	algorithms: ["EdDSA"],
	keys: createRemoteJWKSet("https://auth.example.com/jwks"), // cached, rate-limited, rotation-aware, HTTPS-only
	maxTokenAge: "10m",
});

const { payload } = await jwtVerify(token, accessToken); // VerifiedJwt - every check passed
```

### Sign

`typ` is a constructor argument, and `.sign()` refuses to run without
`issuer`, `audience` and `expiresIn` (waivable only via grep-loud
`unsafeAllowMissing*` calls). Every token gets a unique `jti`, lifetimes are
capped (default 1h), and a hygiene scanner rejects payloads that contain
things like passwords, card numbers, PEM keys, or other JWTs - because **a
JWS payload is base64url-encoded plaintext, readable by anyone who holds the
token**. Never put secrets in it.

```ts
import { SignJWT, generateKeyPair } from "lacewing";

const { publicKey, privateKey } = await generateKeyPair(); // EdDSA by default

const token = await new SignJWT("at+jwt")
	.issuer("https://auth.example.com")
	.audience("https://api.example.com")
	.subject("user-42")
	.claim("scope", "read")
	.expiresIn("10m")
	.sign(privateKey);
```

A note on HMAC (`HS256/384/512`): it is supported, but every verifier of an
HMAC token holds the same secret and can therefore also **mint** them. For
anything beyond a single service, use asymmetric keys + JWKS. HMAC secrets
are entropy-checked at import - `"my-secret"` will not import, ever;
`generateSecret()` gives you a proper one.

### Transport: the paved road

Do **not** put tokens in `localStorage` or `sessionStorage` - both are
readable by any script on the page, so one XSS means token theft. Use an
`HttpOnly` cookie (browsers) or an in-memory bearer token (services):

```ts
import { setTokenCookie, readTokenCookie, parseBearer } from "lacewing";

setTokenCookie(response.headers, token); // always HttpOnly; Secure; SameSite - weaker is unrepresentable
const fromCookie = readTokenCookie(request);
const fromHeader = parseBearer(request); // strict RFC 6750; no query-string tokens, ever
```

### Access vs refresh (the cookbook)

The single most common token-confusion bug is letting a refresh token buy API
access, or an access token mint new sessions. Lacewing **ships** the two
profiles rather than leaving them as homework - they are mutually exclusive by
`typ` (RFC 8725 §3.12), so presenting one where the other is expected fails,
even with identical keys, claims and audience:

```ts
import { accessTokenProfile, refreshTokenProfile, newAccessToken } from "lacewing";

const api = accessTokenProfile({          // typ: "at+jwt", 10m default cap
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",    // the API
  algorithms: ["EdDSA"],
  keys: { jwksUri: "https://auth.example.com/jwks" },
});

const refresh = refreshTokenProfile({     // typ: "rt+jwt", 30d default cap
  issuer: "https://auth.example.com",
  audience: "https://auth.example.com/token", // the auth server, never the API
  algorithms: ["EdDSA"],
  keys: privateJwks,
  revocation,                              // long-lived tokens must be revocable
});

const token = await newAccessToken()
  .issuer("https://auth.example.com")
  .audience("https://api.example.com")
  .subject("user-42")
  .expiresIn("10m")
  .sign(privateKey);

await jwtVerify(token, refresh); // -> JWTClaimValidationFailed (wrong typ)
```

### Revocation is built-in, not homework

```ts
import { MemoryRevocationStore } from "lacewing";

const revocation = new MemoryRevocationStore(); // or your Redis/DB adapter (RevocationStore)
const profile = defineProfile({ /* ...as above... */ revocation });

revocation.revoke(payload.jti, payload.exp); // e.g. on logout
await jwtVerify(token, profile); // -> JWTRevoked
```

The store is consulted only *after* signature and claims pass, and store
errors fail closed.

## Advanced

### Revocation is not replay protection

Be precise about what revocation buys you: it lets you kill a
token you *know about* (logout, compromise). It does **not** stop replay - a
valid, non-revoked token that leaks can be replayed by anyone who holds it
until `exp`. That is the deliberate cost of stateless verification, and no
JWT library can remove it without becoming a session store.

Your levers, in order of cheapness:

- **Short lifetimes.** The default caps (10m access tokens) exist exactly to
  shrink the replay window. Prefer shortening `exp` over building state.
- **Revocation on every logout/refresh**, so a stolen token dies with the
  session it came from.
- **A jti-seen cache** when an endpoint must be strictly once-only (e.g. a
  password-reset action token): every Lacewing token carries a unique `jti`,
  so you can reject repeats with a `claimValidators` entry backed by a
  store with the token's remaining TTL:

  ```ts
  const profile = defineProfile({
    /* ...as above... */
    claimValidators: {
      jti: async (jti) => {
        // setnx-style: returns false if the jti was already seen
        if (!(await seenCache.addIfAbsent(String(jti), remainingTtl))) {
          throw new Error("token replayed");
        }
      },
    },
  });
  ```

  This is intentionally not built in: a once-only cache is a distributed-state
  decision (which store, which TTL, what happens when it's down) that your
  deployment has to own, not something a library should silently half-do.
- **Proof-of-possession** (mTLS-bound or DPoP-bound tokens) when replay by a
  network eavesdropper is in your threat model. That is beyond Lacewing's
  bearer-token scope today.

### Encrypting (JWE): when the payload really is a secret

A signed JWT is readable plaintext. When you genuinely need the payload
*hidden* - not just tamper-evident - use an encrypted JWT. Same discipline as
signing (mandatory `typ`, required `iss`/`aud`/`exp`, unique `jti`, capped
lifetime), but with a curated set of encryption algorithms and no `none`. The
sign-time hygiene scanner is deliberately off here - hiding secrets is the
whole point:

```ts
import {
  EncryptJWT, jwtDecrypt, defineDecryptionProfile, generateEncryptionKeyPair,
} from "lacewing";

const { publicKey, privateKey } = await generateEncryptionKeyPair("ECDH-ES+A256KW");

const token = await new EncryptJWT("at+jwt", { contentEncryption: "A256GCM" })
  .issuer("https://auth.example.com")
  .audience("https://api.example.com")
  .subject("user-42")
  .claim("ssn", "123-45-6789") // fine - it's encrypted, not just encoded
  .expiresIn("10m")
  .encrypt(publicKey);

const profile = defineDecryptionProfile({
  typ: "at+jwt",
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  keyManagementAlgorithms: ["ECDH-ES+A256KW"], // the header never chooses
  contentEncryptionAlgorithms: ["A256GCM"],
  key: privateKey,
  maxTokenAge: "10m",
});

const { payload } = await jwtDecrypt(token, profile); // DecryptedJwt - distinct from VerifiedJwt
```

`none`, `RSA1_5`, `RSA-OAEP` (SHA-1) and the password-based `PBES2*` family are
absent by construction. A JWS handed to `jwtDecrypt` (or a JWE handed to
`jwtVerify`) is rejected - the two formats never cross over.

**Portability caveat - 192-bit AES:** the registry includes the `A192*`
algorithms (`A192KW`, `A192GCMKW`, `A192GCM`, `A192CBC-HS384`) for JOSE
completeness, and they work on Node ≥ 24 (Lacewing's floor). But WebCrypto
implementations in browsers and some edge runtimes do not implement 192-bit
AES at all. If tokens must be decrypted outside Node, stick to the `A128*` /
`A256*` variants - there is no security reason to prefer 192-bit anyway.

### Debugging

`unsafeDecode(token)` parses without verifying and returns an `UntrustedJwt`
that is type-incompatible with `VerifiedJwt` - useful for inspecting expired
tokens, useless (by design) for auth logic.

### Legacy interop

The `RS*` (RSASSA-PKCS1-v1_5) family exists only behind an explicit import, for
verifying tokens from issuers you don't control and can't move off PKCS#1 v1.5:

```ts
import { enableLegacyRS256 } from "lacewing/legacy/rs256";
enableLegacyRS256(); // grep for this in code review

// Or, for an issuer that rotates across hash sizes:
import { enableLegacyRSA } from "lacewing/legacy/rsa"; // RS256 + RS384 + RS512
```

Prefer `PS256`/`EdDSA` everywhere you control both sides.

## Why Lacewing exists

Lacewing is not trying to compete with general-purpose JWT libraries. It started as the hardened setup I kept rebuilding for my own projects, packaged so I'd stop rebuilding it.

The other reason is irritation. Generic JWT libraries are fine, but they leave enough rope for misinformed developers (and lazy AI slop) to ship something unsafe. It pisses me off when people implement something genuinely safe wrongly and then blame the technology instead of accepting operator error. These are the mistakes Lacewing makes unrepresentable or loudly explicit:

- Decoding instead of verifying
- Accepting `"none"` for the algorithm
- No explicit allowlist on the server that enforces expected algorithms
- Putting sensitive data in the token payload
- No way to revoke stateless JWTs
- Storing tokens in `localStorage` or `sessionStorage`
- Not configuring `iss` or `aud`
- Over-caching a JWKS when an endpoint goes down

Insecure usage is still *possible* - but only unmistakably deliberate, through `unsafe*`-prefixed escape hatches that are easy to grep for in code review. Secure usage is the path of least resistance.

## Attribution

Lacewing depends on and includes code adapted from the [jose](https://github.com/panva/jose) library, created by Filip Skokan (panva). We are grateful for their work!
