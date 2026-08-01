---
title: Getting started
---

# Getting started with Lacewing

Adopting Lacewing in a real service: keys, profiles, issuing, verifying,
transport, refresh tokens, revocation, and key distribution.

Every code sample below was executed against the library before publishing.

For the pitch and the API reference, see the [README](./README.md).

**Contents**

1. [Before you start](#1-before-you-start)
2. [A working example](#2-a-working-example)
3. [Keys](#3-keys)
4. [Profiles](#4-profiles)
5. [Issuing tokens](#5-issuing-tokens)
6. [Verifying tokens](#6-verifying-tokens)
7. [Getting the token out of a request](#7-getting-the-token-out-of-a-request)
8. [Access and refresh tokens](#8-access-and-refresh-tokens)
9. [Revocation](#9-revocation)
10. [Distributing keys in production](#10-distributing-keys-in-production)
11. [Handling errors](#11-handling-errors)
12. [Coming from `jsonwebtoken`](#12-coming-from-jsonwebtoken)
13. [Adoption checklist](#13-adoption-checklist)

---

## 1. Before you start

Lacewing requires Node 24 or later and is ESM only. There is no CommonJS
build and no `require()` path.

```bash
npm install lacewing
```

Your `package.json` needs `"type": "module"`. If you are on CommonJS, that
migration comes first.

TypeScript is not required, but most of the design assumes it. `VerifiedJwt`
is a branded type that only `jwtVerify` produces, so handing an unverified
token to code expecting verified claims fails to compile. From plain
JavaScript you lose that check.

---

## 2. A working example

Copy this into `demo.mts` and run `node --experimental-strip-types demo.mts`:

```ts
import { generateKeyPair, SignJWT, defineProfile, jwtVerify } from "lacewing";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

// 1. Keys. EdDSA by default.
const { publicKey, privateKey } = await generateKeyPair();

// 2. A profile: everything the verifier will demand. Define it once.
const profile = defineProfile({
  typ: "at+jwt",
  issuer: ISSUER,
  audience: AUDIENCE,
  algorithms: ["EdDSA"],
  keys: publicKey,
  maxTokenAge: "15m",
});

// 3. Issue.
const token = await new SignJWT("at+jwt")
  .issuer(ISSUER)
  .audience(AUDIENCE)
  .subject("user-42")
  .claim("scope", "read:documents")
  .expiresIn("10m")
  .sign(privateKey);

// 4. Verify. The only way to turn a string into trusted claims.
const { payload } = await jwtVerify(token, profile);
console.log(payload.sub, payload.scope); // user-42 read:documents
```

---

## 3. Keys

### Generating

```ts
import { generateKeyPair, generateSecret } from "lacewing";

const { publicKey, privateKey } = await generateKeyPair();          // EdDSA
const { publicKey: p2, privateKey: k2 } = await generateKeyPair("ES256");
const secret = generateSecret("HS256");                             // symmetric
```

Supported algorithms: `EdDSA` (default), `ES256`/`ES384`/`ES512`,
`PS256`/`PS384`/`PS512`, `HS256`/`HS384`/`HS512`. The `RS*` family is not
registered at all. Using it means importing `lacewing/legacy/rsa` and calling
`enableLegacyRS256()` (or `enableLegacyRSA()` for the whole family), which is
the marker code review looks for. Prefer `PS256` or `EdDSA` where you control
both sides.

Use `EdDSA` unless you have a reason not to. Under `HS256` everyone who can
verify a token can also mint one, so your API servers can impersonate your
auth server.

A key is bound to one algorithm at import time. `LacewingKey<"ES256">`
cannot be passed where `LacewingKey<"HS256">` is expected, so algorithm
confusion is a compile error.

### Generated private keys cannot be exported

`generateKeyPair()` produces a non-extractable private key by default, so it
cannot leave through `exportKeyPEM`:

```ts
const { privateKey } = await generateKeyPair();
await exportKeyPEM(privateKey); // throws KeyExportFailed
```

That suits a key generated at boot, but it means you cannot generate a key
and then save it. To persist one, ask for it:

```ts
const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
  extractable: true,
});
const pem = await exportKeyPEM(privateKey); // now works; store it somewhere safe
```

Public keys export either way.

### Loading existing keys

```ts
import { importKey } from "lacewing";

const signing = await importKey(process.env.PRIVATE_KEY_PEM!, "EdDSA");
const fromJwk = await importKey({ kty: "OKP", crv: "Ed25519", x: "..." }, "EdDSA");
const hmac = await importKey(process.env.SECRET!, "HS256");
```

`importKey` runs an entropy check on HMAC secrets, so a password-shaped
secret fails at startup instead of producing weak signatures:

```ts
await importKey("my-secret-password-123", "HS256"); // throws EntropyCheckFailed
```

If that fires on a secret you already use, replace the secret.
`generateSecret("HS256")` produces one at the algorithm's minimum size.

---

## 4. Profiles

A profile is the complete set of demands a verifier makes, and the only
argument shape `jwtVerify` accepts. That is what makes `typ`, `issuer`,
`audience`, `algorithms` and `keys` impossible to omit.

```ts
import { defineProfile } from "lacewing";

const profile = defineProfile({
  typ: "at+jwt",                    // required: which kind of token
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  algorithms: ["EdDSA"],            // the header never gets a vote
  keys: publicKey,
  maxTokenAge: "15m",               // required: max age by iat, independent of exp

  // optional
  maxTokenLifetime: "1h",           // refuse an implausible declared exp-iat span
  maxClockSkew: "5s",               // default 5s, capped at 120s
  subject: "user-42",               // pin the expected sub
  revocation: store,
  claimValidators: {
    scope: (value) => {
      if (typeof value !== "string" || !value.includes("read")) {
        throw new Error("scope must include read");
      }
    },
  },
});
```

Define each profile once at module scope and export it. A profile is inert
configuration; building one per request wastes work and lets two call sites
disagree about what is acceptable.

```ts
// auth/profiles.ts: the whole app imports from here
export const apiProfile = defineProfile({ /* ... */ });
```

`maxTokenAge` and `exp` are separate controls and you want both. `exp` is
what the issuer claimed. `maxTokenAge` is what you accept regardless, so an
issuer that starts handing out 30-day access tokens does not widen your
window.

---

## 5. Issuing tokens

```ts
import { SignJWT } from "lacewing";

const token = await new SignJWT("at+jwt")   // typ is a constructor argument
  .issuer("https://auth.example.com")
  .audience("https://api.example.com")
  .subject("user-42")
  .claim("scope", "read:documents")
  .claim("tenant", "acme")
  .expiresIn("10m")
  .sign(privateKey);
```

`.sign()` refuses to run without `issuer`, `audience` and `expiresIn`. Each
is waivable through a method named to show up in code review:

```ts
await new SignJWT("at+jwt")
  .audience("...")
  .expiresIn("5m")
  .unsafeAllowMissingIssuer()   // grep for `unsafeAllow` in CI
  .sign(privateKey);
```

Applied automatically, with no configuration:

- `jti`: a unique UUID on every token, so revocation always has a key
- `iat`: set at sign time
- Lifetime cap: `.expiresIn()` above 1h throws `MaxLifetimeExceeded`. Raise
  it with `new SignJWT("at+jwt", { maxLifetime: "24h" })`
- Payload hygiene: the payload is scanned before signing and refuses
  anything shaped like a password, card number, or PEM key

A JWS payload is base64url-encoded plaintext, readable by anyone holding the
token. That is what the last check is for:

```ts
await new SignJWT("at+jwt")
  .issuer(ISSUER).audience(AUDIENCE).expiresIn("5m")
  .claim("password", "hunter2")
  .sign(privateKey);                        // throws PayloadHygieneViolation
```

For a false positive, allow that claim by name:

```ts
.unsafeAllowClaim("password_changed_at")
```

---

## 6. Verifying tokens

```ts
import { jwtVerify } from "lacewing";

const verified = await jwtVerify(token, profile);
verified.payload.sub;    // trusted
verified.header.alg;     // trusted
```

`jwtVerify` returns a fully checked `VerifiedJwt` or throws. There is no
partial result and no decoded-but-unverified object to trust by accident.
Checks run fail-fast in this order: structure, header, key resolution,
signature, claims, your custom validators, revocation.

Revocation runs last so unauthenticated input never reaches your revocation
store.

### Reading a token you have not verified

Debugging and logging sometimes need the contents of an unverified token.
`unsafeDecode` returns one, branded `UntrustedJwt` and type-incompatible
with `VerifiedJwt`:

```ts
import { unsafeDecode } from "lacewing";

const { header, payload } = unsafeDecode(token); // never trust these
console.log("token was issued by", payload.iss);
```

---

## 7. Getting the token out of a request

Two transports. Both refuse ambiguous input rather than resolving it.

```ts
import { parseBearer, readTokenCookie, setTokenCookie, buildTokenCookie } from "lacewing";

const token = parseBearer(request);            // strict RFC 6750
const fromCookie = readTokenCookie(request);   // __Host-token by default
```

Do not put tokens in `localStorage` or `sessionStorage`. Both are readable
by any script on the page, so one XSS is total token theft. Use an
`HttpOnly` cookie in browsers and an in-memory bearer token between
services.

```ts
setTokenCookie(response.headers, token);
// __Host-token=...; Path=/; HttpOnly; Secure; SameSite=Lax
```

`HttpOnly`, `Secure` and `SameSite` are always emitted, there is no option
to remove them, and `SameSite=None` throws. The default name uses the
`__Host-` prefix, which binds the cookie to the exact origin and forbids
`Domain`.

To log someone out:

```ts
import { clearTokenCookie } from "lacewing";
clearTokenCookie(response.headers);
```

### On Node frameworks

Both readers take WHATWG `Headers`, anything carrying them such as
`Request`, or the raw header string. Express, Fastify and Koa hand you a
plain object instead, so convert once at the edge:

```ts
app.use((req, res, next) => {
  const headers = new Headers(req.headers as Record<string, string>);
  req.token = readTokenCookie(headers) ?? parseBearer(headers);
  next();
});
```

Passing the raw `req` throws a `TypeError` naming this fix. It does not read
as "no token".

The response side is a string, so it works anywhere:

```ts
res.setHeader("Set-Cookie", buildTokenCookie(token));   // Express
reply.header("Set-Cookie", buildTokenCookie(token));    // Fastify
c.header("Set-Cookie", buildTokenCookie(token));        // Hono
```

---

## 8. Access and refresh tokens

The most common token-confusion bug is a refresh token buying API access, or
an access token minting new sessions. Both profiles ship with the library:

```ts
import {
  accessTokenProfile, refreshTokenProfile,
  newAccessToken, newRefreshToken,
} from "lacewing";

export const apiProfile = accessTokenProfile({
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",        // the API
  algorithms: ["EdDSA"],
  keys: { jwksUri: "https://auth.example.com/jwks" },
});

export const refreshProfile = refreshTokenProfile({
  issuer: "https://auth.example.com",
  audience: "https://auth.example.com/token", // the auth server, never the API
  algorithms: ["EdDSA"],
  keys: publicKey,
  revocation: store,                          // long-lived means revocable
});
```

|  | access | refresh |
|---|---|---|
| `typ` | `at+jwt` | `rt+jwt` |
| audience | your API | your auth server's token endpoint |
| default max age | 10m | 30d |
| lifetime cap when signing | 1h | 90d |
| revocation | optional | required in practice |

Issuing:

```ts
const access = await newAccessToken()
  .issuer(ISSUER).audience(API).subject("user-42").expiresIn("10m").sign(privateKey);

const refresh = await newRefreshToken()
  .issuer(ISSUER).audience(`${ISSUER}/token`).subject("user-42").expiresIn("30d").sign(privateKey);
```

`typ` does the work. Even with identical keys, claims and audience, each
profile refuses the other's tokens:

```ts
// throws JWTClaimValidationFailed: typ is rt+jwt, the profile demands at+jwt
await jwtVerify(refresh, apiProfile);
```

---

## 9. Revocation

Every token gets a `jti`, so revocation always has a key. The in-memory
store suits a single process; implement the interface for anything else.

```ts
import { MemoryRevocationStore, defineProfile } from "lacewing";

const store = new MemoryRevocationStore();

const profile = defineProfile({
  typ: "at+jwt",
  issuer: ISSUER,
  audience: AUDIENCE,
  algorithms: ["EdDSA"],
  keys: publicKey,
  maxTokenAge: "15m",
  revocation: store,
});

// On logout. jti and exp both come off the verified payload.
const { payload } = await jwtVerify(token, profile);
store.revoke(payload.jti as string, payload.exp as number);

await jwtVerify(token, profile); // now throws JWTRevoked
```

Entries are dropped once the token would have expired anyway, so the store
does not grow without bound.

For a deployment, back it with Redis or your database:

```ts
import type { RevocationStore, TokenRevocationContext } from "lacewing";

class RedisRevocationStore implements RevocationStore {
  constructor(private redis: Redis) {}

  async isRevoked(ctx: TokenRevocationContext): Promise<boolean> {
    if (ctx.jti === undefined) return false;
    return (await this.redis.exists(`revoked:${ctx.jti}`)) === 1;
  }
}
```

The context also carries `sub`, `sid`, `exp` and `iat`, so "revoke every
session for this user" needs no interface change.

A store that throws fails closed: the token is rejected because you cannot
confirm it is not revoked. A Redis outage is therefore an auth outage. The
opposite trade exists and is named to be conspicuous:

```ts
unsafeFailOpenOnRevocationError: true
```

---

## 10. Distributing keys in production

Your API servers need the public key. In production that means a JWKS
endpoint rather than shipping a key file to every service:

```ts
const profile = defineProfile({
  typ: "at+jwt",
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  algorithms: ["EdDSA"],
  keys: { jwksUri: "https://auth.example.com/.well-known/jwks.json" },
  maxTokenAge: "15m",
});
```

Caching, `Cache-Control` handling, a fetch cooldown, a size cap and a
timeout apply by default. HTTPS is mandatory, redirects are never followed,
and symmetric keys are refused: a JWKS endpoint is public, so an `oct` key
published there is one any reader could mint with.

The knobs and their defaults:

```ts
keys: {
  jwksUri: "https://auth.example.com/.well-known/jwks.json",
  cacheTtlSeconds: 300,
  cooldownSeconds: 30,
  timeoutMs: 5000,
  staleWhileErrorSeconds: 3600,  // how long known-good keys serve during an outage
}
```

`staleWhileErrorSeconds` is bounded deliberately. A key rotated out because
it was compromised must not stay trusted for as long as an attacker can keep
your JWKS endpoint unreachable. Set it to `0` to disable stale serving.

Publishing the JWKS from the signing side:

```ts
import { exportKeyJWK } from "lacewing";

const jwks = { keys: [{ ...(await exportKeyJWK(publicKey)), kid: "2026-08" }] };
app.get("/.well-known/jwks.json", (_req, res) => res.json(jwks));
```

### Before you plan a rotation

`SignJWT` emits only `{ alg, typ }` in the header and cannot set a `kid`.
JWKS key selection matches on key type, curve and `kid`, so two keys of the
same algorithm in one JWKS are ambiguous for a Lacewing-signed token:

```ts
// A JWKS holding two EdDSA keys, the state you are in during a rotation.
await jwtVerify(token, profile);
// throws JWKSNoMatchingKey: Multiple keys in the JWKS match this token -
// issue tokens with a kid
```

Since you cannot issue with a `kid`, plan around it. In order of preference:

1. Verify against an explicit key rather than a JWKS wherever you control
   both ends. `keys: publicKey` has no ambiguity to resolve.
2. Rotate across algorithms. Publish the outgoing `EdDSA` key and the
   incoming `ES256` key together, allow both during the overlap, then drop
   the old one. Tokens then select by `alg`:

   ```ts
   const profile = defineProfile({
     typ: "at+jwt", issuer: ISSUER, audience: AUDIENCE,
     algorithms: ["EdDSA", "ES256"],       // both, only during the overlap
     keys: { jwksUri: "https://auth.example.com/.well-known/jwks.json" },
     maxTokenAge: "15m",
   });
   ```

3. Hard cutover. Publish one key at a time and accept that tokens signed
   with the old key fail for one token lifetime. At 10-minute access tokens
   that window is small.

Verifying other issuers' tokens is unaffected. Lacewing reads and validates
`kid` normally, so a JWKS from Auth0, Okta or Cognito works as expected. The
constraint applies only to tokens Lacewing signs.

---

## 11. Handling errors

Every error extends `JWTError` and carries a machine-readable `code`.
Messages are generic and never echo token content, so they cannot become an
oracle or a log-injection vector.

```ts
import { JWTError, JWTExpired, JWTRevoked } from "lacewing";

try {
  const { payload } = await jwtVerify(token, profile);
  return handle(payload);
} catch (error) {
  if (error instanceof JWTExpired) return res.status(401).json({ error: "token_expired" });
  if (error instanceof JWTRevoked) return res.status(401).json({ error: "revoked" });
  if (error instanceof JWTError) {
    logger.warn({ code: error.code }, "token rejected");
    return res.status(401).json({ error: "invalid_token" });
  }
  throw error; // not a token problem; don't swallow it
}
```

The codes you will branch on:

| Error | `code` | Means |
|---|---|---|
| `JWTInvalid` | `JWT_INVALID` | Malformed, or the signature doesn't check out |
| `JWTExpired` | `JWT_EXPIRED` | Past `exp`, or older than `maxTokenAge` |
| `JWTClaimValidationFailed` | `JWT_CLAIM_VALIDATION_FAILED` | A claim is present but wrong (`.claim` names it) |
| `MissingClaim` | `MISSING_CLAIM` | A required claim isn't there |
| `AlgorithmNotAllowed` | `ALGORITHM_NOT_ALLOWED` | `alg` isn't in your allowlist |
| `JWTRevoked` | `JWT_REVOKED` | The store says no |
| `RevocationCheckFailed` | `REVOCATION_CHECK_FAILED` | The store broke; failing closed |
| `JWKSFetchFailed` | `JWKS_FETCH_FAILED` | Couldn't fetch the JWKS |
| `JWKSNoMatchingKey` | `JWKS_NO_MATCHING_KEY` | No key matched, or several did |
| `EntropyCheckFailed` | `ENTROPY_CHECK_FAILED` | HMAC secret is too weak; a startup problem |
| `PayloadHygieneViolation` | `PAYLOAD_HYGIENE_VIOLATION` | You're about to sign a secret |

Do not return a distinct HTTP response per code to unauthenticated callers.
Use `401 invalid_token` for all of them and keep the detail in logs.

---

## 12. Coming from `jsonwebtoken`

The mapping is mechanical except for two habits.

| `jsonwebtoken` | Lacewing |
|---|---|
| `jwt.sign(payload, key, opts)` | `new SignJWT(typ).issuer().audience().expiresIn().sign(key)` |
| `jwt.verify(token, key, opts)` | `jwtVerify(token, profile)` |
| `jwt.decode(token)` | `unsafeDecode(token)`, branded untrusted |
| options per call site | one `defineProfile` shared by every call site |
| `algorithms: [...]` optional | mandatory, always |

Options move to the profile. Passing verification options at each call site
is how one endpoint ends up not checking `audience`. Define the profile once
and import it everywhere.

`typ` is mandatory. `jsonwebtoken` does not make you distinguish token
kinds, so most codebases have one sort of JWT doing several jobs. Lacewing
requires the kind to be named, and different kinds refuse each other.
Existing tokens without a `typ` have to be reissued; no profile accepts an
absent `typ`.

Migration order:

1. Add Lacewing alongside your existing library; issue new tokens with both.
2. Move verification to `jwtVerify` with a profile, behind a flag.
3. Once all live tokens carry `typ`, drop the old path.

Step 3 waits one token lifetime.

---

## 13. Adoption checklist

- [ ] `"type": "module"` and Node 24+ in your deploy image
- [ ] Asymmetric keys (`EdDSA`) unless you deliberately chose otherwise
- [ ] Private key loaded from your secret manager, never from the repo
- [ ] One `defineProfile` per token kind, at module scope, exported
- [ ] `audience` is the specific service, not a wildcard
- [ ] `maxTokenAge` set to what you accept, not what the issuer claims
- [ ] Access tokens in minutes; refresh tokens revocable
- [ ] Browser tokens in `HttpOnly` cookies; grep for `localStorage` to be sure
- [ ] Node framework? `new Headers(req.headers)` at the edge
- [ ] A revocation store that survives a restart
- [ ] A decision on what a store outage should do; the default fails closed
- [ ] A rotation plan that accounts for the `kid` constraint in
      [§10](#10-distributing-keys-in-production)
- [ ] `401 invalid_token` for every rejection; codes go to logs only
- [ ] CI greps for `unsafeAllow`, `unsafeDecode` and
      `unsafeFailOpenOnRevocationError`

---

`npm run demo` in the repository runs a live walkthrough where every
rejection is a real thrown error. For the full API, see the
[README](./README.md) and the generated
[TypeDoc](https://github.com/grMLEqomlkkU5Eeinz4brIrOVCUCkJuN/lacewing).
