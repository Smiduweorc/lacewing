---
title: Getting started
---

# Getting started with Lacewing

Adopting Lacewing in a service, step by step. Each step links to the guide
with the details.

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

## 2. A working example

Copy this into `demo.mts` and run `node demo.mts`:

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

## 3. Keys

```ts
import { generateKeyPair, generateSecret, importKey } from "lacewing";

const { publicKey, privateKey } = await generateKeyPair();          // EdDSA
const { publicKey: p2, privateKey: k2 } = await generateKeyPair("ES256");
const secret = generateSecret("HS256");                             // symmetric

const signing = await importKey(process.env.PRIVATE_KEY_PEM!, "EdDSA");
const fromJwk = await importKey({ kty: "OKP", crv: "Ed25519", x: "..." }, "EdDSA");
const hmac = await importKey(process.env.SECRET!, "HS256");
```

Supported algorithms: `EdDSA` (default), `Ed25519`, `ES256`/`ES384`/`ES512`,
`PS256`/`PS384`/`PS512`, `HS256`/`HS384`/`HS512`. `RS*` needs a descriptor
from `lacewing/legacy/rsa` ([Verifying](./guides/verifying.md)).

Use `EdDSA` unless you have a reason not to. With HMAC, every verifier can
also sign, and secrets have to pass a length and entropy check at import
([Signing](./guides/signing.md#hmac)).

A key is bound to one algorithm at import time. `LacewingKey<"ES256">`
cannot be passed where `LacewingKey<"HS256">` is expected, so algorithm
confusion is a compile error.

`generateKeyPair()` makes a non-extractable private key by default, so you
can't generate a key and then save it:

```ts
const { privateKey } = await generateKeyPair();
await exportKeyPEM(privateKey); // throws KEY_EXPORT_FAILED
```

To persist one, ask for it:

```ts
const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
  extractable: true,
});
const pem = await exportKeyPEM(privateKey);
```

Public keys export either way.

## 4. Profiles

A profile is everything a verifier demands, and the only argument shape
`jwtVerify` accepts, so `typ`, `issuer`, `audience`, `algorithms` and `keys`
can't be left out.

```ts
import { defineProfile } from "lacewing";

const profile = defineProfile({
  typ: "at+jwt",                    // required: which kind of token
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  algorithms: ["EdDSA"],            // the header can't choose the algorithm
  keys: publicKey,
  maxTokenAge: "15m",               // required: max age by iat, independent of exp

  // optional
  maxTokenLifetime: "1h",           // refuse an implausible declared exp-iat span
  maxClockSkew: "5s",               // default 5s, capped at 30s
  subject: "user-42",               // pin the expected sub
  revocation: store,
  unsafeClaimValidators: {         // your code in the accept path
    scope: (value) => {
      if (typeof value !== "string" || !value.includes("read")) {
        throw new Error("scope must include read");
      }
    },
  },
});
```

Define each profile once at module scope and export it. Building one per
request wastes work and lets two call sites disagree about what is
acceptable.

```ts
// auth/profiles.ts: the whole app imports from here
export const apiProfile = defineProfile({ /* ... */ });
```

`maxTokenAge` and `exp` are separate limits and you want both
([Lifetimes](./guides/lifetimes-and-revocation.md#age-and-lifetime)).

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
can be waived with an `unsafeAllowMissing*()` call, which CI can grep for:

```ts
await new SignJWT("at+jwt")
  .audience("...")
  .expiresIn("5m")
  .unsafeAllowMissingIssuer()
  .sign(privateKey);
```

Every token gets a `jti` and an `iat`. `.expiresIn()` above 1h throws
`MAX_LIFETIME_EXCEEDED` unless you raise the cap, and the payload is scanned
for anything shaped like a password, card number or PEM key
([Signing](./guides/signing.md)).

## 6. Verifying tokens

```ts
import { jwtVerify } from "lacewing";

const verified = await jwtVerify(token, profile);
verified.payload.sub;
verified.header.alg;
```

`jwtVerify` returns a fully checked `VerifiedJwt` or throws. There is no
partial result. Checks run in this order and stop at the first failure:
structure, header, key resolution, signature, claims, your custom
validators, revocation. Revocation runs last so unauthenticated input never
reaches your revocation store.

To read a token without verifying it (for debugging), use `unsafeDecode`
([Errors, events and time](./guides/operations.md#debugging)).

## 7. Getting the token out of a request

```ts
import { parseBearer, readTokenCookie, setTokenCookie } from "lacewing";

const token = parseBearer(request);            // strict RFC 6750
const fromCookie = readTokenCookie(request);   // __Host-token by default
setTokenCookie(response.headers, token);       // HttpOnly; Secure; SameSite=Lax
```

Browsers get the `HttpOnly` cookie, services get a bearer header. Express,
Fastify and Koa need `new Headers(req.headers as Record<string, string>)`
first. Both are covered in [Transport](./guides/transport.md).

## 8. Access and refresh tokens

Use `accessTokenProfile` and `refreshTokenProfile` (and `newAccessToken()` /
`newRefreshToken()` to sign) instead of one profile for both. They refuse
each other's tokens by `typ`, and the refresh profile requires a revocation
store. Defaults and an example are in
[Lifetimes and revocation](./guides/lifetimes-and-revocation.md).

## 9. Revocation

Pass a `RevocationStore` as the profile's `revocation`.
`MemoryRevocationStore` works for a single process; for more than one, back
the interface with Redis or your database. A store that throws fails closed,
so a store outage is an auth outage. Revoking by token, subject or session,
and a Redis example, are in
[Lifetimes and revocation](./guides/lifetimes-and-revocation.md#revocation).

## 10. Distributing keys in production

Your API servers need the public key. In production, publish a JWKS instead
of shipping a key file to every service:

```ts
const profile = defineProfile({
  typ: "at+jwt",
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  algorithms: ["EdDSA"],
  keys: {
    jwksUri: "https://auth.example.com/.well-known/jwks.json",
    cacheTtlSeconds: 300,          // no Cache-Control? trust fetched keys this long (0-86400)
    cooldownSeconds: 30,           // at most one fetch per 30s (1-86400)
    timeoutMs: 2000,               // verification waits this long on a cold cache
    staleWhileErrorSeconds: 3600,  // optional, default 3600, at most 86400
  },
  maxTokenAge: "15m",
});
```

The first three have no defaults. What each one controls, and what happens
when the endpoint goes down, is in [Verifying](./guides/verifying.md).

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
// throws JWKS_NO_MATCHING_KEY: Multiple keys in the JWKS match this token -
// issue tokens with a kid
```

Since you cannot issue with a `kid`, plan around it. In order of preference:

1. Verify against an explicit key instead of a JWKS wherever you control
   both ends. `keys: publicKey` has no ambiguity to resolve.
2. Rotate across algorithms. Publish the outgoing `EdDSA` key and the
   incoming `ES256` key together, allow both during the overlap, then drop
   the old one. Tokens then select by `alg`:

   ```ts
   const profile = defineProfile({
     typ: "at+jwt", issuer: ISSUER, audience: AUDIENCE,
     algorithms: ["EdDSA", "ES256"],       // both, only during the overlap
     keys: { jwksUri: "https://auth.example.com/.well-known/jwks.json", cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 2000 },
     maxTokenAge: "15m",
   });
   ```

3. Hard cutover. Publish one key at a time and accept that tokens signed
   with the old key fail for one token lifetime. At 10-minute access tokens
   that window is small.

The constraint applies only to tokens Lacewing signs. Lacewing reads and
matches `kid` on other issuers' tokens, so an issuer that sets `kid` can
rotate normally. We haven't tested against Auth0, Okta or Cognito
specifically.

## 11. Handling errors

Every refusal is a `JWTError` with a `code`. Log the code and return
`401 invalid_token` for all of them; misconfiguration is a `TypeError` at the
call that receives it. The codes, an example handler and the `onEvent`
listener for JWKS outages and fail-open revocation are in
[Errors, events and time](./guides/operations.md).

## 12. Coming from `jsonwebtoken`

| `jsonwebtoken` | Lacewing |
| --- | --- |
| `jwt.sign(payload, key, opts)` | `new SignJWT(typ).issuer().audience().expiresIn().sign(key)` |
| `jwt.verify(token, key, opts)` | `jwtVerify(token, profile)` |
| `jwt.decode(token)` | `unsafeDecode(token)`, branded untrusted |
| options per call site | one `defineProfile` shared by every call site |
| `algorithms: [...]` optional | required |

Two habits change. Options move to the profile: passing verification options
at each call site is how one endpoint ends up not checking `audience`. And
`typ` is required. `jsonwebtoken` does not make you distinguish token kinds,
so most codebases have one sort of JWT doing several jobs. Existing tokens
without a `typ` have to be reissued; no profile accepts an absent `typ`.

Migration order:

1. Add Lacewing alongside your existing library; issue new tokens with both.
2. Move verification to `jwtVerify` with a profile, behind a flag.
3. Once all live tokens carry `typ` (one token lifetime), drop the old path.
