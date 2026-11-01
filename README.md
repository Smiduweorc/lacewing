# Lacewing
![Logo](./assets/logo.png)

**Lacewing is an opinionated JWT library for people who want the safe way to be the only easy way, and the unsafe way to be something you have to type out loud.**

It does not hand you primitives and wish you luck. You get verification profiles, a short algorithm list, mandatory claim checks, revocation, cookie helpers, and a refusal for most of the ways people usually get JWTs wrong. Every RFC 8725 (JWT Best Current Practices) requirement a library is in a position to check is checked, and `tools/compliance-gate.ts` fails the build if one of them has no passing test. What it cannot check is listed under [what only you can decide](#what-only-you-can-decide), because pretending otherwise would be the exact kind of lie this library exists to stop.

**The signature maths is not ours.** Lacewing enforces the *policy* RFC 8725 asks for. The ECDSA and EdDSA signing and verifying, curve point checks, and nonce generation are done by [jose](https://github.com/panva/jose) on top of Node's WebCrypto (OpenSSL). Lacewing does not control or re-check them. ECDSA nonces are whatever Node's OpenSSL build produces (randomised, not RFC 6979 deterministic), and low-level primitive conformance is only as good as your Node version. The compliance suite tests that Lacewing calls these primitives correctly, not the primitives themselves.

One runtime dependency (`jose`), nothing happens at import time, ESM only.

**Batteries loaded (RFC 8725):**

- **Verification profiles**: the only way to verify; `typ`, issuer, audience, algorithm allowlist, key source and maximum token age are required
- **Remote JWKS** with caching, rotation handling, `kid` hygiene, a fetch cooldown, a 1 MiB response budget, and a *bounded* stale-serving window when the endpoint goes down
- **Revocation**: a random `jti` on every token (unless you set your own), a `RevocationStore` interface, and an in-memory store for one process that revokes by `jti`, subject or session. Refresh-token profiles refuse to exist without one
- **Cookie + bearer helpers**: `HttpOnly; Secure; SameSite` always set, `SameSite=None` refused, strict RFC 6750 parsing
- **Access/refresh token presets**: mutually exclusive by `typ`, shipped rather than left as homework
- **Encrypted JWTs (JWE)** with the same profile discipline
- **A sign-time payload scanner** that refuses claim names that read as passwords, secrets, keys or tokens, and values that are PEM private keys, other JWTs or real card numbers. It is a net for the obvious mistakes, not a mind reader: a password under a claim called `note` goes straight through
- **One error class** with a machine-readable `code`; messages never echo token content

## Lacewing is not for you if you

- **want to decode a token and decide later whether to trust it.** There is no `decode()` on the verify path. `unsafeDecode` exists for debugging, and its result does not type-check where a verified token is expected.
- **need `alg: none`, `RS256` as a bare string, `RSA1_5` or `PBES2`.** Not available. Legacy `RS*` comes in through `lacewing/legacy/rsa`, by name, per profile.
- **want a token with no `iss`, no `aud` or no `exp`** without saying so in code. You can, through `unsafeAllowMissing*`, and your reviewer will see it.
- **want the library to pick your cache TTLs and timeouts.** Your JWKS endpoint, your rotation schedule, your latency budget. You pick.
- **need tokens bound to a client** (DPoP, mTLS). Bearer tokens only.
- **run on CommonJS or Node older than 24.**

## Security advisories

Lacewing has published security advisories, and one of them may apply to the
version you run. **Read [ADVISORIES.md](./ADVISORIES.md) before you deploy or
upgrade**: it lists every advisory with its affected versions, the release that
fixes it, and a workaround. To report a vulnerability, see
[SECURITY.md](./SECURITY.md).

## Requirements

- Node **>= 24**
- **ESM** only
- **TypeScript-first** (full types shipped; the branded `VerifiedJwt`/`UntrustedJwt` types are part of the security model)

## Installation

```bash
npm install lacewing
```

[Getting started](./GETTING-STARTED.md) walks through adopting Lacewing in a
real service: keys, profiles, transport, refresh tokens, revocation, key
rotation, and a migration path from `jsonwebtoken`. Coming from an older
Lacewing, [Migrating](./MIGRATING.md) lists what 3.0 and 2.0 break and what to
write instead. The rest of this README is the pitch and the reference.

## Quick start

The complete lifecycle (generate a key, sign, define a profile once, verify everywhere):

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

const { payload } = await jwtVerify(token, profile); // VerifiedJwt: every check passed
```

A runnable version of everything in this README ships with the repo: `npm run demo`.

## Concepts

**Profiles are the central abstraction.** Configuration is something you create once, not something every endpoint reinvents. A profile names the expected `typ`, the trusted issuer, the required audience, an explicit algorithm allowlist, and the key source bound to that issuer. `jwtVerify(token, profile)` is the *only* verify path: there is no `decode()`, no `ignoreExpiration`, no "accept whatever the header says" mode. If any check fails you get a `JWTError` whose `code` says why (`JWT_EXPIRED`, `ALGORITHM_NOT_ALLOWED`, `JWT_CLAIM_VALIDATION_FAILED`, ...) and no partial result.

**Built on jose.** Lacewing does not reimplement cryptography. It is a policy layer over [jose](https://github.com/panva/jose) (the audited, maintained, runtime-portable JOSE implementation), so the novel code is the policy, not the crypto. Tokens Lacewing signs or encrypts are standard JWTs/JWEs.

**What the conformance suite shows, and what it doesn't.** `tests/conformance/golden/` holds tokens Lacewing did not make. Seven were built with no JOSE library at all and must be accepted: HS256 from the OpenSSL CLI, and Ed25519, ES256, PS256, `dir`/A256GCM and ECDH-ES+A256KW/A256GCM from pyca/cryptography (`tools/golden-vectors.py` is how; re-run it and diff). One more OpenSSL token must be refused for its audience. The four RFC 7515/7516/7519 worked examples are all *refused*, each for the reason it should be: no `aud`, no `typ`, `RSA1_5`, `RSA-OAEP` with SHA-1. No RFC example can pass, because none of them carries a `typ` and an `aud`. Separately, the jose round-trip tests show jose accepts what Lacewing signs, which mostly shows we call jose correctly, since that is what Lacewing is built on.

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
	keys: createRemoteJWKSet("https://auth.example.com/jwks", {
		cacheTtlSeconds: 300, // no Cache-Control? a key your issuer removed stays trusted this long
		cooldownSeconds: 30,  // at most one fetch per 30s, however many made-up kids arrive
		timeoutMs: 2000,      // verification waits this long on a cold cache
	}),
	maxTokenAge: "10m",
});

const { payload } = await jwtVerify(token, accessToken); // VerifiedJwt: every check passed
```

There are no defaults for those three. A library that quietly picks a cache
TTL is a library that quietly decides how long your rotated-out key stays
trusted, and that's not its call. `cacheTtlSeconds` is 0 to 86400 (a
`Cache-Control: max-age` on the response wins, capped at a day),
`cooldownSeconds` is 1 to 86400, and `timeoutMs` must be positive. HTTPS only,
redirects are never followed.

**When the endpoint goes down**, the last good keys keep serving for a bounded
window after their cache lifetime ends (`staleWhileErrorSeconds`, default
3600, at most 86400), and then verification **fails closed**. So the longest
any fetched key can be trusted is the cache lifetime plus that window. The
bound is the whole point: keys that go stale forever mean a key you rotated out
*because it was compromised* stays trusted for exactly as long as an attacker
can keep your JWKS unreachable. `0` turns stale serving off.

Two more things that endpoint does not get to do. The response is read under a
1 MiB budget, checked against `Content-Length` and again on every chunk, so a
hostile or broken endpoint cannot stream you out of memory. And symmetric
(`oct`) entries are refused from a *remote* set: a JWKS endpoint is public, so a
secret published there is one every reader could **mint** with, not merely
verify with. A local JWKS may still carry them.

### Verify: keys you already have

Not everyone has a JWKS endpoint to point at. If the issuer handed you a raw
public key, or you're pinning a single known one, the same `keys` field takes it
directly. No URL, no fetch. `importKey` reads a PEM (SPKI public key), a JWK, or
a `CryptoKey`, and binds it to exactly one algorithm:

```ts
import { defineProfile, importKey } from "lacewing";

const publicKey = await importKey(spkiPem, "ES256"); // PEM string, JWK, or CryptoKey

const profile = defineProfile({
	typ: "at+jwt",
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	algorithms: ["ES256"],
	keys: publicKey, // one pinned key, nothing to fetch
	maxTokenAge: "10m",
});
```

Hand it a private key by mistake and it refuses: profiles verify, they don't
sign, and the error says exactly that. The key's algorithm has to be one you
allowlisted too, so a key you imported for `ES256` won't quietly slip into an
`EdDSA`-only profile.

Got a handful of keys but still no endpoint to serve them from? Pass a JWKS
document straight in, the same shape a `/jwks` URL would return, just inlined:

```ts
keys: {
	keys: [
		{ kty: "OKP", crv: "Ed25519", x: "...", kid: "2024-key" },
		{ kty: "EC", crv: "P-256", x: "...", y: "...", kid: "2025-key" },
	],
},
```

Selection is exact: the token's `kid` (and its algorithm's key type and curve)
has to single out one key. Two keys that both match with no `kid` to tell them
apart is treated as your mistake, not something to guess at. The same goes for
a key with no `alg`: if the profile allows several algorithms that key could
serve (say `PS256` and `PS512` for one RSA key), it is refused rather than
used under all of them. Set `alg` on the key. EC and OKP keys are exempt,
because their curve already names the algorithm.

And if your keys live somewhere less ordinary (an HSM, a secrets manager, a
database), wrap anything with a `getVerificationKey(header)` method in
`unsafeCustomKeySource(...)` and pass that. Your code now decides which key
verifies a token, so it gets a name that shows up in a grep. A bare object is
refused. It is still held to the same rules: the `alg` it returns must be the
token's, and a raw HMAC secret it returns goes through the same strength check
as `importKey`.

### Sign

`typ` is a constructor argument, and `.sign()` refuses to run without
`issuer`, `audience` and `expiresIn` (waivable only via
`unsafeAllowMissing*` calls). Every token gets a random `jti` unless you set
one with `.jwtId()`, and lifetimes are capped: 1h by default, raisable to 30
days with `maxLifetime`, beyond that only with `unsafeAllowLongLifetime`.

Then the payload scanner runs, because **a JWS payload is base64url-encoded plaintext**,
readable by anyone who holds the token. It refuses claim names
that read as passwords, secrets, API or private keys, tokens, SSNs or card
data (matched by word: `apiKey` and `accesstoken` are refused, `businessName`
and `tokenizer` are not), and values that are PEM private keys, other JWTs, or
card numbers with a real brand prefix, length and Luhn check. That catches
the copy-paste accident. It does not catch a password in a claim called
`note`, base64 of anything, or anything else that looks like ordinary text.
Never put secrets in it, scanner or no scanner.

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

For a real false positive, waive one claim, or one field inside it, by path:
`.unsafeAllowClaim("profile", "passwordHint")`. The refusal tells you the
path to write. A waiver covers that node and what's under it, nothing beside
it.

A note on HMAC (`HS256/384/512`): it is supported, but every verifier of an
HMAC token holds the same secret and can therefore also **mint** them. For
anything beyond a single service, use asymmetric keys + JWKS. HMAC secrets
must meet the RFC 7518 length floor and pass an entropy check, so
`"my-secret"` will not import, ever. What no library can do is prove a byte
string came out of a random number generator, so a long, high-entropy string
a human made up will import. PLEASE use `generateSecret()` and don't
hand-write key material. Symmetric keys are also refused from a *remote*
JWKS: that endpoint is public, so a secret published there is one anyone can
mint with.

### Transport: the paved road

Do **not** put tokens in `localStorage` or `sessionStorage`: both are
readable by any script on the page, so one XSS means token theft. Lacewing
can't stop you doing that from your own frontend code. What it can do is make
the right way the easy one: an `HttpOnly` cookie (browsers) or an in-memory
bearer token (services):

```ts
import { setTokenCookie, readTokenCookie, parseBearer } from "lacewing";

setTokenCookie(response.headers, token); // always HttpOnly; Secure; SameSite, there is no option to drop them
const fromCookie = readTokenCookie(request);
const fromHeader = parseBearer(request); // strict RFC 6750; no query-string tokens, ever
```

The cookie defaults to the `__Host-` prefix and `SameSite=Lax`; `Strict` is
available, `None` throws.

Both readers refuse ambiguity rather than resolving it. `parseBearer` rejects
the `", "`-joined value `Headers` produces when a request carried two
`Authorization` headers, and `readTokenCookie` returns `undefined` when the
cookie name appears twice, the servers disagree about whether the first or the
last duplicate wins, and cookie shadowing is built on that disagreement.

Both readers take WHATWG `Headers` (or anything carrying them, like `Request`),
or the raw header string. Node-style frameworks - Express, Fastify, Koa - hand
you a plain object instead, so convert once at the edge; a shape the readers
don't accept throws rather than reading as "no token":

```ts
const headers = new Headers(req.headers as Record<string, string>);
const fromCookie = readTokenCookie(headers);

res.setHeader("Set-Cookie", buildTokenCookie(token)); // the response side is just a string
```

### Access vs refresh (the cookbook)

The single most common token-confusion bug is letting a refresh token buy API
access, or an access token mint new sessions. Lacewing **ships** the two
profiles rather than leaving them as homework. They are mutually exclusive by
`typ` (RFC 8725 §3.12), so presenting one where the other is expected fails,
even with identical keys, claims and audience:

```ts
import { accessTokenProfile, refreshTokenProfile, newAccessToken } from "lacewing";

const api = accessTokenProfile({          // typ: "at+jwt", 10m default max age
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",    // the API
  algorithms: ["EdDSA"],
  keys: { jwksUri: "https://auth.example.com/jwks", cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 2000 },
});

const refresh = refreshTokenProfile({     // typ: "rt+jwt", 30d default max age
  issuer: "https://auth.example.com",
  audience: "https://auth.example.com/token", // the auth server, never the API
  algorithms: ["EdDSA"],
  keys: privateJwks,
  revocation,                              // required: a 30-day token nobody can kill is a 30-day incident
});

const token = await newAccessToken()
  .issuer("https://auth.example.com")
  .audience("https://api.example.com")
  .subject("user-42")
  .expiresIn("10m")
  .sign(privateKey);

await jwtVerify(token, refresh); // -> JWT_CLAIM_VALIDATION_FAILED (wrong typ)
```

A refresh profile without `revocation` throws, and doesn't type-check. If you
really have no store, `unsafeNoRevocation: true` says so where your reviewer
can see it. `newRefreshToken()` caps lifetimes at 30 days, the same as the
profile's default age, so the signer never issues a token the verifier has
already given up on.

### Revocation

```ts
import { MemoryRevocationStore } from "lacewing";

const revocation = new MemoryRevocationStore(); // one process; your Redis/DB adapter for a fleet
const profile = defineProfile({ /* ...as above... */ revocation });

revocation.revoke(payload.jti, payload.exp);      // one token, e.g. on logout
revocation.revokeSubject(payload.sub, until);     // everything the user holds right now
revocation.revokeSession(payload.sid, until);     // everything one session holds
await jwtVerify(token, profile); // -> JWT_REVOKED
```

`revokeSubject` and `revokeSession` revoke tokens issued up to that second
(by `iat`), so the user logging back in a second later gets a working token.
`until` is how long the cut-off has to last: now plus your longest
`maxTokenAge` for those tokens. Entries are dropped once nothing they cover
can still verify.

The store is consulted only *after* signature and claims pass, so a forged
token never reaches it, and a store that throws fails closed: the token is
refused because you can't confirm it isn't revoked. Failing open exists, and
it's called `unsafeFailOpenOnRevocationError`.

`MemoryRevocationStore` is memory. Twenty replicas are twenty stores, and a
revocation on one is invisible to the other nineteen. For a fleet, implement
`RevocationStore` over shared state; the context it gets carries `jti`,
`sub`, `sid`, `exp` and `iat`.

## Advanced

### Age vs lifetime: two different caps

`maxTokenAge` and `maxTokenLifetime` sound alike and do different jobs.

**`maxTokenAge`** (required) bounds how long after issuance a token still works
*here* (`now - iat`). It is enforced independently of `exp`, so a token minted
with a decade-long `exp` stops being accepted once it is older than your cap,
no matter what the issuer wrote. It is at most 30 days unless you set
`unsafeAllowLongTokenAge`.

**`maxTokenLifetime`** (optional) bounds the span the issuer *declared*
 (`exp - iat`). Note what `maxTokenAge` alone does with that decade-long token:
it accepts it, right up until the age window closes. That is usually fine, since
the age window is what actually governs. But an `exp` wildly beyond your own
policy is a misissuance signal, and this refuses it on sight instead of
tolerating it for the length of the window:

```ts
const profile = defineProfile({
	/* ...as above... */
	maxTokenAge: "10m",     // unusable 10m after iat, whatever exp claims
	maxTokenLifetime: "1h", // and refuse anything declaring a span beyond 1h
});
```

It is opt-in because plenty of legitimate issuers set a generous `exp` and
expect the verifier's own window to do the limiting.

Clock skew (`maxClockSkew`) defaults to 5 seconds and is at most 30. If your
clocks really drift further than that, `unsafeAllowLargeClockSkew` allows up
to 120, and then go fix your NTP.

### Revocation is not replay protection

Be precise about what revocation buys you: it lets you kill a
token you *know about* (logout, compromise). It does **not** stop replay: a
valid, non-revoked token that leaks can be replayed by anyone who holds it
until `exp`. That is the deliberate cost of stateless verification, and no
JWT library can remove it without becoming a session store.

Your levers, in order of cheapness:

- **Short lifetimes.** The default caps (10m access tokens) exist exactly to
  shrink the replay window. Prefer shortening `exp` over building state.
- **Revocation on every logout/refresh**, so a stolen token dies with the
  session it came from. `revokeSession` does the whole session in one call.
- **A jti-seen cache** when an endpoint must be strictly once-only (e.g. a
  password-reset action token): every Lacewing token carries a `jti`, so you
  can reject repeats with an `unsafeClaimValidators` entry backed by a store
  with the token's remaining TTL. The `unsafe` is there because it's your
  code running inside the accept path:

  ```ts
  const profile = defineProfile({
    /* ...as above... */
    unsafeClaimValidators: {
      jti: async (jti) => {
        // setnx-style: returns false if the jti was already seen
        if (!(await seenCache.addIfAbsent(String(jti), remainingTtl))) {
          throw new Error("token replayed");
        }
      },
    },
  });
  ```

  Validators run after the signature and every built-in claim check have
  passed (revocation comes after them), so they can refuse a token but never
  rescue one. A once-only cache is not built in: which store,
  which TTL and what happens when it's down are your deployment's decisions,
  not something a library should silently half-do.
- **Proof-of-possession** (mTLS-bound or DPoP-bound tokens) when replay by a
  network eavesdropper is in your threat model. Lacewing does bearer tokens
  only.

### Encrypting (JWE): when the payload really is a secret

A signed JWT is readable plaintext. When you genuinely need the payload
*hidden*, not just tamper-evident, use an encrypted JWT. Same discipline as
signing (mandatory `typ`, required `iss`/`aud`/`exp`, a `jti`, capped
lifetime), but with a curated set of encryption algorithms and no `none`. The
sign-time payload scanner is off here, since hiding secrets is the whole
point:

```ts
import {
  EncryptJWT, jwtDecrypt, defineDecryptionProfile, generateEncryptionKeyPair,
} from "lacewing";

const { publicKey, privateKey } = await generateEncryptionKeyPair("ECDH-ES+A256KW");

const token = await new EncryptJWT("at+jwt", { contentEncryption: "A256GCM" })
  .issuer("https://auth.example.com")
  .audience("https://api.example.com")
  .subject("user-42")
  .claim("ssn", "123-45-6789") // fine: it's encrypted, not just encoded
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

const { payload } = await jwtDecrypt(token, profile); // DecryptedJwt, distinct from VerifiedJwt
```

`none`, `RSA1_5`, `RSA-OAEP` (SHA-1) and the password-based `PBES2*` family are
absent by construction. A JWS handed to `jwtDecrypt` (or a JWE handed to
`jwtVerify`) is rejected: the two formats never cross over. The age, skew and
validator rules above apply to decryption profiles the same way.

**Portability (192-bit AES):** the registry includes the `A192*`
algorithms (`A192KW`, `A192GCMKW`, `A192GCM`, `A192CBC-HS384`) for JOSE
completeness, and they work on Node >= 24 (Lacewing's floor). But WebCrypto
implementations in browsers and some edge runtimes do not implement 192-bit
AES at all. If tokens must be decrypted outside Node, stick to the `A128*` /
`A256*` variants. There is no security reason to prefer 192-bit anyway.

### Errors

Every refusal is a `JWTError` with a `code`, and messages never contain token
content: no claim values, no `kid`, nothing an attacker put there. The codes
are distinct on purpose (`JWT_EXPIRED`, `ALGORITHM_NOT_ALLOWED`,
`JWT_REVOKED`, ...), which makes them great for your logs and a free probing
tool if you send them to the client. Don't. Answer every refusal with
`401 invalid_token` and keep the code server-side. Lacewing can't make that
choice for your HTTP layer.

### What Lacewing tells you, and whose clock it reads

Lacewing never logs. Things you should know about that aren't refusals come
to an `onEvent` you pass to a profile or to `createRemoteJWKSet`, as plain
objects; what you do with them is your business, and a listener that throws
is ignored rather than failing the token:

| `type` | When |
| --- | --- |
| `jwks-refresh-failed` | a JWKS fetch failed (`url`, `cause`), once per fetch however many verifications shared it |
| `jwks-stale-serving` | a verification used keys past their cache lifetime because the endpoint is down (`url`, `staleForSeconds`) |
| `revocation-fail-open` | the store threw and `unsafeFailOpenOnRevocationError` let the token through anyway (`cause`) |

If you turned on fail-open and don't listen for that last one, you've chosen
not to know when your revocation is off. Your call, but now it's a visible one.

Every place Lacewing reads the time (profiles, `SignJWT`, `EncryptJWT`,
`createRemoteJWKSet`, `MemoryRevocationStore`) takes a `now` option in
milliseconds, defaulting to `Date.now`, so tests drive time instead of
sleeping or patching globals.

### Debugging

`unsafeDecode(token)` parses without verifying and returns an `UntrustedJwt`
that is type-incompatible with `VerifiedJwt`: useful for inspecting expired
tokens, useless (by design) for auth logic.

### Legacy interop

The `RS*` (RSASSA-PKCS1-v1_5) family is not in the default set, for verifying
tokens from issuers you don't control and can't move off PKCS#1 v1.5. Each one
is a descriptor you import and pass where you want it accepted:

```ts
import { LEGACY_RS256 } from "lacewing/legacy/rsa"; // grep for this in code review

const key = await importKey(issuerPem, LEGACY_RS256);
const legacyIdp = defineProfile({ ..., algorithms: [LEGACY_RS256], keys: key });

// Or, for an issuer that rotates across hash sizes:
import { LEGACY_RSA } from "lacewing/legacy/rsa"; // [LEGACY_RS256, LEGACY_RS384, LEGACY_RS512]
defineProfile({ ..., algorithms: LEGACY_RSA, keys: { jwksUri, cacheTtlSeconds, cooldownSeconds, timeoutMs } });
```

Importing the module changes nothing, and passing a descriptor to one profile
changes no other: `"RS256"` as a string is refused everywhere, and a profile
that does not list `LEGACY_RS256` refuses RS256 tokens, in the same process.
Descriptors are checked by identity, so a hand-built
`{ name: "RS256", minKeyBits: 1024 }` is refused rather than trusted.

Prefer `PS256`/`EdDSA` everywhere you control both sides.

### Ed25519 has two names

`EdDSA` and `Ed25519` are the same signature over the same key. `Ed25519` is
the fully-specified name from [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864),
and some issuers and clients (oauth4webapi, for one) write only that one. Both
are in the default set, as two entries, and Lacewing does not treat them as
aliases:

- A profile accepts the names you list. `algorithms: ["EdDSA"]` refuses a
  token whose header says `Ed25519`; list both if your issuer might send
  either.
- A key is bound to the name it was imported under. A key imported for
  `EdDSA` does not verify an `Ed25519` token, even with both allowlisted.
  Import it once per name, or use a JWKS entry with no `alg`, which serves
  both.

### Building on Lacewing: `lacewing/extension`

For packages that add a check on top of a Lacewing profile and must agree with
Lacewing about what a valid algorithm, duration or JWS segment is. It is
covered by semver like the root export, and it is read-only:

```ts
import { getAlgorithmProperties, parseDuration, parseJsonObject, readHeaderValue } from "lacewing/extension";

getAlgorithmProperties("ES256"); // { name: "ES256", kty: "EC", crv: "P-256", minKeyBits: 256 }, frozen
getAlgorithmProperties("RS256", [LEGACY_RS256]); // legacy names answer only for a caller that passes them
parseDuration("15m");            // 900, as DurationSeconds
parseJsonObject(text, "header"); // a plain object, or JWT_INVALID; a member named twice, or __proto__/constructor/prototype, is refused
readHeaderValue(request, "dpop", "verifyProof"); // same source rules as parseBearer
```

Descriptors come back frozen, so nothing that imports them can lower a
key-size floor for the rest of the process, and there is no registry to add
to: what one package opts into, by passing a `legacy/` descriptor, never
changes what another sees. Header validation is not exported: it
refuses an embedded `jwk`, which is right for a token and wrong for a format
that carries its own key, so each format owns its own header rules.

## The escape hatches, all of them

Every way to loosen one of Lacewing's checks past its bound is spelled
`unsafe*` or `LEGACY_*`, so this is your code review:

```bash
grep -rnE "unsafe[A-Z]|LEGACY_" .
```

| Name | What it loosens |
| --- | --- |
| `unsafeAllowMissingIssuer`, `...Audience`, `...Expiration` | a signed or encrypted token without `iss`, `aud` or `exp` |
| `unsafeAllowClaim(...path)` | the payload scanner, for one claim path |
| `unsafeAllowLongLifetime` | a signing cap above 30 days |
| `unsafeAllowLongTokenAge` | a profile `maxTokenAge` above 30 days |
| `unsafeAllowLargeClockSkew` | `maxClockSkew` above 30s, up to 120s |
| `unsafeClaimValidators` | your code in the accept path |
| `unsafeCustomKeySource` | your code choosing the verification key |
| `unsafeNoRevocation` | a refresh profile with no way to revoke |
| `unsafeFailOpenOnRevocationError` | accepting tokens while the revocation store is down |
| `unsafeDecode` | reading a token without verifying it |
| `LEGACY_RS256`, `LEGACY_RS384`, `LEGACY_RS512`, `LEGACY_RSA` | PKCS#1 v1.5 signatures |

Inside the bounds (an age up to 30 days, skew up to 30s, a lifetime up to 30
days, a stale window up to a day) it's your number and nobody's business.

## What only you can decide

Two things a library is in no position to check, stated as rules rather than
apologies:

- **A kind of token is its `typ` and its audience.** Lacewing makes `typ`
  required and checks it, and the cookbook presets can't share one. But if
  you define two profiles yourself with the same `typ`, issuer, audience and
  keys, you have defined the same profile twice, and they will accept each
  other's tokens, because there is nothing left to tell them apart. Give each
  kind its own `typ`.
- **An HMAC secret has to come from a random number generator.** Lacewing
  enforces the RFC 7518 length floor and refuses short and low-entropy
  secrets. It cannot tell a random 32 bytes from a long string you typed.
  `generateSecret()`.

## Known quirks

- **Two copies of Lacewing do not trust each other's objects.** Keys,
  profiles, key sources and `LEGACY_*` descriptors carry provenance only the
  copy that made them recognises, so that a look-alike object (or a
  `{ ...profile, maxTokenAge: tenYears }`) can't skip the checks that built
  the real one. The cost: a key imported by one installed copy is a forgery
  to another. If a package you depend on brings its own Lacewing, `npm ls
  lacewing` shows it; dedupe to one copy.

- **`x5t` in a header rejects the token.** Lacewing refuses `jku`, `x5u`,
  `jwk`, `x5c`, `x5t`, `zip` and `crit` outright rather than ignoring them,
  and there is no option to allow one. Microsoft Entra ID puts `x5t` (the
  same value as `kid`) on its v1.0 access tokens, and an API registration
  gets v1.0 tokens unless it asks otherwise, so Lacewing cannot verify Entra
  access tokens out of the box. Its v2.0 access tokens carry only `kid`: set
  `api.requestedAccessTokenVersion` to `2` in the app manifest. See
  Microsoft's
  [access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#header-claims)
  and [app manifest reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest#api-attribute).

## Why Lacewing exists

Lacewing is not trying to compete with general-purpose JWT libraries. It started as the hardened setup I kept rebuilding for my own projects, packaged so I'd stop rebuilding it.

The other reason is irritation. Generic JWT libraries are fine, but they leave enough rope for misinformed developers (and lazy AI slop) to ship something unsafe. It pisses me off when people implement something genuinely safe wrongly and then blame the technology instead of accepting operator error. So these mistakes are either impossible here or need an `unsafe*` call to make:

- Decoding instead of verifying
- Accepting `"none"` for the algorithm
- No explicit allowlist on the server that enforces expected algorithms
- Not configuring `iss` or `aud`
- Tokens that never expire, or that a verifier accepts for years
- A refresh token nobody can revoke
- Over-caching a JWKS when an endpoint goes down (stale keys serve for a bounded window, then verification fails closed)

And these it can't make impossible, so it makes them harder to do by accident:

- Putting sensitive data in a signed payload: the scanner refuses the obvious ones, the docs tell you the rest
- Storing tokens in `localStorage` or `sessionStorage`: Lacewing never touches your frontend, so it hands you a cookie helper that can't be configured weak and leaves you no excuse

Insecure usage is still *possible*. It's just spelled out, in a [grep-able list](#the-escape-hatches-all-of-them), so whoever reviews your code gets to ask why. Secure usage is the path of least resistance.

## Lore

Almost none of this started as a library. Most of it existed first as
harnesses, wrappers and primitives we implemented directly inside our own
projects, because we kept having to build the same thing again. Turning it
into one library was mostly me getting sick of rebuilding it.

Our projects live on an internal GitLab instance, because some of our legacy
projects run a modified Lacewing that bends where this one doesn't. That's
also why the email on my commits looks weird.

When Lacewing gets a new major version or a big breaking change, the release
is often coordinated with a release of Smiduweorc's Antlion.

## Attribution

Lacewing depends on and includes code adapted from the [jose](https://github.com/panva/jose) library, created by Filip Skokan (panva). We are grateful for their work!
