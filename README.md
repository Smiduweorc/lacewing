# Lacewing
![Logo](./assets/logo.png)

JWT signing, verification and encryption for Node. You define a profile once per kind of token, and anything that weakens a check has to be called `unsafe*` or `LEGACY_*`.

Signatures and encryption are done by [jose](https://github.com/panva/jose). Lacewing adds the checks around them: a short algorithm list, required `typ`, `iss`, `aud` and `exp`, a bounded JWKS client, revocation and cookie helpers. Every RFC 8725 requirement a library can check has a test, and CI fails if one doesn't pass ([Evidence](./guides/evidence.md)).

## Install

```bash
npm install lacewing
```

Node 24 or later (CI runs Node 24 on Linux, macOS and Windows), ESM only. One runtime dependency, `jose`. Nothing runs at import time.

## Example

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

A profile holds the expected `typ`, the trusted issuer, the required audience, an algorithm allowlist, the key source and the maximum token age. `jwtVerify(token, profile)` is the only verify path: it returns a `VerifiedJwt` or throws a `JWTError` whose `code` says why. The algorithm, key and `typ` always come from the profile, never from the token header. Profiles and keys must come from Lacewing's factories (`defineProfile`, `importKey` and so on); a hand-built or copied one is refused. Signing refuses a payload that verifying would reject on shape or size.

In production, point the profile at your issuer's JWKS ([Verifying](./guides/verifying.md)) and keep browser tokens in an `HttpOnly` cookie ([Transport](./guides/transport.md)). `examples/demo.ts` runs the main flows end to end.

## Not included

- Decoding without verifying. `unsafeDecode` exists for debugging, and its result does not type-check where a verified token is expected.
- `alg: none`, `RSA1_5` and `PBES2`. `RS*` only through `lacewing/legacy/rsa`, per profile; `"RS256"` as a string is refused.
- Tokens with no `iss`, `aud` or `exp`, unless you pass `unsafeAllowMissing*`.
- Default JWKS cache TTLs and timeouts. You set them.
- DPoP. Use [Antlion](https://github.com/Smiduweorc/antlion), which wraps a Lacewing profile. mTLS-bound tokens are not supported.
- CommonJS and Node before 24.

[Boundaries](./guides/boundaries.md) has the full list, with where each one goes instead.

## What Lacewing can't check

- Two profiles with the same `typ`, issuer, audience and keys accept each other's tokens, because nothing tells them apart. Lacewing requires `typ` and the cookbook presets use different ones; for your own profiles, give each kind of token its own `typ`.
- Whether an HMAC secret is random. Lacewing enforces the RFC 7518 length floor and refuses short and low-entropy secrets, but it can't tell random bytes from a long string you typed. Use `generateSecret()`.

## Escape hatches

Every option that loosens a check past its bound is named `unsafe*` or `LEGACY_*`. To audit a codebase:

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

Inside the bounds (an age up to 30 days, skew up to 30s, a lifetime up to 30 days, a stale window up to a day) no flag is needed.

## Known quirks

- Two copies of Lacewing do not trust each other's objects. Keys,
  profiles, key sources and `LEGACY_*` descriptors carry provenance only the
  copy that made them recognises, so that a look-alike object (or a
  `{ ...profile, maxTokenAge: tenYears }`) can't skip the checks that built
  the real one. The cost: a key imported by one installed copy is a forgery
  to another. If a package you depend on brings its own Lacewing, `npm ls
  lacewing` shows it; dedupe to one copy.

- `x5t` in a header rejects the token. Lacewing refuses `jku`, `x5u`,
  `jwk`, `x5c`, `x5t`, `x5t#S256`, `zip` and `crit` outright rather than ignoring them,
  and there is no option to allow one. Microsoft Entra ID puts `x5t` (the
  same value as `kid`) on its v1.0 access tokens, and an API registration
  gets v1.0 tokens unless it asks otherwise, so Lacewing cannot verify Entra
  access tokens out of the box. Its v2.0 access tokens carry only `kid`: set
  `api.requestedAccessTokenVersion` to `2` in the app manifest. See
  Microsoft's
  [access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#header-claims)
  and [app manifest reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest#api-attribute).

- Tokens Lacewing signs have no `kid`, so a JWKS with two keys of the same
  algorithm can't verify them. See "Before you plan a rotation" in
  [Getting started](./GETTING-STARTED.md).

## Documentation

- [Getting started](./GETTING-STARTED.md)
- [Verifying](./guides/verifying.md)
- [Signing and encrypting](./guides/signing.md)
- [Transport](./guides/transport.md)
- [Lifetimes and revocation](./guides/lifetimes-and-revocation.md)
- [Errors, events and time](./guides/operations.md)
- [Building on Lacewing](./guides/extension.md)
- [Boundaries](./guides/boundaries.md)
- [Evidence](./guides/evidence.md)
- [Migrating](./MIGRATING.md)
- [Changelog](./CHANGELOG.md)

Security advisories are in [ADVISORIES.md](./ADVISORIES.md); check it before you deploy or upgrade. To report a vulnerability, see [SECURITY.md](./SECURITY.md).

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
- Storing tokens in `localStorage` or `sessionStorage`: Lacewing never touches your frontend, so it hands you a cookie helper that can't be configured weak

## Licence

MIT, see [LICENSE](./LICENSE). Lacewing includes code adapted from [jose](https://github.com/panva/jose) by Filip Skokan (panva), also MIT; its licence is in [NOTICE.md](./NOTICE.md).

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
