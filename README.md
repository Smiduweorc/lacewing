# Lacewing
![Logo](./assets/logo.png)

**Lacewing is an opinionated JWT library for people who want the safe way to be the only easy way, and the unsafe way to be something you have to type out loud.**

It signs, verifies and encrypts JWTs through profiles you define once, with a short algorithm list, required claim checks, a JWKS client, revocation and cookie helpers. Every RFC 8725 requirement a library can check is checked, and the build fails if one has no passing test ([Evidence](./guides/evidence.md)). What it can't check is under [what only you can decide](#what-only-you-can-decide). The cryptography is [jose](https://github.com/panva/jose)'s; the policy is ours.

One runtime dependency (`jose`), nothing happens at import time, ESM only, Node 24 or later.

## Lacewing is not for you if you

- **want to decode a token and decide later whether to trust it.** There is no `decode()` on the verify path. `unsafeDecode` exists for debugging, and its result does not type-check where a verified token is expected.
- **need `alg: none`, `RS256` as a bare string, `RSA1_5` or `PBES2`.** Not available. Legacy `RS*` comes in through `lacewing/legacy/rsa`, by name, per profile.
- **want a token with no `iss`, no `aud` or no `exp`** without saying so in code. You can, through `unsafeAllowMissing*`, and your reviewer will see it.
- **want the library to pick your cache TTLs and timeouts.** Your JWKS endpoint, your rotation schedule, your latency budget. You pick.
- **need tokens bound to a client.** Lacewing does bearer tokens. DPoP is [Antlion](https://github.com/Smiduweorc/antlion), which wraps a Lacewing profile; mTLS-bound tokens are nobody's here.
- **run on CommonJS or Node older than 24.**

[Boundaries](./guides/boundaries.md) has the full list, with where each excluded thing goes instead.

## Security advisories

Lacewing has published security advisories, and one of them may apply to the
version you run. **Read [ADVISORIES.md](./ADVISORIES.md) before you deploy or
upgrade**: it lists every advisory with its affected versions, the release that
fixes it, and a workaround. To report a vulnerability, see
[SECURITY.md](./SECURITY.md).

## How it works

Everything goes through a profile. You define one per kind of token, once: the expected `typ`, the trusted issuer, the required audience, an explicit algorithm allowlist, the key source bound to that issuer, and how old a token may be. `jwtVerify(token, profile)` is the only verify path, and it either returns a `VerifiedJwt` or throws a `JWTError` whose `code` says why. What follows from that:

- **The header never chooses.** The algorithm, the key and the `typ` are the profile's; a token can only fail to match them.
- **Profiles and keys come only from Lacewing's factories** (`defineProfile`, `importKey` and friends). A hand-built or copied one is refused, so nothing skips the checks that made the real one.
- **Loosening is spelled out.** Past its bound, every way to relax a check is named `unsafe*` or `LEGACY_*` (the [list](#the-escape-hatches-all-of-them)).
- **Signing refuses a payload verifying would reject on shape or size**, so a token doesn't first fail when it is used.

## Quick start

1. Install it:

   ```bash
   npm install lacewing
   ```

2. Generate a key, sign, define a profile once, verify:

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

3. In production, point the profile at your issuer's JWKS instead of one key ([Verifying](./guides/verifying.md)), and keep browser tokens in an `HttpOnly` cookie ([Transport](./guides/transport.md)).

`npm run demo` runs the main flows end to end, every refusal a real thrown error.

## Documentation

| Guide | What it covers |
| --- | --- |
| [Getting started](./GETTING-STARTED.md) | Adopting Lacewing in a real service, end to end, and moving off `jsonwebtoken` |
| [Verifying](./guides/verifying.md) | Remote and local JWKS, pinned keys, custom key sources, Ed25519's two names, legacy `RS*` |
| [Signing and encrypting](./guides/signing.md) | What `SignJWT` refuses, the payload scanner, HMAC, JWE |
| [Transport](./guides/transport.md) | Cookies for browsers, bearer headers for services, and what both refuse |
| [Lifetimes and revocation](./guides/lifetimes-and-revocation.md) | Access vs refresh, age vs lifetime, revoking, and why revocation isn't replay protection |
| [Errors, events and time](./guides/operations.md) | Error codes, `onEvent`, the `now` clock, `unsafeDecode` |
| [Building on Lacewing](./guides/extension.md) | `lacewing/extension`, for packages that add a check on top |
| [Boundaries](./guides/boundaries.md) | What Lacewing owns, what it never does, and where that goes |
| [Evidence](./guides/evidence.md) | The requirement gate, whose code does the crypto, and the foreign golden vectors |
| [Migrating](./MIGRATING.md) | What 3.0 and 2.0 break, and what to write instead |
| [Advisories](./ADVISORIES.md), [Security](./SECURITY.md), [Changelog](./CHANGELOG.md) | Published advisories, reporting a vulnerability, every release |

The API reference is generated by TypeDoc (`npm run docs`), with every page above included.

## Where it sits

| Package | Question it answers |
| --- | --- |
| **Lacewing** | **Is this token signed by who it claims, unexpired, and meant for me?** |
| [Antlion](https://github.com/Smiduweorc/antlion) | Is the one presenting it the one it was issued to, and is this request the one they signed? |

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
  `jwk`, `x5c`, `x5t`, `x5t#S256`, `zip` and `crit` outright rather than ignoring them,
  and there is no option to allow one. Microsoft Entra ID puts `x5t` (the
  same value as `kid`) on its v1.0 access tokens, and an API registration
  gets v1.0 tokens unless it asks otherwise, so Lacewing cannot verify Entra
  access tokens out of the box. Its v2.0 access tokens carry only `kid`: set
  `api.requestedAccessTokenVersion` to `2` in the app manifest. See
  Microsoft's
  [access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference#header-claims)
  and [app manifest reference](https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest#api-attribute).

## Scripts

| Script | What it does |
| --- | --- |
| `npm run build` | Compile to `dist/`, after deleting the old one. |
| `npm run typecheck` | Type-check the package and the tests. |
| `npm run lint` | Run ESLint (`lint:fix` to fix what it can). |
| `npm test` | Run the suite with the Node test runner via `tsx`. |
| `npm run test:dist` | Build, then test the built package through its `exports` map. |
| `npm run compliance` | Run the suite and fail if any requirement has no passing test; writes `compliance-report.md`. |
| `npm run demo` | Run `examples/demo.ts`. |
| `npm run docs` | Generate the API reference and guides into `docs/` with TypeDoc. |
| `npm run changelog` | Regenerate `CHANGELOG.md` with git-cliff. |

Publishing is manual; there is no publish workflow.

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

Lacewing depends on and includes code adapted from the [jose](https://github.com/panva/jose) library, created by Filip Skokan (panva); [NOTICE.md](./NOTICE.md) carries the licence. We are grateful for their work!
