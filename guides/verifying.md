---
title: Verifying tokens
---

# Verifying tokens

## A remote JWKS

With an issuer that publishes a JWKS:

```ts
import { defineProfile, jwtVerify, createRemoteJWKSet } from "lacewing";

const accessToken = defineProfile({
	typ: "at+jwt",
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	algorithms: ["EdDSA"],
	keys: createRemoteJWKSet("https://auth.example.com/.well-known/jwks.json", {
		cacheTtlSeconds: 300, // no Cache-Control? a key your issuer removed stays trusted this long
		cooldownSeconds: 30,  // at most one fetch per 30s, however many made-up kids arrive
		timeoutMs: 2000,      // verification waits this long on a cold cache
	}),
	maxTokenAge: "10m",
});

const { payload } = await jwtVerify(token, accessToken);
```

`keys: { jwksUri, cacheTtlSeconds, cooldownSeconds, timeoutMs }` in the
profile does the same thing.

These three have no defaults, because the cache TTL decides how long a
rotated-out key stays trusted and only you know your rotation schedule.
`cacheTtlSeconds` is 0 to 86400 (a `Cache-Control: max-age` on the response
wins, capped at a day). `cooldownSeconds` is 1 to 86400 and has to be shorter
than your rotation overlap, or a new key is refused until the cooldown
passes. `timeoutMs` must be positive and is part of your request latency.
HTTPS only, and redirects are never followed.

When the endpoint goes down, the last good keys keep serving for a bounded
window after their cache lifetime ends (`staleWhileErrorSeconds`, default
3600, at most 86400), and then verification fails closed. The window is
bounded because a key you rotated out after a compromise would otherwise stay
trusted for as long as an attacker can keep your JWKS unreachable. The
longest any fetched key can be trusted is the cache lifetime plus that
window, two days at most. `0` turns stale serving off.

The response is read under a 1 MiB budget, checked against `Content-Length`
and again on every chunk. Symmetric (`oct`) entries are refused from a remote
set: a JWKS endpoint is public, so anyone could sign with a secret published
there. A local JWKS may still carry them.

## Keys you already have

If the issuer gave you a raw public key, or you're pinning one, pass it to
`keys` directly. `importKey` reads a PEM (SPKI public key), a JWK or a
`CryptoKey`, and binds it to one algorithm:

```ts
import { defineProfile, importKey } from "lacewing";

const publicKey = await importKey(spkiPem, "ES256");

const profile = defineProfile({
	typ: "at+jwt",
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	algorithms: ["ES256"],
	keys: publicKey,
	maxTokenAge: "10m",
});
```

A private key is refused, with an error that says profiles verify and don't
sign. The key's algorithm must also be in the allowlist, so a key imported
for `ES256` can't be used by an `EdDSA`-only profile.

For a few keys and no endpoint, pass a JWKS document inline:

```ts
keys: {
	keys: [
		{ kty: "OKP", crv: "Ed25519", x: "...", kid: "2024-key" },
		{ kty: "EC", crv: "P-256", x: "...", y: "...", kid: "2025-key" },
	],
},
```

Selection is exact: the token's `kid`, and its algorithm's key type and
curve, have to single out one key. Two keys that both match with no `kid` to
tell them apart throw `JWKS_NO_MATCHING_KEY`. A key with no `alg` is refused
if the profile allows several algorithms it could serve (say `PS256` and
`PS512` for one RSA key); set `alg` on the key. EC and OKP keys are exempt,
because their curve already names the algorithm.

## Your own key source

If your keys live somewhere else (an HSM, a secrets manager, a database),
wrap anything with a `getVerificationKey(header)` method in
`unsafeCustomKeySource(...)` and pass that. A bare object is refused. The
`alg` it returns must be the token's, and a raw HMAC secret it returns goes
through the same strength check as `importKey`.

## Ed25519 has two names

`EdDSA` and `Ed25519` are the same signature over the same key. `Ed25519` is
the fully-specified name from [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864),
and some issuers and clients (oauth4webapi, for one) write only that one. Both
are in the default set as separate entries, and Lacewing does not treat them
as aliases:

- A profile accepts the names you list. `algorithms: ["EdDSA"]` refuses a
  token whose header says `Ed25519`; list both if your issuer might send
  either.
- A key is bound to the name it was imported under. A key imported for
  `EdDSA` does not verify an `Ed25519` token, even with both allowlisted.
  Import it once per name, or use a JWKS entry with no `alg`, which serves
  both.

## Legacy RS* algorithms

The `RS*` (RSASSA-PKCS1-v1_5) family is not in the default set, and
`"RS256"` as a string is refused. For issuers you can't move off PKCS#1
v1.5, import a descriptor and pass it where you want it accepted:

```ts
import { LEGACY_RS256 } from "lacewing/legacy/rsa";

const key = await importKey(issuerPem, LEGACY_RS256);
const legacyIdp = defineProfile({ ..., algorithms: [LEGACY_RS256], keys: key });

// Or, for an issuer that rotates across hash sizes:
import { LEGACY_RSA } from "lacewing/legacy/rsa"; // [LEGACY_RS256, LEGACY_RS384, LEGACY_RS512]
defineProfile({ ..., algorithms: LEGACY_RSA, keys: { jwksUri, cacheTtlSeconds, cooldownSeconds, timeoutMs } });
```

Importing the module changes nothing, and passing a descriptor to one
profile changes no other: a profile that does not list `LEGACY_RS256`
refuses RS256 tokens, in the same process. Descriptors are checked by
identity, so a hand-built `{ name: "RS256", minKeyBits: 1024 }` is refused.

Use `PS256` or `EdDSA` where you control both sides.
