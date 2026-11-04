---
title: Verifying tokens
---

# Verifying tokens

**How `jwtVerify` gets its keys: a remote JWKS, keys you already hold, a local JWKS, your own key source, and the legacy and Ed25519 naming rules.**

## A remote JWKS

With an issuer that publishes a JWKS:

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

## Keys you already have

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

## Ed25519 has two names

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

## Legacy interop

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
