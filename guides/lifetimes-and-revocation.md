---
title: Lifetimes and revocation
---

# Lifetimes and revocation

## Access and refresh tokens

A refresh token that buys API access, or an access token that mints new
sessions, is a token-confusion bug. Lacewing has both profiles built in, and
they refuse each other's tokens by `typ` (RFC 8725 section 3.12), even with
identical keys, claims and audience:

```ts
import { accessTokenProfile, refreshTokenProfile, newAccessToken, newRefreshToken } from "lacewing";

export const api = accessTokenProfile({
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",        // the API
  algorithms: ["EdDSA"],
  keys: { jwksUri: "https://auth.example.com/.well-known/jwks.json", cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 2000 },
});

export const refresh = refreshTokenProfile({
  issuer: "https://auth.example.com",
  audience: "https://auth.example.com/token", // the auth server's token endpoint
  algorithms: ["EdDSA"],
  keys: publicKey,
  revocation: store,
});

const access = await newAccessToken()
  .issuer("https://auth.example.com").audience("https://api.example.com")
  .subject("user-42").expiresIn("10m").sign(privateKey);

const refreshToken = await newRefreshToken()
  .issuer("https://auth.example.com").audience("https://auth.example.com/token")
  .subject("user-42").expiresIn("30d").sign(privateKey);

await jwtVerify(access, refresh); // throws JWT_CLAIM_VALIDATION_FAILED (wrong typ)
```

| | access | refresh |
| --- | --- | --- |
| `typ` | `at+jwt` | `rt+jwt` |
| audience | your API | your auth server's token endpoint |
| default `maxTokenAge` | 10m | 30d |
| lifetime cap when signing | 1h | 30d |
| revocation | optional | required |

A refresh profile without `revocation` throws and doesn't type-check. If you
have no store, pass `unsafeNoRevocation: true`. The 30-day signing cap on
`newRefreshToken()` matches the profile's default age, so the signer never
issues a token the verifier would already refuse.

## Age and lifetime

`maxTokenAge` (required) bounds how long after issuance a token still works
here (`now - iat`). It is enforced independently of `exp`: a token with a
decade-long `exp` stops being accepted once it is older than your cap,
whatever the issuer wrote. At most 30 days unless you set
`unsafeAllowLongTokenAge`.

`maxTokenLifetime` (optional) bounds the span the issuer declared
(`exp - iat`). Without it, that decade-long token is accepted until the age
window closes, which is usually fine. With it, an `exp` far beyond your
policy is refused on sight, as a sign of misissuance:

```ts
const profile = defineProfile({
	/* ...as above... */
	maxTokenAge: "10m",     // unusable 10m after iat, whatever exp claims
	maxTokenLifetime: "1h", // and refuse anything declaring a span beyond 1h
});
```

It is opt-in because many legitimate issuers set a generous `exp` and expect
the verifier's window to do the limiting.

Clock skew (`maxClockSkew`) defaults to 5 seconds and is at most 30.
`unsafeAllowLargeClockSkew` raises the ceiling to 120 seconds.

## Revocation

Every token Lacewing signs gets a `jti`, so revocation always has a key.

```ts
import { MemoryRevocationStore } from "lacewing";

const revocation = new MemoryRevocationStore();
const profile = defineProfile({ /* ...as above... */ revocation });

const { payload } = await jwtVerify(token, profile);
revocation.revoke(payload.jti as string, payload.exp as number); // one token, e.g. on logout

const until = Math.floor(Date.now() / 1000) + 30 * 24 * 3600;     // now + your longest maxTokenAge
revocation.revokeSubject(payload.sub as string, until);          // "log out everywhere"
revocation.revokeSession(payload.sid as string, until);          // one device

await jwtVerify(token, profile); // throws JWT_REVOKED
```

`revokeSubject` and `revokeSession` revoke tokens issued up to that second
(by `iat`), so the user logging back in a second later gets a working token.
`until` is how long the cut-off has to last: now plus your longest
`maxTokenAge` for those tokens. Entries are dropped once nothing they cover
can still verify, so the store does not grow without bound.

The store is consulted only after signature and claims pass, so a forged
token never reaches it. A store that throws fails closed: the token is
refused because you can't confirm it isn't revoked, so a Redis outage is an
auth outage. `unsafeFailOpenOnRevocationError: true` accepts tokens instead.

`MemoryRevocationStore` is per process. Twenty replicas are twenty stores,
and a revocation on one is invisible to the others. For a fleet, implement
`RevocationStore` over shared state:

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

The context also carries `sub`, `sid`, `exp` and `iat`, so a shared store can
do what `revokeSubject` and `revokeSession` do: keep a per-subject cut-off
time and reject any token whose `iat` is at or before it.

## Revocation is not replay protection

Revocation only kills tokens you know about (logout, a reported compromise).
A leaked token that hasn't been revoked works for anyone until `exp`. That is
the price of stateless verification. What you can do about it:

- Keep lifetimes short. The 10-minute default for access tokens is there to
  shrink the replay window.
- Revoke on every logout and refresh, so a stolen token dies with its
  session. `revokeSession` does a whole session in one call.
- Add a jti-seen cache where an endpoint must be strictly once-only (a
  password-reset token, say). Every Lacewing token has a `jti`, so an
  `unsafeClaimValidators` entry backed by a store with the token's remaining
  TTL can reject repeats:

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
  passed, and before revocation, so they can refuse a token but never rescue
  one. The cache is not built in because the store, the TTL and the
  behaviour when it is down depend on your deployment.
- Bind tokens to a key when replay by a network eavesdropper is in your
  threat model. Lacewing does bearer tokens only; for DPoP, put
  [Antlion](https://github.com/Smiduweorc/antlion) in front of your profile.
