---
title: Lifetimes and revocation
---

# Lifetimes and revocation

**How long a token works, the access/refresh split, revoking tokens, and what revocation does not do.**

## Access vs refresh

A refresh token that buys API access, or an access token that mints new
sessions, is a token-confusion bug. Lacewing has both profiles built in, and
they are mutually exclusive by
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

## Age vs lifetime: two different caps

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

## Revocation

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

## Revocation is not replay protection

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
- **Proof-of-possession** when replay by a network eavesdropper is in your
  threat model. Lacewing does bearer tokens only; for DPoP-bound tokens, put
  [Antlion](https://github.com/Smiduweorc/antlion) in front of your profile.
