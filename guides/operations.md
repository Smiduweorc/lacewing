---
title: Errors, events and time
---

# Errors, events and time

**What a refusal looks like, what Lacewing reports instead of logging, the clock it reads, and how to look inside a token while debugging.**

## Errors

Every refusal is a `JWTError` with a `code`, and messages never contain token
content: no claim values, no `kid`, nothing an attacker put there. The codes
are distinct on purpose (`JWT_EXPIRED`, `ALGORITHM_NOT_ALLOWED`,
`JWT_REVOKED`, ...), which makes them great for your logs and a free probing
tool if you send them to the client. Don't. Answer every refusal with
`401 invalid_token` and keep the code server-side. Lacewing can't make that
choice for your HTTP layer.

## What Lacewing tells you, and whose clock it reads

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

## Debugging

`unsafeDecode(token)` parses without verifying and returns an `UntrustedJwt`
that is type-incompatible with `VerifiedJwt`: useful for inspecting expired
tokens, useless (by design) for auth logic.
