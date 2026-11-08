---
title: Errors, events and time
---

# Errors, events and time

## Errors

Every refusal of a token is a `JWTError`: one class, with a `code` from the
`JWTErrorCode` union and a message that starts with `lacewing: `. The claim
codes also set `.claim` to the claim's name. Messages never contain token
content (no claim values, no `kid`), so they can't be used as an oracle or
for log injection.

Log the code. Don't send it to the client: a different response per code lets
an attacker probe which check they failed. Return `401 invalid_token` for
every refusal.

```ts
import { JWTError } from "lacewing";

try {
  const { payload } = await jwtVerify(token, profile);
  return handle(payload);
} catch (error) {
  if (!(error instanceof JWTError)) throw error; // not a token problem
  logger.warn({ code: error.code, claim: error.claim }, "token rejected");
  return res.status(401).json({ error: "invalid_token" });
}
```

| `code` | Means |
| --- | --- |
| `JWT_INVALID` | Malformed, or the signature doesn't check out |
| `JWT_EXPIRED` | Past `exp`, or older than `maxTokenAge` |
| `JWT_CLAIM_VALIDATION_FAILED` | A claim is present but wrong (`.claim` names it) |
| `MISSING_CLAIM` | A required claim isn't there (`.claim` names it) |
| `ALGORITHM_NOT_ALLOWED` | `alg` isn't one Lacewing supports, or isn't in your allowlist |
| `JWT_REVOKED` | The revocation store says the token is revoked |
| `REVOCATION_CHECK_FAILED` | The store threw; the token is refused |
| `JWKS_FETCH_FAILED` | Couldn't fetch the JWKS with the global `fetch` |
| `JWKS_NO_MATCHING_KEY` | No key matched, or several did |
| `KEY_IMPORT_FAILED` | Key material couldn't be imported or generated |
| `KEY_TYPE_MISMATCH` | The key doesn't fit the algorithm |
| `KEY_EXPORT_FAILED` | The key couldn't be exported (not extractable, or a secret as PEM) |
| `ENTROPY_CHECK_FAILED` | The HMAC secret is too weak |
| `PAYLOAD_HYGIENE_VIOLATION` | The payload looks like it contains a secret (`.claim` names where) |
| `MAX_LIFETIME_EXCEEDED` | `.expiresIn()` is past the lifetime cap |
| `BEARER_PARSE_FAILED` | The `Authorization` header isn't exactly `Bearer <token>` |

Misconfiguration (a profile with no `typ`, an `http:` JWKS URL, a malformed
duration, a profile or key Lacewing didn't build) is a `TypeError` at the
call that receives it. When your `unsafeClaimValidators` function or your
revocation store throws, you get `JWT_CLAIM_VALIDATION_FAILED` or
`REVOCATION_CHECK_FAILED` with your error as `cause`. Anything else that is
not a `JWTError` did not come from Lacewing's checks: a `fetch` you passed to
`createRemoteJWKSet` that throws reaches you as itself.

## Events

Lacewing never logs. Things worth knowing that aren't refusals go to an
`onEvent` you pass to a profile or to `createRemoteJWKSet`, as plain objects.
A listener that throws is ignored and does not fail the token.

| `type` | When |
| --- | --- |
| `jwks-refresh-failed` | a JWKS fetch failed (`url`, `cause`), once per fetch however many verifications shared it |
| `jwks-stale-serving` | a verification used keys past their cache lifetime because the endpoint is down (`url`, `staleForSeconds`) |
| `revocation-fail-open` | the store threw and `unsafeFailOpenOnRevocationError` let the token through anyway (`cause`) |

If you enable fail-open, listen for `revocation-fail-open`. Otherwise you
won't know when revocation is down.

## Time

Every place Lacewing reads the time (profiles, `SignJWT`, `EncryptJWT`,
`createRemoteJWKSet`, `MemoryRevocationStore`) takes a `now` option in
milliseconds, defaulting to `Date.now`, so tests can drive time without
sleeping or patching globals.

## Debugging

`unsafeDecode(token)` parses without verifying and returns an `UntrustedJwt`,
which is type-incompatible with `VerifiedJwt`. Use it to inspect expired or
rejected tokens, never for auth decisions.

```ts
import { unsafeDecode } from "lacewing";

const { header, payload } = unsafeDecode(token);
console.log("token was issued by", payload.iss);
```
