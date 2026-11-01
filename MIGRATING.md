# Migrating from 2.x to 3.0

3.0 makes every remaining way to loosen a check carry an `unsafe` name you
can grep for, makes the caller name the numbers only the caller knows, and
fixes two v2 behaviours that did not do what the docs said. Each row is a
build or runtime error in 3.0 until you change it.

| 2.x | 3.0 |
| --- | --- |
| `maxTokenAge` above 30 days | add `unsafeAllowLongTokenAge: true` |
| `maxClockSkew` above 30s (up to 120s) | add `unsafeAllowLargeClockSkew: true`; 120s stays the hard ceiling |
| `claimValidators: {...}` | rename to `unsafeClaimValidators: {...}` |
| `keys: { getVerificationKey }` (custom source) | `keys: unsafeCustomKeySource({ getVerificationKey })` |
| `new SignJWT(typ, { maxLifetime })` or `EncryptJWT` above 30 days | add `unsafeAllowLongLifetime: true` |
| `createRemoteJWKSet(url)` or `keys: { jwksUri }` | name `cacheTtlSeconds`, `cooldownSeconds` and `timeoutMs`; 2.x used 300, 30 and 5000 |
| `cooldownSeconds: 0` | at least 1; 0 let every unknown `kid` trigger a fetch |
| `staleWhileErrorSeconds` above 86400 | at most 86400 |
| `refreshTokenProfile({...})` with no `revocation` | pass a store, or `unsafeNoRevocation: true` |
| `unsafeAllowClaim("profile")` to get past one nested field | `unsafeAllowClaim("profile", "field")` waives only that field |
| a profile, key or key source built by hand or copied with `{ ...x }` | build it with `defineProfile`, `importKey` and friends; copies throw `TypeError` |
| `keys: source` after `unsafeCustomKeySource(source)` | pass the wrapper it returns, not the original object |
| `notBefore` at or after `expiresIn` | throws `TypeError`; such a token could never be valid |
| signing a token `jwtVerify` would refuse (a `__proto__` member, an `iss`/`sub`/`jti` over 1024 characters, a token over 16384) | throws `TypeError` at `.sign()`/`.encrypt()` instead of failing at verify time |
| an RSA key under 2048 bits from PEM or a `CryptoKey` | `KEY_TYPE_MISMATCH` at import (JWKs already were) |
| an encryption key of the wrong family or curve (an ECDSA key for `ECDH-ES`, X25519, RSA-PSS for `RSA-OAEP-256`) | `KEY_TYPE_MISMATCH` at import |
| a `dir` key whose size fits none of the profile's `contentEncryptionAlgorithms` | `TypeError` from `defineDecryptionProfile` |
| `RevocationStore.isAnyRevoked` | removed; Lacewing never called it |

The first four rows apply to both `defineProfile` and
`defineDecryptionProfile`. Sources from `createLocalJWKSet` and
`createRemoteJWKSet` need no wrapper. A single-argument `unsafeAllowClaim`
still waives the whole claim, as before.

Behaviour that changed without an API change:

- **The stale-while-error window starts when the cached keys expire**, not
  when they were fetched. In 2.x an endpoint sending `max-age=3600` or more
  got no stale serving at all with the default 3600s window. Keys can now be
  trusted for at most the cache lifetime plus the window.
- **The payload scanner matches names by word.** `businessName`,
  `classNumber` and `tokenizer` now pass; `apiKey`, `accesstoken` and
  `passwordHash` are still refused. Waivers you added for the first kind can
  go.
- **`newRefreshToken()` caps lifetimes at 30 days**, down from 90, to match
  `refreshTokenProfile`'s default `maxTokenAge`. A 90-day refresh token was
  refused at day 30 anyway.
- **Keys, profiles and key sources are unforgeable.** In 2.x an object
  literal with `__brand: "LacewingKey"` signed with whatever bytes it held,
  and `jwtVerify` accepted any object shaped like a profile, including one
  with a decade of accepted age. Both are refused now.
- **Binary HMAC secrets that repeat a short pattern** (all zeros, `fill(7)`)
  throw `ENTROPY_CHECK_FAILED`, from `importKey`, a JWKS and custom sources.
- **A `now` clock that returns NaN or a non-number throws** on every read.
  Every comparison with NaN is false, so it would have let expired tokens
  through.
- **`x5t#S256` in a header rejects the token**, like `x5t` already did.
- **Cookie prefixes are matched in any case**: `__HOST-t` gets the `__Host-`
  rules, as browsers apply them. A cookie path with a control character
  throws.
- **The scanner also refuses card numbers written as JSON numbers, and
  compact JWEs.**
- **New and optional:** an `onEvent` listener on profiles and
  `createRemoteJWKSet`, and a `now` clock option everywhere time is read.
- **`MemoryRevocationStore` revokes by subject and session too**:
  `revokeSubject(sub, until)` and `revokeSession(sid, until)`. Revoking the
  same `jti` twice keeps the later expiry instead of the last one written.

# Migrating from 1.x to 2.0

2.0 breaks two things on purpose: how legacy `RS*` algorithms are enabled, and
the error classes. Each section says what to change.

### Legacy algorithms are values you pass, not a switch you flip

In 1.x, `enableLegacyRS256()` added `RS256` to a registry shared by the whole
process. Every profile, `importKey` call and package in that process could
then use it, and whether a test passed depended on which file had run first.
2.0 has no registry. The modern set is a frozen constant, and each legacy
algorithm is a descriptor you import and pass at the call site:

```ts
// 1.x
import { enableLegacyRS256 } from "lacewing/legacy/rs256";
enableLegacyRS256();
const key = await importKey(pem, "RS256");
defineProfile({ ..., algorithms: ["RS256"], keys: key });

// 2.0
import { LEGACY_RS256 } from "lacewing/legacy/rsa";
const key = await importKey(pem, LEGACY_RS256);
defineProfile({ ..., algorithms: [LEGACY_RS256], keys: key });
```

| 1.x | 2.0 |
| --- | --- |
| `enableLegacyRS256()` | pass `LEGACY_RS256` (from `lacewing/legacy/rsa` or `lacewing/legacy/rs256`) |
| `enableLegacyRS384()` | pass `LEGACY_RS384` |
| `enableLegacyRS512()` | pass `LEGACY_RS512` |
| `enableLegacyRSA()` | pass `LEGACY_RSA`, the array of all three |
| `importKey(m, "RS256")` | `importKey(m, LEGACY_RS256)` |
| `generateKeyPair("RS256")` | `generateKeyPair(LEGACY_RS256)` |
| `algorithms: ["RS256"]` | `algorithms: [LEGACY_RS256]`; strings and descriptors mix: `["PS256", LEGACY_RS256]` |
| `getAlgorithmProperties("RS256")` | `getAlgorithmProperties("RS256", [LEGACY_RS256])` |

`"RS256"` as a string is refused everywhere with `ALGORITHM_NOT_ALLOWED`. A
descriptor works only where it is passed: a profile that lists `LEGACY_RS256`
accepts RS256 tokens, and its neighbour in the same process that does not list
it still refuses them. Descriptors are compared by identity, so a hand-built
`{ name: "RS256", ... }` is refused.

Two public types follow from this:

- `ExpectedJwtProfile.alg` holds the resolved descriptors
  (`readonly AlgorithmInfo[]`), not branded strings. Read `.name` for the
  algorithm name.
- A custom `KeySource` receives those descriptors as its second argument,
  `getVerificationKey(header, allowedAlgorithms: readonly AlgorithmInfo[])`,
  so it can see each algorithm's key type and curve without a lookup.

### For antlion (or any package built on `lacewing/extension`)

Antlion's `legacyRS256Proofs()` called `enableLegacyRS256()` so that
`getAlgorithmProperties("RS256")` would answer in `checkKey`. That call, and
the process-wide side effect its doc comment warned about, go away:

1. `src/legacy.ts`: drop the `enableLegacyRS256` import and call. Keep
   Lacewing's descriptor with the proof algorithm, for example
   `import { LEGACY_RS256 } from "lacewing/legacy/rsa"` and return a frozen
   `{ name: "RS256", lacewing: LEGACY_RS256 }` branded as
   `LegacyProofAlgorithm`.
2. `src/profile.ts` `checkAlgorithms`: instead of probing
   `getAlgorithmProperties(name)` to detect "RS256 is not enabled", store the
   descriptors (`legacy.map((entry) => entry.lacewing)`) on the DPoP profile
   next to the names. The "not enabled" error has no cause any more; a proof
   algorithm that did not come from `antlion-lacewing/legacy` is still
   refused by the brand check.
3. `src/proof.ts` `checkKey`: `getAlgorithmProperties(alg, profile.legacyDescriptors)`.
   For the FAPI set the second argument is `[]` and nothing changes.
4. `lacewing` peer range: `^2.0.0`. The `JWTError` import and
   `error instanceof JWTError` in `src/verify.ts` keep working; code that reads
   `cause.code` (`"JWT_INVALID"`, `"JWT_CLAIM_VALIDATION_FAILED"`) keeps
   working. A test that compares a wrapped Lacewing message must add the
   `lacewing: ` prefix.
5. The access-token profile's own `algorithms` is unaffected unless it lists
   `"RS256"`; if it does, list `LEGACY_RS256` instead.

### One error class: `JWTError` with a `code`

The sixteen 1.x subclasses are gone. Every refusal is now a `JWTError`, and
`error.code` says which one it was. The codes themselves are the strings 1.x
already used, so code that branched on `error.code` keeps working.

```ts
// 1.x
if (error instanceof JWTExpired) { ... }
assert.rejects(jwtVerify(token, profile), JWTRevoked);

// 2.0
if (error instanceof JWTError && error.code === "JWT_EXPIRED") { ... }
assert.rejects(jwtVerify(token, profile), { name: "JWTError", code: "JWT_REVOKED" });
```

| 1.x class | 2.0 `code` |
| --- | --- |
| `JWTInvalid` | `JWT_INVALID` |
| `JWTExpired` | `JWT_EXPIRED` |
| `JWTClaimValidationFailed` | `JWT_CLAIM_VALIDATION_FAILED` (sets `claim`) |
| `MissingClaim` | `MISSING_CLAIM` (sets `claim`) |
| `AlgorithmNotAllowed` | `ALGORITHM_NOT_ALLOWED` |
| `KeyImportFailed` | `KEY_IMPORT_FAILED` |
| `KeyTypeMismatch` | `KEY_TYPE_MISMATCH` |
| `KeyExportFailed` | `KEY_EXPORT_FAILED` |
| `EntropyCheckFailed` | `ENTROPY_CHECK_FAILED` |
| `JWKSFetchFailed` | `JWKS_FETCH_FAILED` |
| `JWKSNoMatchingKey` | `JWKS_NO_MATCHING_KEY` |
| `JWTRevoked` | `JWT_REVOKED` |
| `RevocationCheckFailed` | `REVOCATION_CHECK_FAILED` |
| `PayloadHygieneViolation` | `PAYLOAD_HYGIENE_VIOLATION` (sets `claim`) |
| `MaxLifetimeExceeded` | `MAX_LIFETIME_EXCEEDED` |
| `BearerParseFailed` | `BEARER_PARSE_FAILED` |

The `JWTErrorCode` type is the union of all of them, so a `switch` over
`error.code` is checked for exhaustiveness.

Also changed:

- `error.name` is `"JWTError"` for every code. It used to be the subclass name.
- Messages start with `lacewing: `. Match on `code`, never on message text.
- A `fetch` you pass to `createRemoteJWKSet` keeps its own errors: whatever it
  throws reaches you unchanged instead of arriving as `JWKS_FETCH_FAILED` with
  your error as `cause`. Failures of the global `fetch` are still
  `JWKS_FETCH_FAILED`.
