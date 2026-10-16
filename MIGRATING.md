# Migrating from 1.x to 2.0

2.0 breaks two things on purpose: how legacy `RS*` algorithms are enabled, and
the error classes. Each section says what to change.

## Legacy algorithms are values you pass, not a switch you flip

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

## One error class: `JWTError` with a `code`

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
