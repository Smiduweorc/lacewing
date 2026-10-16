# Migrating from 1.x to 2.0

2.0 breaks three things on purpose. Each section says what to change.

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
