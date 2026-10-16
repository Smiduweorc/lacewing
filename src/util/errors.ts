/**
 * Lacewing's one error class.
 *
 * Every refusal Lacewing makes is a {@link JWTError} whose `code` names the
 * failure mode, so callers branch on `error.code` and never on message text.
 * Messages stay generic: security-relevant rejections never echo untrusted
 * token content (no oracle for attackers, no log injection, RFC 8725 §3.10
 * hygiene).
 *
 * Errors thrown by code the caller supplied (a `fetch` for a remote JWKS, for
 * one) are not Lacewing's refusals and come back unchanged.
 */

/**
 * Why Lacewing refused.
 *
 * | Code | Meaning |
 * | --- | --- |
 * | `JWT_INVALID` | Token structure, encoding or signature is invalid. |
 * | `JWT_EXPIRED` | Token is past `exp`, or older than the profile's `maxTokenAge`. |
 * | `JWT_CLAIM_VALIDATION_FAILED` | A claim is present but fails the profile's rules. Sets `claim`. |
 * | `MISSING_CLAIM` | A claim the profile or Lacewing requires is absent. Sets `claim`. |
 * | `ALGORITHM_NOT_ALLOWED` | The algorithm is not one Lacewing speaks, or not in the allowlist. |
 * | `KEY_IMPORT_FAILED` | Key material could not be imported or generated. |
 * | `KEY_TYPE_MISMATCH` | Key does not fit the algorithm it is used with. |
 * | `KEY_EXPORT_FAILED` | Key material could not be exported. |
 * | `ENTROPY_CHECK_FAILED` | HMAC secret is too short or looks human-chosen (§3.5). |
 * | `JWKS_FETCH_FAILED` | Remote JWKS could not be fetched or parsed. |
 * | `JWKS_NO_MATCHING_KEY` | No single key in the JWKS matches the token. |
 * | `JWT_REVOKED` | Token is valid but its `jti` is revoked. |
 * | `REVOCATION_CHECK_FAILED` | The revocation store errored and Lacewing failed closed. |
 * | `PAYLOAD_HYGIENE_VIOLATION` | A payload about to be signed carries sensitive data. Sets `claim`. |
 * | `MAX_LIFETIME_EXCEEDED` | Requested token lifetime exceeds the cap. |
 * | `BEARER_PARSE_FAILED` | `Authorization` header failed strict RFC 6750 parsing. |
 */
export type JWTErrorCode =
	| "JWT_INVALID"
	| "JWT_EXPIRED"
	| "JWT_CLAIM_VALIDATION_FAILED"
	| "MISSING_CLAIM"
	| "ALGORITHM_NOT_ALLOWED"
	| "KEY_IMPORT_FAILED"
	| "KEY_TYPE_MISMATCH"
	| "KEY_EXPORT_FAILED"
	| "ENTROPY_CHECK_FAILED"
	| "JWKS_FETCH_FAILED"
	| "JWKS_NO_MATCHING_KEY"
	| "JWT_REVOKED"
	| "REVOCATION_CHECK_FAILED"
	| "PAYLOAD_HYGIENE_VIOLATION"
	| "MAX_LIFETIME_EXCEEDED"
	| "BEARER_PARSE_FAILED";

/** The codes that are about one claim, and so always name it. */
export type JWTClaimErrorCode =
	| "JWT_CLAIM_VALIDATION_FAILED"
	| "MISSING_CLAIM"
	| "PAYLOAD_HYGIENE_VIOLATION";

export class JWTError extends Error {
	readonly code: JWTErrorCode;
	/** Name of the claim involved (never its value). Set for the claim codes only. */
	declare readonly claim?: string;

	constructor(
		code: JWTClaimErrorCode,
		message: string,
		options: { claim: string; cause?: unknown }
	);
	constructor(
		code: Exclude<JWTErrorCode, JWTClaimErrorCode>,
		message: string,
		options?: { cause?: unknown }
	);
	constructor(code: JWTErrorCode, message: string, options?: { claim?: string; cause?: unknown }) {
		super(
			`lacewing: ${message}`,
			options !== undefined && "cause" in options ? { cause: options.cause } : undefined
		);
		this.name = "JWTError";
		this.code = code;
		if (options?.claim !== undefined) this.claim = options.claim;
	}
}
