/**
 * Typed error hierarchy.
 *
 * Every error carries a machine-readable `code` so operators can branch on
 * failure modes, while messages stay generic: security-relevant rejections
 * never echo untrusted token content (no oracle for attackers, no log
 * injection - RFC 8725 §3.10 hygiene).
 */

export abstract class JWTError extends Error {
	abstract readonly code: string;

	constructor(message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.name = new.target.name;
	}
}

/** Token structure or signature is invalid. */
export class JWTInvalid extends JWTError {
	readonly code = "JWT_INVALID";
}

/** Token is past `exp`, or older than the profile's `maxTokenAge`. */
export class JWTExpired extends JWTError {
	readonly code = "JWT_EXPIRED";
}

/** A claim is present but does not satisfy the profile's rules. */
export class JWTClaimValidationFailed extends JWTError {
	readonly code = "JWT_CLAIM_VALIDATION_FAILED";
	/** Name of the offending claim (never its value). */
	readonly claim: string;

	constructor(claim: string, message: string, options?: { cause?: unknown }) {
		super(message, options);
		this.claim = claim;
	}
}

/** A claim required by the profile or by Lacewing policy is absent. */
export class MissingClaim extends JWTError {
	readonly code = "MISSING_CLAIM";
	readonly claim: string;

	constructor(claim: string, message?: string) {
		super(message ?? `Required claim "${claim}" is missing`);
		this.claim = claim;
	}
}

/** Algorithm is not in the registry / profile allowlist. */
export class AlgorithmNotAllowed extends JWTError {
	readonly code = "ALGORITHM_NOT_ALLOWED";
}

/** Key material could not be imported. */
export class KeyImportFailed extends JWTError {
	readonly code = "KEY_IMPORT_FAILED";
}

/** Key does not match the algorithm it is being used with. */
export class KeyTypeMismatch extends JWTError {
	readonly code = "KEY_TYPE_MISMATCH";
}

/** Key material could not be exported. */
export class KeyExportFailed extends JWTError {
	readonly code = "KEY_EXPORT_FAILED";
}

/** HMAC secret failed the strength checks (RFC 8725 §3.5). */
export class EntropyCheckFailed extends JWTError {
	readonly code = "ENTROPY_CHECK_FAILED";
}

/** Remote JWKS could not be fetched or parsed. */
export class JWKSFetchFailed extends JWTError {
	readonly code = "JWKS_FETCH_FAILED";
}

/** No key in the JWKS matches the token's header. */
export class JWKSNoMatchingKey extends JWTError {
	readonly code = "JWKS_NO_MATCHING_KEY";
}

/** Token is valid but its `jti` has been revoked (LW-rev.2). */
export class JWTRevoked extends JWTError {
	readonly code = "JWT_REVOKED";
}

/** The revocation store errored; Lacewing fails closed (LW-rev.4). */
export class RevocationCheckFailed extends JWTError {
	readonly code = "REVOCATION_CHECK_FAILED";
}

/** Sign-time payload hygiene scanner found sensitive data (LW-payload). */
export class PayloadHygieneViolation extends JWTError {
	readonly code = "PAYLOAD_HYGIENE_VIOLATION";
	/** Name of the offending claim (never its value). */
	readonly claim: string;

	constructor(claim: string, message: string) {
		super(message);
		this.claim = claim;
	}
}

/** Requested token lifetime exceeds the configured cap (LW-life.1). */
export class MaxLifetimeExceeded extends JWTError {
	readonly code = "MAX_LIFETIME_EXCEEDED";
}

/** `Authorization` header failed strict RFC 6750 parsing (LW-http.2). */
export class BearerParseFailed extends JWTError {
	readonly code = "BEARER_PARSE_FAILED";
}
