/**
 * Claims validation engine (RFC 8725 §3.8/§3.9).
 *
 * One pass, fail-fast, all-or-nothing. Rejection messages never echo
 * untrusted token content (log-injection hygiene, §3.10) - errors name
 * the claim, not its value.
 */

import { JWTError } from "../util/errors.js";
import type { ClaimsPolicy } from "../types.js";

const MAX_STRING_CLAIM_LENGTH = 1024;

function requireString(payload: Record<string, unknown>, claim: string): string {
	const value = payload[claim];
	if (value === undefined) {
		throw new JWTError("MISSING_CLAIM", `Required claim "${claim}" is missing`, { claim });
	}
	if (typeof value !== "string" || value.length === 0) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			`Claim "${claim}" must be a non-empty string`,
			{ claim }
		);
	}
	if (value.length > MAX_STRING_CLAIM_LENGTH) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			`Claim "${claim}" exceeds the length cap`,
			{ claim }
		);
	}
	return value;
}

function requireNumber(payload: Record<string, unknown>, claim: string): number {
	const value = payload[claim];
	if (value === undefined) {
		throw new JWTError("MISSING_CLAIM", `Required claim "${claim}" is missing`, { claim });
	}
	if (typeof value !== "number" || !Number.isFinite(value)) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			`Claim "${claim}" must be a finite number`,
			{ claim }
		);
	}
	return value;
}

function audienceMatches(aud: unknown, expected: string): boolean {
	if (typeof aud === "string") {
		return aud === expected;
	}
	if (Array.isArray(aud)) {
		return aud.some((entry) => typeof entry === "string" && entry === expected);
	}
	return false;
}

export type { ValidateClaim } from "../types.js";

/**
 * Validate a decoded payload against a profile. Only called after the
 * signature has been verified. `nowSeconds` is injectable for tests.
 */
export async function validateClaims(
	payload: Record<string, unknown>,
	profile: ClaimsPolicy,
	nowSeconds: number = Math.floor(Date.now() / 1000)
): Promise<void> {
	const skew = profile.maxClockSkew;

	// iss - must exactly match the trusted issuer (§3.8).
	const iss = requireString(payload, "iss");
	if (iss !== profile.iss) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			"Token issuer is not trusted by this profile",
			{ claim: "iss" }
		);
	}

	// aud - the profile's audience must be present (§3.9).
	if (payload.aud === undefined) {
		throw new JWTError("MISSING_CLAIM", "Required claim \"aud\" is missing", { claim: "aud" });
	}
	if (!audienceMatches(payload.aud, profile.aud)) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			"Token audience does not include this profile's audience",
			{ claim: "aud" }
		);
	}

	// exp - required, with bounded clock skew.
	const exp = requireNumber(payload, "exp");
	if (nowSeconds >= exp + skew) {
		throw new JWTError("JWT_EXPIRED", "Token has expired");
	}

	// iat - required, may not be in the future.
	const iat = requireNumber(payload, "iat");
	if (iat > nowSeconds + skew) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			"Token issued-at time is in the future",
			{ claim: "iat" }
		);
	}

	// maxTokenAge - enforced independently of exp (LW-life.2). This bounds how
	// long after issuance a token stays usable *here*, whatever `exp` claims:
	// a token minted with a decade-long exp is still refused once it is older
	// than maxTokenAge. It does not reject such a token on sight - see
	// maxTokenLifetime for that.
	if (nowSeconds - iat > profile.maxTokenAge + skew) {
		throw new JWTError("JWT_EXPIRED", "Token exceeds the profile's maximum age");
	}

	// maxTokenLifetime - optional, and about the token's *declared* span
	// (exp - iat) rather than its current age. An absurd declared lifetime is
	// a misissuance signal worth refusing outright rather than silently
	// tolerating for the length of the age window.
	if (profile.maxTokenLifetime !== undefined && exp - iat > profile.maxTokenLifetime) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			"Token's declared lifetime (exp - iat) exceeds the profile's maximum",
			{ claim: "exp" }
		);
	}

	// nbf - optional, but honored when present.
	if (payload.nbf !== undefined) {
		const nbf = requireNumber(payload, "nbf");
		if (nbf > nowSeconds + skew) {
			throw new JWTError(
				"JWT_CLAIM_VALIDATION_FAILED",
				"Token is not yet valid",
				{ claim: "nbf" }
			);
		}
	}

	// jti - optional per RFC 7519, but bounded when present.
	if (payload.jti !== undefined) {
		requireString(payload, "jti");
	}

	// sub - validated when the profile pins one (§3.8.2).
	if (payload.sub !== undefined) {
		requireString(payload, "sub");
	}
	if (profile.subject !== undefined) {
		const sub = requireString(payload, "sub");
		if (sub !== profile.subject) {
			throw new JWTError(
				"JWT_CLAIM_VALIDATION_FAILED",
				"Token subject does not match this profile",
				{ claim: "sub" }
			);
		}
	}

	// Custom claim validators - run last, after all standard checks.
	if (profile.claimValidators !== undefined) {
		for (const [claim, validate] of Object.entries(profile.claimValidators)) {
			try {
				await validate(payload[claim], payload);
			} catch (cause) {
				if (cause instanceof JWTError && (cause.code === "JWT_CLAIM_VALIDATION_FAILED" || cause.code === "MISSING_CLAIM")) {
					throw cause;
				}
				throw new JWTError(
					"JWT_CLAIM_VALIDATION_FAILED",
					`Custom validation for claim "${claim}" failed`,
					{ claim, cause }
				);
			}
		}
	}
}
