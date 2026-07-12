/**
 * Claims validation engine (RFC 8725 §3.8/§3.9).
 *
 * One pass, fail-fast, all-or-nothing. Rejection messages never echo
 * untrusted token content (log-injection hygiene, §3.10) - errors name
 * the claim, not its value.
 */

import {
	JWTClaimValidationFailed,
	JWTExpired,
	MissingClaim,
} from "../util/errors.js";
import type { ClaimsPolicy } from "../types.js";

const MAX_STRING_CLAIM_LENGTH = 1024;

function requireString(payload: Record<string, unknown>, claim: string): string {
	const value = payload[claim];
	if (value === undefined) {
		throw new MissingClaim(claim);
	}
	if (typeof value !== "string" || value.length === 0) {
		throw new JWTClaimValidationFailed(claim, `Claim "${claim}" must be a non-empty string`);
	}
	if (value.length > MAX_STRING_CLAIM_LENGTH) {
		throw new JWTClaimValidationFailed(claim, `Claim "${claim}" exceeds the length cap`);
	}
	return value;
}

function requireNumber(payload: Record<string, unknown>, claim: string): number {
	const value = payload[claim];
	if (value === undefined) {
		throw new MissingClaim(claim);
	}
	if (typeof value !== "number" || !Number.isFinite(value)) {
		throw new JWTClaimValidationFailed(claim, `Claim "${claim}" must be a finite number`);
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
		throw new JWTClaimValidationFailed("iss", "Token issuer is not trusted by this profile");
	}

	// aud - the profile's audience must be present (§3.9).
	if (payload.aud === undefined) {
		throw new MissingClaim("aud");
	}
	if (!audienceMatches(payload.aud, profile.aud)) {
		throw new JWTClaimValidationFailed("aud", "Token audience does not include this profile's audience");
	}

	// exp - required, with bounded clock skew.
	const exp = requireNumber(payload, "exp");
	if (nowSeconds >= exp + skew) {
		throw new JWTExpired("Token has expired");
	}

	// iat - required, may not be in the future.
	const iat = requireNumber(payload, "iat");
	if (iat > nowSeconds + skew) {
		throw new JWTClaimValidationFailed("iat", "Token issued-at time is in the future");
	}

	// maxTokenAge - enforced independently of exp (LW-life.2), so a
	// compromised signer can't mint decade-long tokens we accept.
	if (nowSeconds - iat > profile.maxTokenAge + skew) {
		throw new JWTExpired("Token exceeds the profile's maximum age");
	}

	// nbf - optional, but honored when present.
	if (payload.nbf !== undefined) {
		const nbf = requireNumber(payload, "nbf");
		if (nbf > nowSeconds + skew) {
			throw new JWTClaimValidationFailed("nbf", "Token is not yet valid");
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
			throw new JWTClaimValidationFailed("sub", "Token subject does not match this profile");
		}
	}

	// Custom claim validators - run last, after all standard checks.
	if (profile.claimValidators !== undefined) {
		for (const [claim, validate] of Object.entries(profile.claimValidators)) {
			try {
				await validate(payload[claim], payload);
			} catch (cause) {
				if (cause instanceof JWTClaimValidationFailed || cause instanceof MissingClaim) {
					throw cause;
				}
				throw new JWTClaimValidationFailed(
					claim,
					`Custom validation for claim "${claim}" failed`,
					{ cause }
				);
			}
		}
	}
}
