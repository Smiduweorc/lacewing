/**
 * Header parsing and hardening (RFC 8725 §3.1/§3.2/§3.6/§3.10/§3.11).
 *
 * Header values are untrusted input: `kid` is length-capped and
 * character-whitelisted before any lookup, `jku`/`x5u`/`jwk`/`x5c` are
 * never honored, `zip` is rejected outright, and `crit` is rejected
 * because Lacewing supports no header extensions.
 */

import { AlgorithmNotAllowed, JWTClaimValidationFailed, JWTInvalid } from "../util/errors.js";
import { getAlgorithmProperties } from "./algorithms.js";
import { SetAlg, type ExpectedJwtProfile, type JwtHeader } from "../types.js";

const KID_MAX_LENGTH = 128;
const KID_CHARSET = /^[A-Za-z0-9._:-]+$/;

// Never followed / never honored (§3.6, §3.10) plus `crit`, since we
// implement no extensions and RFC 7515 requires rejecting unknown ones.
const FORBIDDEN_PARAMS = ["jku", "x5u", "jwk", "x5c", "x5t", "zip", "crit"] as const;

/**
 * Sanitize an untrusted `kid` before it is used for key lookup (§3.10):
 * bounded length, conservative charset.
 */
export function sanitizeKid(kid: unknown): string {
	if (
		typeof kid !== "string" ||
		kid.length === 0 ||
		kid.length > KID_MAX_LENGTH ||
		!KID_CHARSET.test(kid)
	) {
		throw new JWTInvalid("Token key identifier failed sanitization");
	}
	return kid;
}

/** Compare `typ` values per RFC 9068: optional media-type prefix, case-insensitive. */
export function normalizeTyp(typ: string): string {
	const lower = typ.toLowerCase();
	return lower.startsWith("application/") ? lower.slice("application/".length) : lower;
}

/** Validate a decoded (but unverified) header object against a profile. */
export function validateHeader(raw: unknown, profile: ExpectedJwtProfile): JwtHeader {
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
		throw new JWTInvalid("Token header is not a JSON object");
	}
	const header = raw as Record<string, unknown>;

	for (const param of FORBIDDEN_PARAMS) {
		if (param in header) {
			throw new JWTInvalid(`Token header parameter "${param}" is not supported`);
		}
	}

	const alg = header.alg;
	if (typeof alg !== "string" || alg.toLowerCase() === "none") {
		throw new AlgorithmNotAllowed("Algorithm 'none' (or a missing alg) is not allowed");
	}
	if (!profile.alg.some((allowed) => (allowed as string) === alg)) {
		throw new AlgorithmNotAllowed("Token algorithm is not in this profile's allowlist");
	}
	// Defense in depth: the allowlist is registry-validated at profile
	// creation, but re-check in case the profile object was hand-built.
	getAlgorithmProperties(alg);

	const typ = header.typ;
	if (typeof typ !== "string" || typ.length === 0) {
		throw new JWTInvalid("Token header is missing a typ (explicit typing is mandatory)");
	}
	if (normalizeTyp(typ) !== normalizeTyp(profile.typ)) {
		throw new JWTClaimValidationFailed("typ", "Unexpected token type for this profile");
	}

	const result: JwtHeader = { alg: SetAlg(alg), typ };
	if (header.kid !== undefined) {
		result.kid = sanitizeKid(header.kid);
	}
	if (header.cty !== undefined) {
		if (typeof header.cty !== "string") {
			throw new JWTInvalid("Token header cty must be a string");
		}
		result.cty = header.cty;
	}
	return result;
}
