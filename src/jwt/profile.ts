/**
 * Verification profiles - the RFC 8725 §3.12 mechanism and the library's
 * signature API.
 *
 * A profile is the *only* argument shape `jwtVerify` accepts, which makes
 * `typ`, issuer, audience, and the algorithm allowlist structurally
 * mandatory. The key source belongs to the profile, which belongs to an
 * issuer - that is the §3.8 issuer-to-key binding.
 */

import { toValidAlg } from "../lib/algorithms.js";
import { parseDuration } from "../lib/duration.js";
import { createLocalJWKSet } from "../jwks/local.js";
import { createRemoteJWKSet } from "../jwks/remote.js";
import {
	isLacewingKey,
	toSeconds,
	type ExpectedJwtProfile,
	type KeySource,
	type LacewingKey,
	type RemoteJWKS,
	type RevocationStore,
	type StaticJWKS,
	type ValidateClaim,
} from "../types.js";

const DEFAULT_CLOCK_SKEW_SECONDS = 5;
const MAX_CLOCK_SKEW_SECONDS = 120;

export interface ProfileOptions {
	/** Expected token type, e.g. `"at+jwt"` (§3.11). */
	typ: string;
	/** The one issuer this profile trusts (§3.8). */
	issuer: string;
	/** The audience value that must appear in the token (§3.9). */
	audience: string;
	/** Explicit algorithm allowlist - the token header never decides (§3.1). */
	algorithms: readonly string[];
	/** Key source: a JWKS (static or remote config), a KeySource, or a single key. */
	keys: KeySource | LacewingKey | StaticJWKS | RemoteJWKS;
	/** Maximum accepted token age, independent of `exp`. */
	maxTokenAge: number | string;
	/** Allowed clock skew, default 5s, capped at 120s. */
	maxClockSkew?: number | string;
	/** Optional revocation store - its absence is a visible choice. */
	revocation?: RevocationStore;
	/** Extra per-claim predicates, run after all standard checks. */
	claimValidators?: Record<string, ValidateClaim>;
	/** Pin the expected `sub` (§3.8.2). */
	subject?: string;
	/** Ugly on purpose: accept tokens when the revocation store errors (LW-rev.4). */
	unsafeFailOpenOnRevocationError?: boolean;
}

function requireNonEmptyString(value: unknown, field: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new TypeError(`Profile "${field}" must be a non-empty string`);
	}
	return value;
}

function normalizeKeys(
	keys: ProfileOptions["keys"],
	algorithms: readonly string[]
): KeySource | LacewingKey {
	if (isLacewingKey(keys)) {
		if (keys.keyType === "private") {
			throw new TypeError(
				"Profiles verify tokens - pass the public key, not the private key"
			);
		}
		if (!algorithms.includes(keys.algorithm)) {
			throw new TypeError(
				"The profile key's algorithm is not in the profile's allowlist"
			);
		}
		return keys;
	}
	if (typeof keys === "object" && keys !== null) {
		if (typeof (keys as KeySource).getVerificationKey === "function") {
			return keys as KeySource;
		}
		if (Array.isArray((keys as StaticJWKS).keys)) {
			return createLocalJWKSet(keys as StaticJWKS);
		}
		if (typeof (keys as RemoteJWKS).jwksUri === "string") {
			const remote = keys as RemoteJWKS;
			return createRemoteJWKSet(remote.jwksUri, {
				cacheTtlSeconds: remote.cacheTtlSeconds,
				cooldownSeconds: remote.cooldownSeconds,
				timeoutMs: remote.timeoutMs,
			});
		}
	}
	throw new TypeError(
		"Profile keys must be a JWKS document, a { jwksUri } config, a KeySource, or an imported key"
	);
}

/** Build the security boundary that `jwtVerify` enforces. */
export function defineProfile(options: ProfileOptions): ExpectedJwtProfile {
	const typ = requireNonEmptyString(options.typ, "typ");
	const iss = requireNonEmptyString(options.issuer, "issuer");
	const aud = requireNonEmptyString(options.audience, "audience");

	if (!Array.isArray(options.algorithms) || options.algorithms.length === 0) {
		throw new TypeError("Profile requires a non-empty algorithm allowlist");
	}
	const alg = Object.freeze(options.algorithms.map((name) => toValidAlg(name)));

	const maxTokenAge = parseDuration(options.maxTokenAge);
	if (maxTokenAge < 1) {
		throw new TypeError("Profile maxTokenAge must be at least one second");
	}
	const maxClockSkew = parseDuration(options.maxClockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS);
	if (maxClockSkew > MAX_CLOCK_SKEW_SECONDS) {
		throw new TypeError(`Profile maxClockSkew is capped at ${MAX_CLOCK_SKEW_SECONDS} seconds`);
	}

	if (options.revocation !== undefined && typeof options.revocation.isRevoked !== "function") {
		throw new TypeError("Profile revocation store must implement isRevoked()");
	}
	if (options.claimValidators !== undefined) {
		for (const [claim, validator] of Object.entries(options.claimValidators)) {
			if (typeof validator !== "function") {
				throw new TypeError(`Claim validator for "${claim}" must be a function`);
			}
		}
	}
	if (options.subject !== undefined) {
		requireNonEmptyString(options.subject, "subject");
	}

	const profile: ExpectedJwtProfile = {
		typ,
		iss,
		aud,
		alg,
		keys: normalizeKeys(options.keys, options.algorithms),
		maxTokenAge: toSeconds(maxTokenAge),
		maxClockSkew: toSeconds(maxClockSkew),
	};
	if (options.revocation !== undefined) profile.revocation = options.revocation;
	if (options.claimValidators !== undefined) {
		profile.claimValidators = { ...options.claimValidators };
	}
	if (options.subject !== undefined) profile.subject = options.subject;
	if (options.unsafeFailOpenOnRevocationError === true) {
		profile.unsafeFailOpenOnRevocationError = true;
	}
	return Object.freeze(profile);
}
