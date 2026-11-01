/**
 * Verification profiles - the RFC 8725 §3.12 mechanism and the library's
 * signature API.
 *
 * A profile is the *only* argument shape `jwtVerify` accepts, which makes
 * `typ`, issuer, audience, and the algorithm allowlist structurally
 * mandatory. The key source belongs to the profile, which belongs to an
 * issuer - that is the §3.8 issuer-to-key binding.
 */

import { resolveAlgorithm, type AlgorithmInfo } from "../lib/algorithms.js";
import { parseDuration } from "../lib/duration.js";
import { createLocalJWKSet } from "../jwks/local.js";
import { createRemoteJWKSet } from "../jwks/remote.js";
import { isVouchedKeySource } from "../jwks/trusted.js";
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
const MAX_CLOCK_SKEW_SECONDS = 30;
const UNSAFE_MAX_CLOCK_SKEW_SECONDS = 120;
const MAX_TOKEN_AGE_SECONDS = 30 * 24 * 60 * 60;

export interface ProfileOptions {
	/** Expected token type, e.g. `"at+jwt"` (§3.11). */
	typ: string;
	/** The one issuer this profile trusts (§3.8). */
	issuer: string;
	/** The audience value that must appear in the token (§3.9). */
	audience: string;
	/**
	 * Explicit algorithm allowlist - the token header never decides (§3.1).
	 * Names from the default set (`"EdDSA"`, `"ES256"`, `"PS256"`, ...), or
	 * legacy descriptors from `lacewing/legacy/rsa` such as `LEGACY_RS256`;
	 * `"RS256"` as a bare string is refused.
	 */
	algorithms: readonly (string | AlgorithmInfo)[];
	/** Key source: a JWKS (static or remote config), a Lacewing-built (or `unsafeCustomKeySource`) KeySource, or a single key. */
	keys: KeySource | LacewingKey | StaticJWKS | RemoteJWKS;
	/** Maximum accepted token age (`now - iat`), independent of `exp`. */
	maxTokenAge: number | string;
	/** Ugly on purpose: allow `maxTokenAge` above 30 days. */
	unsafeAllowLongTokenAge?: boolean;
	/**
	 * Optional cap on the token's *declared* lifetime (`exp - iat`). Where
	 * `maxTokenAge` bounds how long a token stays usable, this refuses a token
	 * whose issuer claimed an implausible span at all - a misissuance signal.
	 */
	maxTokenLifetime?: number | string;
	/** Allowed clock skew, default 5s, capped at 30s (120s with `unsafeAllowLargeClockSkew`). */
	maxClockSkew?: number | string;
	/** Ugly on purpose: allow `maxClockSkew` above 30s, up to 120s. */
	unsafeAllowLargeClockSkew?: boolean;
	/** Optional revocation store - its absence is a visible choice. */
	revocation?: RevocationStore;
	/**
	 * Ugly on purpose: extra per-claim predicates, run after all standard
	 * checks. Arbitrary code in the accept path - you own its correctness.
	 */
	unsafeClaimValidators?: Record<string, ValidateClaim>;
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
	algorithms: readonly AlgorithmInfo[]
): KeySource | LacewingKey {
	if (isLacewingKey(keys)) {
		if (keys.keyType === "private") {
			throw new TypeError(
				"Profiles verify tokens - pass the public key, not the private key"
			);
		}
		if (!algorithms.some((info) => info.name === (keys.algorithm as string))) {
			throw new TypeError(
				"The profile key's algorithm is not in the profile's allowlist"
			);
		}
		return keys;
	}
	if (typeof keys === "object" && keys !== null) {
		if (typeof (keys as KeySource).getVerificationKey === "function") {
			if (!isVouchedKeySource(keys as KeySource)) {
				throw new TypeError(
					"Custom key sources must be wrapped in unsafeCustomKeySource() - or use createLocalJWKSet/createRemoteJWKSet"
				);
			}
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
				staleWhileErrorSeconds: remote.staleWhileErrorSeconds,
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
	const alg = Object.freeze(options.algorithms.map((choice) => resolveAlgorithm(choice)));

	const maxTokenAge = parseDuration(options.maxTokenAge);
	if (maxTokenAge < 1) {
		throw new TypeError("Profile maxTokenAge must be at least one second");
	}
	const maxClockSkew = parseDuration(options.maxClockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS);
	if (maxTokenAge > MAX_TOKEN_AGE_SECONDS && options.unsafeAllowLongTokenAge !== true) {
		throw new TypeError(
			"Profile maxTokenAge is capped at 30 days - set unsafeAllowLongTokenAge to go beyond"
		);
	}
	const skewCap =
		options.unsafeAllowLargeClockSkew === true ? UNSAFE_MAX_CLOCK_SKEW_SECONDS : MAX_CLOCK_SKEW_SECONDS;
	if (maxClockSkew > skewCap) {
		throw new TypeError(
			skewCap === MAX_CLOCK_SKEW_SECONDS
				? `Profile maxClockSkew is capped at ${MAX_CLOCK_SKEW_SECONDS} seconds - set unsafeAllowLargeClockSkew to allow up to ${UNSAFE_MAX_CLOCK_SKEW_SECONDS}`
				: `Profile maxClockSkew is capped at ${UNSAFE_MAX_CLOCK_SKEW_SECONDS} seconds`
		);
	}
	const maxTokenLifetime =
		options.maxTokenLifetime === undefined ? undefined : parseDuration(options.maxTokenLifetime);
	if (maxTokenLifetime !== undefined && maxTokenLifetime < 1) {
		throw new TypeError("Profile maxTokenLifetime must be at least one second");
	}

	if (options.revocation !== undefined && typeof options.revocation.isRevoked !== "function") {
		throw new TypeError("Profile revocation store must implement isRevoked()");
	}
	if (options.unsafeClaimValidators !== undefined) {
		for (const [claim, validator] of Object.entries(options.unsafeClaimValidators)) {
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
		keys: normalizeKeys(options.keys, alg),
		maxTokenAge: toSeconds(maxTokenAge),
		maxClockSkew: toSeconds(maxClockSkew),
	};
	if (maxTokenLifetime !== undefined) profile.maxTokenLifetime = toSeconds(maxTokenLifetime);
	if (options.revocation !== undefined) profile.revocation = options.revocation;
	if (options.unsafeClaimValidators !== undefined) {
		profile.claimValidators = { ...options.unsafeClaimValidators };
	}
	if (options.subject !== undefined) profile.subject = options.subject;
	if (options.unsafeFailOpenOnRevocationError === true) {
		profile.unsafeFailOpenOnRevocationError = true;
	}
	return Object.freeze(profile);
}
