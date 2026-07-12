/**
 * Decryption profiles - the JWE analogue of `defineProfile`. A profile is the
 * only argument shape `jwtDecrypt` accepts, which makes `typ`, issuer,
 * audience, the two algorithm allowlists, and the decrypting key structurally
 * mandatory. The key belongs to the profile, which belongs to an issuer.
 */

import { parseDuration } from "../lib/duration.js";
import {
	toValidContentEncryptionAlg,
	toValidKeyManagementAlg,
} from "../lib/jwe_algorithms.js";
import {
	isLacewingEncryptionKey,
	toSeconds,
	type ExpectedDecryptionProfile,
	type LacewingEncryptionKey,
	type RevocationStore,
	type ValidateClaim,
} from "../types.js";

const DEFAULT_CLOCK_SKEW_SECONDS = 5;
const MAX_CLOCK_SKEW_SECONDS = 120;

export interface DecryptionProfileOptions {
	/** Expected token type, e.g. `"at+jwt"`. */
	typ: string;
	/** The one issuer this profile trusts. */
	issuer: string;
	/** The audience value that must appear in the token. */
	audience: string;
	/** Explicit key-management (`alg`) allowlist - the header never decides. */
	keyManagementAlgorithms: readonly string[];
	/** Explicit content-encryption (`enc`) allowlist. */
	contentEncryptionAlgorithms: readonly string[];
	/** The private/secret key that decrypts (bound to one key-management alg). */
	key: LacewingEncryptionKey;
	/** Maximum accepted token age, independent of `exp`. */
	maxTokenAge: number | string;
	/** Allowed clock skew, default 5s, capped at 120s. */
	maxClockSkew?: number | string;
	revocation?: RevocationStore;
	claimValidators?: Record<string, ValidateClaim>;
	subject?: string;
	unsafeFailOpenOnRevocationError?: boolean;
}

function requireNonEmptyString(value: unknown, field: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new TypeError(`Decryption profile "${field}" must be a non-empty string`);
	}
	return value;
}

/** Build the security boundary that `jwtDecrypt` enforces. */
export function defineDecryptionProfile(options: DecryptionProfileOptions): ExpectedDecryptionProfile {
	const typ = requireNonEmptyString(options.typ, "typ");
	const iss = requireNonEmptyString(options.issuer, "issuer");
	const aud = requireNonEmptyString(options.audience, "audience");

	if (!Array.isArray(options.keyManagementAlgorithms) || options.keyManagementAlgorithms.length === 0) {
		throw new TypeError("Decryption profile requires a non-empty keyManagementAlgorithms allowlist");
	}
	if (!Array.isArray(options.contentEncryptionAlgorithms) || options.contentEncryptionAlgorithms.length === 0) {
		throw new TypeError("Decryption profile requires a non-empty contentEncryptionAlgorithms allowlist");
	}
	const keyManagementAlgorithms = Object.freeze(options.keyManagementAlgorithms.map(toValidKeyManagementAlg));
	const contentEncryptionAlgorithms = Object.freeze(options.contentEncryptionAlgorithms.map(toValidContentEncryptionAlg));

	if (!isLacewingEncryptionKey(options.key)) {
		throw new TypeError("Decryption profile key must be imported through importEncryptionKey()/generate*");
	}
	if (options.key.keyType === "public") {
		throw new TypeError("Decryption needs the private/secret key, not the public key");
	}
	if (!keyManagementAlgorithms.some((allowed) => (allowed as string) === options.key.algorithm)) {
		throw new TypeError("The profile key's algorithm is not in the keyManagementAlgorithms allowlist");
	}

	const maxTokenAge = parseDuration(options.maxTokenAge);
	if (maxTokenAge < 1) throw new TypeError("Decryption profile maxTokenAge must be at least one second");
	const maxClockSkew = parseDuration(options.maxClockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS);
	if (maxClockSkew > MAX_CLOCK_SKEW_SECONDS) {
		throw new TypeError(`Decryption profile maxClockSkew is capped at ${MAX_CLOCK_SKEW_SECONDS} seconds`);
	}
	if (options.revocation !== undefined && typeof options.revocation.isRevoked !== "function") {
		throw new TypeError("Decryption profile revocation store must implement isRevoked()");
	}
	if (options.claimValidators !== undefined) {
		for (const [claim, validator] of Object.entries(options.claimValidators)) {
			if (typeof validator !== "function") throw new TypeError(`Claim validator for "${claim}" must be a function`);
		}
	}
	if (options.subject !== undefined) requireNonEmptyString(options.subject, "subject");

	const profile: ExpectedDecryptionProfile = {
		typ,
		iss,
		aud,
		keyManagementAlgorithms,
		contentEncryptionAlgorithms,
		key: options.key,
		maxTokenAge: toSeconds(maxTokenAge),
		maxClockSkew: toSeconds(maxClockSkew),
	};
	if (options.revocation !== undefined) profile.revocation = options.revocation;
	if (options.claimValidators !== undefined) profile.claimValidators = { ...options.claimValidators };
	if (options.subject !== undefined) profile.subject = options.subject;
	if (options.unsafeFailOpenOnRevocationError === true) profile.unsafeFailOpenOnRevocationError = true;
	return Object.freeze(profile);
}
