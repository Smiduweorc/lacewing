/**
 * Decryption profiles - the JWE analogue of `defineProfile`. A profile is the
 * only argument shape `jwtDecrypt` accepts, which makes `typ`, issuer,
 * audience, the two algorithm allowlists, and the decrypting key structurally
 * mandatory. The key belongs to the profile, which belongs to an issuer. Only
 * `defineDecryptionProfile` mints one; `jwtDecrypt` refuses anything else.
 */

import { mintedKind } from "../lib/minted.js";
import {
	toValidContentEncryptionAlg,
	toValidKeyManagementAlg,
} from "../lib/jwe_algorithms.js";
import { buildPolicy, type PolicyOptions } from "./policy.js";
import {
	isLacewingEncryptionKey,
	type ExpectedDecryptionProfile,
	type LacewingEncryptionKey,
} from "../types.js";

export interface DecryptionProfileOptions extends PolicyOptions {
	/** Explicit key-management (`alg`) allowlist - the header never decides. */
	keyManagementAlgorithms: readonly string[];
	/** Explicit content-encryption (`enc`) allowlist. */
	contentEncryptionAlgorithms: readonly string[];
	/** The private/secret key that decrypts (bound to one key-management alg). */
	key: LacewingEncryptionKey;
}

const decryptionProfiles = mintedKind<ExpectedDecryptionProfile>();

/** True only for profiles `defineDecryptionProfile` built. */
export function isDecryptionProfile(value: unknown): value is ExpectedDecryptionProfile {
	return decryptionProfiles.is(value);
}

/** Build the security boundary that `jwtDecrypt` enforces. */
export function defineDecryptionProfile(options: DecryptionProfileOptions): ExpectedDecryptionProfile {
	const policy = buildPolicy(options, "Decryption profile");

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

	return decryptionProfiles.mint({
		...policy,
		keyManagementAlgorithms,
		contentEncryptionAlgorithms,
		key: options.key,
	});
}
