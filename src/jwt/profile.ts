/**
 * Verification profiles - the RFC 8725 §3.12 mechanism and the library's
 * signature API.
 *
 * A profile is the *only* argument shape `jwtVerify` accepts, which makes
 * `typ`, issuer, audience, and the algorithm allowlist structurally
 * mandatory. The key source belongs to the profile, which belongs to an
 * issuer - that is the §3.8 issuer-to-key binding. Only `defineProfile`
 * mints one: a hand-built or spread copy skips every check below and is
 * refused by `jwtVerify`.
 */

import { resolveAlgorithm, type AlgorithmInfo } from "../lib/algorithms.js";
import { mintedKind } from "../lib/minted.js";
import { createLocalJWKSet } from "../jwks/local.js";
import { createRemoteJWKSet } from "../jwks/remote.js";
import { isVouchedKeySource } from "../jwks/trusted.js";
import { buildPolicy, type PolicyOptions } from "./policy.js";
import {
	isLacewingKey,
	type ExpectedJwtProfile,
	type KeySource,
	type LacewingKey,
	type RemoteJWKS,
	type StaticJWKS,
	type TokenPolicy,
} from "../types.js";

export interface ProfileOptions extends PolicyOptions {
	/**
	 * Explicit algorithm allowlist - the token header never decides (§3.1).
	 * Names from the default set (`"EdDSA"`, `"ES256"`, `"PS256"`, ...), or
	 * legacy descriptors from `lacewing/legacy/rsa` such as `LEGACY_RS256`;
	 * `"RS256"` as a bare string is refused.
	 */
	algorithms: readonly (string | AlgorithmInfo)[];
	/** Key source: a JWKS (static or remote config), a Lacewing-built (or `unsafeCustomKeySource`) KeySource, or a single key. */
	keys: KeySource | LacewingKey | StaticJWKS | RemoteJWKS;
}

const profiles = mintedKind<ExpectedJwtProfile>();

/** True only for profiles `defineProfile` built. */
export function isProfile(value: unknown): value is ExpectedJwtProfile {
	return profiles.is(value);
}

function normalizeKeys(
	keys: ProfileOptions["keys"],
	algorithms: readonly AlgorithmInfo[],
	policy: TokenPolicy
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
			if (!isVouchedKeySource(keys)) {
				throw new TypeError(
					"Custom key sources must be wrapped in unsafeCustomKeySource() - or use createLocalJWKSet/createRemoteJWKSet"
				);
			}
			return keys;
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
				// The inline config shares the profile's reporting and clock.
				...(policy.onEvent === undefined ? {} : { onEvent: policy.onEvent }),
				now: policy.now,
			});
		}
	}
	throw new TypeError(
		"Profile keys must be a JWKS document, a { jwksUri } config, a KeySource, or an imported key"
	);
}

/** Build the security boundary that `jwtVerify` enforces. */
export function defineProfile(options: ProfileOptions): ExpectedJwtProfile {
	const policy = buildPolicy(options, "Profile");
	if (!Array.isArray(options.algorithms) || options.algorithms.length === 0) {
		throw new TypeError("Profile requires a non-empty algorithm allowlist");
	}
	const alg = Object.freeze(options.algorithms.map((choice) => resolveAlgorithm(choice)));
	return profiles.mint({ ...policy, alg, keys: normalizeKeys(options.keys, alg, policy) });
}
