/**
 * Static (local) JWK Sets.
 *
 * Selection is registry-driven: entries whose `kty`/`alg`/`crv` fall
 * outside what the token's (already allowlisted) algorithm requires are
 * never candidates. `kid` values arriving here have already been
 * sanitized by header validation (§3.10).
 */

import { importJWK } from "jose";
import {
	EntropyCheckFailed,
	JWKSNoMatchingKey,
	KeyImportFailed,
} from "../util/errors.js";
import { getAlgorithmProperties, isValidAlgorithm } from "../lib/algorithms.js";
import { decodeBase64url } from "../lib/base64url.js";
import { validateHMACSecret } from "../lib/entropy.js";
import type {
	JwtHeader,
	KeySource,
	ResolvedVerificationKey,
	StaticJWK,
	StaticJWKS,
} from "../types.js";

function isCandidate(jwk: StaticJWK, header: JwtHeader): boolean {
	const info = getAlgorithmProperties(header.alg);
	if (jwk.kty !== info.kty) return false;
	if (jwk.use !== undefined && jwk.use !== "sig") return false;
	if (jwk.alg !== undefined && jwk.alg !== (header.alg as string)) return false;
	if (info.crv !== undefined && jwk.crv !== info.crv) return false;
	if (header.kid !== undefined && jwk.kid !== header.kid) return false;
	return true;
}

/** Shared selection + import used by both local and remote sets. */
export async function resolveFromJwks(
	keys: readonly StaticJWK[],
	header: JwtHeader
): Promise<ResolvedVerificationKey> {
	const candidates = keys.filter((jwk) => isCandidate(jwk, header));
	if (candidates.length === 0) {
		throw new JWKSNoMatchingKey("No key in the JWKS matches this token");
	}
	if (candidates.length > 1) {
		throw new JWKSNoMatchingKey(
			"Multiple keys in the JWKS match this token - issue tokens with a kid"
		);
	}
	const jwk = candidates[0] as StaticJWK;
	try {
		if (jwk.kty === "oct") {
			if (typeof jwk.k !== "string") {
				throw new KeyImportFailed("oct JWK is missing its key material");
			}
			const secret = decodeBase64url(jwk.k);
			validateHMACSecret(secret, header.alg);
			return { alg: header.alg, key: secret };
		}
		const key = await importJWK(
			jwk as Parameters<typeof importJWK>[0],
			header.alg
		);
		return { alg: header.alg, key };
	} catch (cause) {
		if (cause instanceof KeyImportFailed || cause instanceof EntropyCheckFailed) {
			throw cause;
		}
		throw new KeyImportFailed("JWKS key could not be imported", { cause });
	}
}

/** Validate the developer-supplied JWKS document shape (config error -> TypeError). */
export function validateJwksShape(jwks: unknown): StaticJWK[] {
	if (
		typeof jwks !== "object" ||
		jwks === null ||
		!Array.isArray((jwks as StaticJWKS).keys)
	) {
		throw new TypeError("A JWKS must be an object with a keys array");
	}
	const keys = (jwks as StaticJWKS).keys;
	if (keys.length > 1000) {
		throw new TypeError("JWKS has an unreasonable number of keys");
	}
	// Entries outside the registry are dropped, not fatal: real-world JWKS
	// documents routinely carry keys for algorithms we refuse to speak.
	return keys.filter(
		(jwk) =>
			typeof jwk === "object" &&
			jwk !== null &&
			typeof jwk.kty === "string" &&
			(jwk.alg === undefined ||
				(typeof jwk.alg === "string" && isValidAlgorithm(jwk.alg)))
	);
}

/** Create a {@link KeySource} backed by a static JWKS document. */
export function createLocalJWKSet(jwks: StaticJWKS): KeySource {
	const keys = validateJwksShape(jwks);
	return {
		getVerificationKey(header: JwtHeader): Promise<ResolvedVerificationKey> {
			return resolveFromJwks(keys, header);
		},
	};
}
