/**
 * Static (local) JWK Sets.
 *
 * Selection follows the profile's allowlist: entries whose `kty`/`alg`/`crv`
 * fall outside what the token's (already allowlisted) algorithm requires are
 * never candidates. `kid` values arriving here have already been
 * sanitized by header validation (§3.10).
 */

import { importJWK } from "jose";
import { JWTError } from "../util/errors.js";
import { findAlgorithm, isKnownAlgorithmName, type AlgorithmInfo } from "../lib/algorithms.js";
import { decodeBase64url } from "../lib/base64url.js";
import { validateHMACSecret } from "../lib/entropy.js";
import type {
	JwtHeader,
	KeySource,
	ResolvedVerificationKey,
	StaticJWK,
	StaticJWKS,
} from "../types.js";

/**
 * Whether a JWK without an `alg` member could serve more than one of the
 * profile's algorithms. A curve pins EC/OKP keys to one algorithm, but an
 * RSA or `oct` key fits every allowlisted algorithm of its type, and using
 * one key under several algorithms is what §3.1 forbids.
 */
function isUnbound(jwk: StaticJWK, allowed: readonly AlgorithmInfo[]): boolean {
	if (jwk.alg !== undefined) return false;
	const sameFamily = allowed.filter((info) => info.kty === jwk.kty && info.crv === undefined);
	return sameFamily.length > 1;
}

function isCandidate(jwk: StaticJWK, header: JwtHeader, info: AlgorithmInfo): boolean {
	if (jwk.kty !== info.kty) return false;
	if (jwk.use !== undefined && jwk.use !== "sig") return false;
	if (jwk.alg !== undefined && jwk.alg !== (header.alg as string)) return false;
	if (info.crv !== undefined && jwk.crv !== info.crv) return false;
	if (header.kid !== undefined && jwk.kid !== header.kid) return false;
	return true;
}

export interface ResolveFromJwksOptions {
	/**
	 * Whether symmetric (`oct`) entries may be used. False for remote sets: a
	 * JWKS endpoint is public, so a secret published there is a secret every
	 * reader can *mint* with, not just verify with.
	 */
	allowSymmetric?: boolean;
}

/** Shared selection + import used by both local and remote sets. */
export async function resolveFromJwks(
	keys: readonly StaticJWK[],
	header: JwtHeader,
	allowed: readonly AlgorithmInfo[],
	options: ResolveFromJwksOptions = {}
): Promise<ResolvedVerificationKey> {
	const allowSymmetric = options.allowSymmetric ?? true;
	const info = findAlgorithm(header.alg, allowed);
	const matching = keys.filter(
		(jwk) => isCandidate(jwk, header, info) && (allowSymmetric || jwk.kty !== "oct")
	);
	const candidates = matching.filter((jwk) => !isUnbound(jwk, allowed));
	if (candidates.length === 0) {
		throw new JWTError(
			"JWKS_NO_MATCHING_KEY",
			matching.length === 0
				? "No key in the JWKS matches this token"
				: "A matching JWKS key has no alg and the profile allows several " +
				"algorithms for its key type; set alg on the key"
		);
	}
	if (candidates.length > 1) {
		throw new JWTError(
			"JWKS_NO_MATCHING_KEY",
			"Multiple keys in the JWKS match this token - issue tokens with a kid"
		);
	}
	const jwk = candidates[0] as StaticJWK;
	try {
		if (jwk.kty === "oct") {
			if (typeof jwk.k !== "string") {
				throw new JWTError("KEY_IMPORT_FAILED", "oct JWK is missing its key material");
			}
			const secret = decodeBase64url(jwk.k);
			validateHMACSecret(secret, info);
			return { alg: header.alg, key: secret };
		}
		const key = await importJWK(
			jwk as Parameters<typeof importJWK>[0],
			header.alg
		);
		return { alg: header.alg, key };
	} catch (cause) {
		if (cause instanceof JWTError && (cause.code === "KEY_IMPORT_FAILED" || cause.code === "ENTROPY_CHECK_FAILED")) {
			throw cause;
		}
		throw new JWTError("KEY_IMPORT_FAILED", "JWKS key could not be imported", { cause });
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
	// Entries for algorithms Lacewing has no descriptor for are dropped, not
	// fatal: real-world JWKS documents routinely carry keys for algorithms we
	// refuse to speak. A legacy RS256 entry is kept: it can only ever match a
	// token whose alg the profile allowlisted, so it widens nothing.
	return keys.filter(
		(jwk) =>
			typeof jwk === "object" &&
			jwk !== null &&
			typeof jwk.kty === "string" &&
			(jwk.alg === undefined ||
				(typeof jwk.alg === "string" && isKnownAlgorithmName(jwk.alg)))
	);
}

/** Create a {@link KeySource} backed by a static JWKS document. */
export function createLocalJWKSet(jwks: StaticJWKS): KeySource {
	const keys = validateJwksShape(jwks);
	return {
		getVerificationKey(
			header: JwtHeader,
			allowedAlgorithms: readonly AlgorithmInfo[]
		): Promise<ResolvedVerificationKey> {
			return resolveFromJwks(keys, header, allowedAlgorithms);
		},
	};
}
