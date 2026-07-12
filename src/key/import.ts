/**
 * Key import with algorithm binding (RFC 8725 §3.1/§3.2/§3.5).
 *
 * Every key enters Lacewing through this module and leaves bound to
 * exactly one algorithm, carried in the type system. Sign/verify never
 * accept raw `CryptoKey`s, so the alg-to-key binding cannot be bypassed.
 */

import { importJWK, importPKCS8, importSPKI } from "jose";
import {
	EntropyCheckFailed,
	KeyImportFailed,
	KeyTypeMismatch,
} from "../util/errors.js";
import { getAlgorithmProperties, type AlgorithmInfo } from "../lib/algorithms.js";
import { validateHMACSecret } from "../lib/entropy.js";
import { decodeBase64url } from "../lib/base64url.js";
import {
	createLacewingKey,
	SetAlg,
	type LacewingKey,
	type StaticJWK,
} from "../types.js";

/** JWK object, PEM string (PKCS#8 / SPKI), raw secret, or a CryptoKey. */
export type KeyMaterial = StaticJWK | string | Uint8Array | CryptoKey;

function expectedWebCryptoName(alg: string, info: AlgorithmInfo): string {
	if (alg === "EdDSA") return "Ed25519";
	if (info.kty === "EC") return "ECDSA";
	if (info.kty === "oct") return "HMAC";
	// RSA: PS* uses RSA-PSS; legacy RS* uses PKCS#1 v1.5.
	return alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5";
}

// Only called for asymmetric JWKs; oct keys take the importSecret path.
function keyTypeOfJwk(jwk: StaticJWK): "public" | "private" {
	return typeof jwk.d === "string" ? "private" : "public";
}

function assertJwkMatches(jwk: StaticJWK, alg: string, info: AlgorithmInfo): void {
	if (jwk.kty !== info.kty) {
		throw new KeyTypeMismatch(
			`Key type "${jwk.kty}" cannot be used with ${alg} (expected ${info.kty})`
		);
	}
	if (info.crv !== undefined && jwk.crv !== info.crv) {
		throw new KeyTypeMismatch(`${alg} requires curve ${info.crv}`);
	}
	if (typeof jwk.alg === "string" && jwk.alg !== alg) {
		throw new KeyTypeMismatch(
			"JWK declares a different algorithm than it is being imported for"
		);
	}
	if (info.kty === "RSA" && typeof jwk.n === "string") {
		const modulusBits = decodeBase64url(jwk.n).length * 8;
		if (modulusBits < info.minKeyBits) {
			throw new KeyTypeMismatch(
				`${alg} requires an RSA modulus of at least ${info.minKeyBits} bits`
			);
		}
	}
}

function assertCryptoKeyMatches(key: CryptoKey, alg: string, info: AlgorithmInfo): void {
	const algorithm = key.algorithm as { name: string; namedCurve?: string };
	if (algorithm.name !== expectedWebCryptoName(alg, info)) {
		throw new KeyTypeMismatch(
			`CryptoKey algorithm "${algorithm.name}" cannot be used with ${alg}`
		);
	}
	if (info.kty === "EC" && algorithm.namedCurve !== info.crv) {
		throw new KeyTypeMismatch(`${alg} requires curve ${info.crv}`);
	}
}

function importSecret(material: KeyMaterial, alg: string): { key: Uint8Array } {
	let secret: Uint8Array;
	if (material instanceof Uint8Array) {
		secret = material;
	} else if (typeof material === "string") {
		// RS256->HS256 key-confusion defense (CVE-2016-5431 class): a PEM -
		// typically the issuer's *public* key - is never a valid HMAC secret.
		if (material.includes("-----BEGIN")) {
			throw new KeyTypeMismatch(
				"PEM key material cannot be used as an HMAC secret"
			);
		}
		secret = new TextEncoder().encode(material);
	} else if (
		typeof material === "object" &&
		material !== null &&
		!(material instanceof CryptoKey) &&
		material.kty === "oct" &&
		typeof material.k === "string"
	) {
		secret = decodeBase64url(material.k);
	} else {
		throw new KeyImportFailed(
			"HMAC secrets must be a Uint8Array, string, or oct JWK"
		);
	}
	validateHMACSecret(secret, alg);
	return { key: secret };
}

async function importAsymmetric(
	material: KeyMaterial,
	alg: string,
	info: AlgorithmInfo
): Promise<{ key: unknown; keyType: "public" | "private" }> {
	if (material instanceof CryptoKey) {
		assertCryptoKeyMatches(material, alg, info);
		const keyType = material.type;
		if (keyType !== "public" && keyType !== "private") {
			throw new KeyTypeMismatch(`A secret key cannot be used with ${alg}`);
		}
		return { key: material, keyType };
	}
	if (typeof material === "string") {
		if (material.includes("-----BEGIN PRIVATE KEY-----")) {
			return { key: await importPKCS8(material, alg), keyType: "private" };
		}
		if (material.includes("-----BEGIN PUBLIC KEY-----")) {
			return { key: await importSPKI(material, alg), keyType: "public" };
		}
		throw new KeyImportFailed(
			"Unsupported PEM - only PKCS#8 private keys and SPKI public keys are accepted"
		);
	}
	if (material instanceof Uint8Array) {
		throw new KeyTypeMismatch(`Raw bytes cannot be used with ${alg}`);
	}
	if (typeof material === "object" && material !== null) {
		assertJwkMatches(material, alg, info);
		const key = await importJWK(
			material as Parameters<typeof importJWK>[0],
			alg
		);
		return { key, keyType: keyTypeOfJwk(material) };
	}
	throw new KeyImportFailed("Unsupported key material");
}

/**
 * Import key material and bind it to `algorithm`. The returned
 * {@link LacewingKey} can only ever be used with that algorithm.
 *
 * Throws {@link KeyTypeMismatch} when material and algorithm disagree,
 * {@link EntropyCheckFailed} for weak HMAC secrets, and
 * {@link KeyImportFailed} for anything else that goes wrong.
 */
export async function importKey<const Alg extends string>(
	material: KeyMaterial,
	algorithm: Alg
): Promise<LacewingKey<Alg>> {
	const info = getAlgorithmProperties(algorithm);
	const alg = SetAlg(algorithm) as Alg & ReturnType<typeof SetAlg>;
	try {
		if (info.kty === "oct") {
			const { key } = importSecret(material, algorithm);
			return createLacewingKey(alg, "secret", key);
		}
		const { key, keyType } = await importAsymmetric(material, algorithm, info);
		return createLacewingKey(alg, keyType, key);
	} catch (cause) {
		if (
			cause instanceof KeyTypeMismatch ||
			cause instanceof EntropyCheckFailed ||
			cause instanceof KeyImportFailed
		) {
			throw cause;
		}
		throw new KeyImportFailed("Key import failed", { cause });
	}
}
