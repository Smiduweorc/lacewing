/**
 * Encryption key import/generation (the JWE counterpart of `key/import.ts` and
 * `key/generate.ts`). Every encryption key enters here and leaves bound to
 * exactly one key-management algorithm, carried in the type. `EncryptJWT` and
 * `jwtDecrypt` never accept a bare `CryptoKey`, so the binding cannot be
 * bypassed - and a signing key can never be used to encrypt (different brand).
 */

import { generateKeyPair as joseGenerateKeyPair, importJWK, importPKCS8, importSPKI } from "jose";
import { KeyImportFailed, KeyTypeMismatch } from "../util/errors.js";
import {
	getContentEncryptionProperties,
	getKeyManagementProperties,
	type JweKeyManagementInfo,
} from "../lib/jwe_algorithms.js";
import { decodeBase64url } from "../lib/base64url.js";
import {
	createLacewingEncryptionKey,
	SetAlg,
	type LacewingEncryptionKey,
	type StaticJWK,
} from "../types.js";

/** JWK object, PEM string (PKCS#8 / SPKI), raw secret, or a CryptoKey. */
export type EncryptionKeyMaterial = StaticJWK | string | Uint8Array | CryptoKey;

export interface GenerateEncryptionKeyPairOptions {
	extractable?: boolean;
}

function assertSymmetric(info: JweKeyManagementInfo, algorithm: string): void {
	if (info.kind !== "aeskw") {
		throw new KeyTypeMismatch(
			`${algorithm} is not an AES key-wrapping algorithm - use ` +
				(info.kind === "dir" ? "generateDirectKey(enc)" : "generateEncryptionKeyPair()")
		);
	}
}

/**
 * Generate an asymmetric encryption key pair for `algorithm` (ECDH-ES* or
 * RSA-OAEP-256). The recipient keeps the private key; senders encrypt to the
 * public key.
 */
export async function generateEncryptionKeyPair<const Alg extends string>(
	algorithm: Alg,
	options: GenerateEncryptionKeyPairOptions = {}
): Promise<{ publicKey: LacewingEncryptionKey<Alg>; privateKey: LacewingEncryptionKey<Alg> }> {
	const info = getKeyManagementProperties(algorithm);
	if (info.kind !== "ecdh" && info.kind !== "rsa") {
		throw new KeyTypeMismatch(`${algorithm} is symmetric - use generateEncryptionSecret()/generateDirectKey()`);
	}
	const alg = SetAlg(algorithm) as Alg & ReturnType<typeof SetAlg>;
	try {
		const { publicKey, privateKey } = await joseGenerateKeyPair(algorithm, {
			extractable: options.extractable ?? false,
		});
		return {
			publicKey: createLacewingEncryptionKey(alg, "public", publicKey),
			privateKey: createLacewingEncryptionKey(alg, "private", privateKey),
		};
	} catch (cause) {
		throw new KeyImportFailed("Encryption key generation failed", { cause });
	}
}

/** Generate a random symmetric key for an AES key-wrapping algorithm (A*KW / A*GCMKW). */
export function generateEncryptionSecret<const Alg extends string>(
	algorithm: Alg
): LacewingEncryptionKey<Alg> {
	const info = getKeyManagementProperties(algorithm);
	assertSymmetric(info, algorithm);
	const alg = SetAlg(algorithm) as Alg & ReturnType<typeof SetAlg>;
	const secret = new Uint8Array(info.secretBytes as number);
	globalThis.crypto.getRandomValues(secret);
	return createLacewingEncryptionKey(alg, "secret", secret);
}

/**
 * Generate a random direct (`alg: "dir"`) key sized to a content-encryption
 * algorithm. The key *is* the content-encryption key, so it is inseparable
 * from its `enc`: a 32-byte key is for A256GCM/A128CBC-HS256, and so on.
 */
export function generateDirectKey<const Enc extends string>(
	enc: Enc
): LacewingEncryptionKey<"dir"> {
	const info = getContentEncryptionProperties(enc);
	const alg = SetAlg("dir") as "dir" & ReturnType<typeof SetAlg>;
	const secret = new Uint8Array(info.cekBytes);
	globalThis.crypto.getRandomValues(secret);
	return createLacewingEncryptionKey(alg, "secret", secret);
}

function importSymmetric(material: EncryptionKeyMaterial, info: JweKeyManagementInfo, algorithm: string): Uint8Array {
	let secret: Uint8Array;
	if (material instanceof Uint8Array) {
		secret = material;
	} else if (
		typeof material === "object" &&
		material !== null &&
		!(material instanceof CryptoKey) &&
		material.kty === "oct" &&
		typeof material.k === "string"
	) {
		secret = decodeBase64url(material.k);
	} else {
		throw new KeyImportFailed(`${algorithm} keys must be a Uint8Array or oct JWK`);
	}
	// AES key-wrap keys are a fixed size; `dir` keys must match some valid CEK size.
	if (info.kind === "aeskw" && secret.length !== info.secretBytes) {
		throw new KeyTypeMismatch(`${algorithm} requires a ${info.secretBytes}-byte key`);
	}
	if (info.kind === "dir" && ![16, 24, 32, 48, 64].includes(secret.length)) {
		throw new KeyTypeMismatch("A dir key must be 16, 24, 32, 48 or 64 bytes (a valid CEK size)");
	}
	return secret;
}

async function importAsymmetricEncryption(
	material: EncryptionKeyMaterial,
	algorithm: string
): Promise<{ key: unknown; keyType: "public" | "private" }> {
	if (material instanceof CryptoKey) {
		if (material.type !== "public" && material.type !== "private") {
			throw new KeyTypeMismatch(`A secret key cannot be used with ${algorithm}`);
		}
		return { key: material, keyType: material.type };
	}
	if (typeof material === "string") {
		if (material.includes("-----BEGIN PRIVATE KEY-----")) {
			return { key: await importPKCS8(material, algorithm), keyType: "private" };
		}
		if (material.includes("-----BEGIN PUBLIC KEY-----")) {
			return { key: await importSPKI(material, algorithm), keyType: "public" };
		}
		throw new KeyImportFailed("Unsupported PEM - only PKCS#8 private and SPKI public keys are accepted");
	}
	if (typeof material === "object" && material !== null) {
		const jwk = material as StaticJWK;
		const keyType = typeof jwk.d === "string" ? "private" : "public";
		return { key: await importJWK(jwk as Parameters<typeof importJWK>[0], algorithm), keyType };
	}
	throw new KeyImportFailed("Unsupported encryption key material");
}

/**
 * Import encryption key material and bind it to `algorithm`. Throws
 * {@link KeyTypeMismatch} when material and algorithm disagree, and
 * {@link KeyImportFailed} for anything else.
 */
export async function importEncryptionKey<const Alg extends string>(
	material: EncryptionKeyMaterial,
	algorithm: Alg
): Promise<LacewingEncryptionKey<Alg>> {
	const info = getKeyManagementProperties(algorithm);
	const alg = SetAlg(algorithm) as Alg & ReturnType<typeof SetAlg>;
	try {
		if (info.kty === "oct") {
			return createLacewingEncryptionKey(alg, "secret", importSymmetric(material, info, algorithm));
		}
		const { key, keyType } = await importAsymmetricEncryption(material, algorithm);
		return createLacewingEncryptionKey(alg, keyType, key);
	} catch (cause) {
		if (cause instanceof KeyTypeMismatch || cause instanceof KeyImportFailed) throw cause;
		throw new KeyImportFailed("Encryption key import failed", { cause });
	}
}
