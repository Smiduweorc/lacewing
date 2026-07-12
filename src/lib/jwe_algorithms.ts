/**
 * The JWE algorithm registry (encrypted JWTs). Two axes, both curated:
 *
 *  - key management (`alg`): how the content-encryption key is agreed/wrapped.
 *  - content encryption (`enc`): the AEAD that actually encrypts the payload.
 *
 * Deliberately absent, exactly as on the JWS side: `none`, `RSA1_5`
 * (Bleichenbacher - CVE-2023-... class), `RSA-OAEP` with SHA-1, and the `PBES2*`
 * password-based algorithms (Lacewing does not do human-memorable secrets).
 * As with JWS, the token header never chooses - the decryption profile does.
 *
 * Portability note: the `A192*` entries work on Node >= 24 (the engine floor)
 * but 192-bit AES is not implemented by browser WebCrypto and some edge
 * runtimes. Documented in the README; prefer `A128*`/`A256*` for tokens that
 * must be decrypted outside Node.
 */

import { AlgorithmNotAllowed } from "../util/errors.js";
import { SetAlg, type ValidAlg } from "../types.js";

export interface JweKeyManagementInfo {
	readonly name: string;
	/** Family: direct key, AES key-wrap, ECDH-ES (opt. wrap), or RSA-OAEP-256. */
	readonly kind: "dir" | "aeskw" | "ecdh" | "rsa";
	/** JWK key type the recipient key must have. */
	readonly kty: "EC" | "RSA" | "oct";
	/** Symmetric secret size in bytes (aeskw only). */
	readonly secretBytes?: number;
	/** Minimum RSA modulus in bits (rsa only). */
	readonly minKeyBits?: number;
}

export interface JweContentEncryptionInfo {
	readonly name: string;
	/** Content-encryption key size in bytes - the size a `dir` key must be. */
	readonly cekBytes: number;
}

const KEY_MANAGEMENT: readonly JweKeyManagementInfo[] = [
	{ name: "dir", kind: "dir", kty: "oct" },
	{ name: "A128KW", kind: "aeskw", kty: "oct", secretBytes: 16 },
	{ name: "A192KW", kind: "aeskw", kty: "oct", secretBytes: 24 },
	{ name: "A256KW", kind: "aeskw", kty: "oct", secretBytes: 32 },
	{ name: "A128GCMKW", kind: "aeskw", kty: "oct", secretBytes: 16 },
	{ name: "A192GCMKW", kind: "aeskw", kty: "oct", secretBytes: 24 },
	{ name: "A256GCMKW", kind: "aeskw", kty: "oct", secretBytes: 32 },
	{ name: "ECDH-ES", kind: "ecdh", kty: "EC" },
	{ name: "ECDH-ES+A128KW", kind: "ecdh", kty: "EC" },
	{ name: "ECDH-ES+A192KW", kind: "ecdh", kty: "EC" },
	{ name: "ECDH-ES+A256KW", kind: "ecdh", kty: "EC" },
	{ name: "RSA-OAEP-256", kind: "rsa", kty: "RSA", minKeyBits: 2048 },
];

const CONTENT_ENCRYPTION: readonly JweContentEncryptionInfo[] = [
	{ name: "A128GCM", cekBytes: 16 },
	{ name: "A192GCM", cekBytes: 24 },
	{ name: "A256GCM", cekBytes: 32 },
	{ name: "A128CBC-HS256", cekBytes: 32 },
	{ name: "A192CBC-HS384", cekBytes: 48 },
	{ name: "A256CBC-HS512", cekBytes: 64 },
];

const keyManagement = new Map(KEY_MANAGEMENT.map((info) => [info.name, info]));
const contentEncryption = new Map(CONTENT_ENCRYPTION.map((info) => [info.name, info]));

export function isValidKeyManagementAlgorithm(alg: string): boolean {
	return keyManagement.has(alg);
}

export function isValidContentEncryptionAlgorithm(enc: string): boolean {
	return contentEncryption.has(enc);
}

/** Look up a key-management algorithm, or throw {@link AlgorithmNotAllowed}. */
export function getKeyManagementProperties(alg: string): JweKeyManagementInfo {
	const info = keyManagement.get(alg);
	if (info === undefined) {
		throw new AlgorithmNotAllowed("Key-management algorithm is not in the Lacewing allowlist");
	}
	return info;
}

/** Look up a content-encryption algorithm, or throw {@link AlgorithmNotAllowed}. */
export function getContentEncryptionProperties(enc: string): JweContentEncryptionInfo {
	const info = contentEncryption.get(enc);
	if (info === undefined) {
		throw new AlgorithmNotAllowed("Content-encryption algorithm is not in the Lacewing allowlist");
	}
	return info;
}

/** Validate against the registry and brand the key-management alg. */
export function toValidKeyManagementAlg(alg: string): ValidAlg {
	getKeyManagementProperties(alg);
	return SetAlg(alg);
}

/** Validate against the registry and brand the content-encryption alg. */
export function toValidContentEncryptionAlg(enc: string): ValidAlg {
	getContentEncryptionProperties(enc);
	return SetAlg(enc);
}

export function listKeyManagementAlgorithms(): string[] {
	return [...keyManagement.keys()];
}

export function listContentEncryptionAlgorithms(): string[] {
	return [...contentEncryption.keys()];
}
