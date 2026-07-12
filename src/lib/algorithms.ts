/**
 * The algorithm registry - single source of truth for which algorithms
 * exist and which key types they pair with (RFC 8725 §3.1/§3.2).
 *
 * `none`, `RSA1_5` and `RS*` are simply absent. Adding an algorithm is a
 * one-entry change here (cryptographic agility, §3.2.4). Legacy interop
 * algorithms can only enter through `registerLegacyAlgorithm`, which is
 * reachable exclusively via the explicit `legacy/` imports.
 */

import { AlgorithmNotAllowed } from "../util/errors.js";
import { SetAlg, type ValidAlg } from "../types.js";

export interface AlgorithmInfo {
	/** JOSE algorithm identifier, e.g. "EdDSA". */
	readonly name: string;
	/** JWK key type this algorithm pairs with. */
	readonly kty: "OKP" | "EC" | "RSA" | "oct";
	/** Named curve for EC/OKP algorithms. */
	readonly crv?: string;
	/** Minimum key size in bits (secret length for `oct`, modulus for RSA). */
	readonly minKeyBits: number;
}

const CORE_ALGORITHMS: readonly AlgorithmInfo[] = [
	{ name: "EdDSA", kty: "OKP", crv: "Ed25519", minKeyBits: 256 },
	{ name: "ES256", kty: "EC", crv: "P-256", minKeyBits: 256 },
	{ name: "ES384", kty: "EC", crv: "P-384", minKeyBits: 384 },
	{ name: "ES512", kty: "EC", crv: "P-521", minKeyBits: 521 },
	{ name: "PS256", kty: "RSA", minKeyBits: 2048 },
	{ name: "PS384", kty: "RSA", minKeyBits: 2048 },
	{ name: "PS512", kty: "RSA", minKeyBits: 2048 },
	// RFC 7518 §3.2: HMAC keys must be at least as large as the hash output.
	{ name: "HS256", kty: "oct", minKeyBits: 256 },
	{ name: "HS384", kty: "oct", minKeyBits: 384 },
	{ name: "HS512", kty: "oct", minKeyBits: 512 },
];

const registry = new Map<string, AlgorithmInfo>(
	CORE_ALGORITHMS.map((info) => [info.name, info])
);

/** Type guard: is this exact string an allowed algorithm? Case sensitive. */
export function isValidAlgorithm(alg: string): boolean {
	return registry.has(alg);
}

/** Look up an algorithm's properties, or throw {@link AlgorithmNotAllowed}. */
export function getAlgorithmProperties(alg: string): AlgorithmInfo {
	const info = registry.get(alg);
	if (info === undefined) {
		// Deliberately does not echo `alg`: it may be attacker-controlled.
		throw new AlgorithmNotAllowed("Algorithm is not in the Lacewing allowlist");
	}
	return info;
}

/** Validate against the registry and brand the string as {@link ValidAlg}. */
export function toValidAlg(alg: string): ValidAlg {
	getAlgorithmProperties(alg);
	return SetAlg(alg);
}

/** Currently registered algorithm names (core + any enabled legacy). */
export function listAlgorithms(): string[] {
	return [...registry.keys()];
}

/**
 * Internal - only the `legacy/` modules call this. Registers an interop
 * algorithm so it becomes importable/verifiable. Never accepts `none`.
 */
export function registerLegacyAlgorithm(info: AlgorithmInfo): void {
	if (info.name.toLowerCase() === "none") {
		throw new AlgorithmNotAllowed("Algorithm 'none' is not allowed");
	}
	if (!registry.has(info.name)) {
		registry.set(info.name, info);
	}
}
