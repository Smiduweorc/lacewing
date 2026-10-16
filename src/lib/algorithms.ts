/**
 * The signature algorithms Lacewing speaks, and which key types they pair
 * with (RFC 8725 §3.1/§3.2).
 *
 * There is no registry to mutate. The default set is a frozen constant, and
 * an algorithm name given as a string is looked up in it alone. The legacy
 * RSASSA-PKCS1-v1_5 descriptors exist too, but a caller only reaches them by
 * importing `lacewing/legacy/rsa` and passing one at the call site, so one
 * caller opting in never widens what another accepts. `none` and `RSA1_5`
 * are in neither list. Adding an algorithm is a one-entry change here
 * (cryptographic agility, §3.2.4).
 *
 * Descriptors are frozen and compared by identity: a hand-built
 * `{ name: "RS256", minKeyBits: 512 }` is not one of Lacewing's and is
 * refused, so nobody can lower a key-size floor by forging one.
 */

import { JWTError } from "../util/errors.js";

export interface AlgorithmInfo<Name extends string = string> {
	/** JOSE algorithm identifier, e.g. "EdDSA". */
	readonly name: Name;
	/** JWK key type this algorithm pairs with. */
	readonly kty: "OKP" | "EC" | "RSA" | "oct";
	/** Named curve for EC/OKP algorithms. */
	readonly crv?: string;
	/** Minimum key size in bits (secret length for `oct`, modulus for RSA). */
	readonly minKeyBits: number;
}

function freeze<const Name extends string>(info: AlgorithmInfo<Name>): AlgorithmInfo<Name> {
	return Object.freeze(info);
}

const DEFAULT_ALGORITHMS: readonly AlgorithmInfo[] = Object.freeze([
	freeze({ name: "EdDSA", kty: "OKP", crv: "Ed25519", minKeyBits: 256 }),
	// RFC 9864's fully-specified name for the same Ed25519 signature. Some
	// clients (oauth4webapi among them) only ever write this one.
	freeze({ name: "Ed25519", kty: "OKP", crv: "Ed25519", minKeyBits: 256 }),
	freeze({ name: "ES256", kty: "EC", crv: "P-256", minKeyBits: 256 }),
	freeze({ name: "ES384", kty: "EC", crv: "P-384", minKeyBits: 384 }),
	freeze({ name: "ES512", kty: "EC", crv: "P-521", minKeyBits: 521 }),
	freeze({ name: "PS256", kty: "RSA", minKeyBits: 2048 }),
	freeze({ name: "PS384", kty: "RSA", minKeyBits: 2048 }),
	freeze({ name: "PS512", kty: "RSA", minKeyBits: 2048 }),
	// RFC 7518 §3.2: HMAC keys must be at least as large as the hash output.
	freeze({ name: "HS256", kty: "oct", minKeyBits: 256 }),
	freeze({ name: "HS384", kty: "oct", minKeyBits: 384 }),
	freeze({ name: "HS512", kty: "oct", minKeyBits: 512 }),
]);

/** Legacy RSASSA-PKCS1-v1_5 descriptors; public only through `lacewing/legacy/rsa`. */
export const LEGACY_RS256 = freeze({ name: "RS256", kty: "RSA", minKeyBits: 2048 });
export const LEGACY_RS384 = freeze({ name: "RS384", kty: "RSA", minKeyBits: 2048 });
export const LEGACY_RS512 = freeze({ name: "RS512", kty: "RSA", minKeyBits: 2048 });

const ALL_ALGORITHMS: readonly AlgorithmInfo[] = Object.freeze([
	...DEFAULT_ALGORITHMS,
	LEGACY_RS256,
	LEGACY_RS384,
	LEGACY_RS512,
]);

function notAllowed(): JWTError {
	// Deliberately does not echo the name: it may be attacker-controlled.
	return new JWTError("ALGORITHM_NOT_ALLOWED", "Algorithm is not in the Lacewing allowlist");
}

/**
 * Resolve the way a caller names an algorithm: a string from the default
 * set, or a descriptor Lacewing handed out (the legacy ones among them).
 * Anything else, a legacy name given as a bare string included, is refused.
 */
export function resolveAlgorithm<Name extends string>(choice: Name | AlgorithmInfo<Name>): AlgorithmInfo<Name> {
	if (typeof choice === "string") {
		const info = DEFAULT_ALGORITHMS.find((candidate) => candidate.name === choice);
		if (info === undefined) throw notAllowed();
		return info as AlgorithmInfo<Name>;
	}
	if (!ALL_ALGORITHMS.includes(choice)) {
		throw new JWTError(
			"ALGORITHM_NOT_ALLOWED",
			"Algorithm descriptors come from Lacewing; a hand-built one is refused"
		);
	}
	return choice;
}

/**
 * Find `name` in an allowlist built by {@link resolveAlgorithm}. Re-checks
 * identity, so a hand-built profile cannot smuggle in a forged descriptor.
 */
export function findAlgorithm(name: string, allowed: readonly AlgorithmInfo[]): AlgorithmInfo {
	const info = allowed.find((candidate) => candidate.name === name);
	if (info === undefined || !ALL_ALGORITHMS.includes(info)) throw notAllowed();
	return info;
}

/** Whether Lacewing has a descriptor by this name at all, default or legacy. */
export function isKnownAlgorithmName(name: string): boolean {
	return ALL_ALGORITHMS.some((info) => info.name === name);
}

/**
 * Look up an algorithm's properties. A string resolves against the default
 * set, then against `legacy`, the legacy descriptors the caller opted into
 * (from `lacewing/legacy/rsa`). Throws `ALGORITHM_NOT_ALLOWED` otherwise.
 *
 * @example
 * ```ts
 * import { LEGACY_RS256 } from "lacewing/legacy/rsa";
 * getAlgorithmProperties("ES256");                 // { kty: "EC", crv: "P-256", ... }
 * getAlgorithmProperties("RS256");                 // throws: not in the default set
 * getAlgorithmProperties("RS256", [LEGACY_RS256]); // { kty: "RSA", minKeyBits: 2048 }
 * ```
 */
export function getAlgorithmProperties(alg: string, legacy: readonly AlgorithmInfo[] = []): AlgorithmInfo {
	const allowed = [...DEFAULT_ALGORITHMS, ...legacy.map((info) => resolveAlgorithm(info))];
	return findAlgorithm(alg, allowed);
}
