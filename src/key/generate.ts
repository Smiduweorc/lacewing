/**
 * Key generation with safe defaults:
 * asymmetric-first - EdDSA unless you say otherwise - and secrets that
 * are always cryptographically random at the algorithm's minimum size.
 */

import { generateKeyPair as joseGenerateKeyPair } from "jose";
import { JWTError } from "../util/errors.js";
import { resolveAlgorithm, type AlgorithmInfo } from "../lib/algorithms.js";
import { createLacewingKey, SetAlg, type LacewingKey } from "../types.js";

export interface GenerateKeyPairOptions {
	/**
	 * Whether the private key may be exported later (default false -
	 * non-extractable keys can't leak through `exportKey*`).
	 */
	extractable?: boolean;
}

/**
 * Generate an asymmetric key pair, bound to `algorithm` (default EdDSA): a
 * name from the default set, or a legacy descriptor from `lacewing/legacy/rsa`.
 */
export async function generateKeyPair<const Alg extends string = "EdDSA">(
	algorithm: Alg | AlgorithmInfo<Alg> = "EdDSA" as Alg,
	options: GenerateKeyPairOptions = {}
): Promise<{ publicKey: LacewingKey<Alg>; privateKey: LacewingKey<Alg> }> {
	const info = resolveAlgorithm(algorithm);
	if (info.kty === "oct") {
		throw new JWTError("KEY_TYPE_MISMATCH", `${info.name} is symmetric - use generateSecret() instead`);
	}
	const alg = SetAlg(info.name) as Alg & ReturnType<typeof SetAlg>;
	try {
		const { publicKey, privateKey } = await joseGenerateKeyPair(info.name, {
			extractable: options.extractable ?? false,
		});
		return {
			publicKey: createLacewingKey(alg, "public", publicKey),
			privateKey: createLacewingKey(alg, "private", privateKey),
		};
	} catch (cause) {
		throw new JWTError("KEY_IMPORT_FAILED", "Key generation failed", { cause });
	}
}

/**
 * Generate a random HMAC secret at the algorithm's minimum size
 * (default HS256 -> 256 bits). Always passes the entropy checks by
 * construction.
 */
export function generateSecret<const Alg extends string = "HS256">(
	algorithm: Alg = "HS256" as Alg
): LacewingKey<Alg> {
	const info = resolveAlgorithm(algorithm);
	if (info.kty !== "oct") {
		throw new JWTError(
			"KEY_TYPE_MISMATCH",
			`${algorithm} is asymmetric - use generateKeyPair() instead`
		);
	}
	const alg = SetAlg(algorithm) as Alg & ReturnType<typeof SetAlg>;
	const secret = new Uint8Array(Math.ceil(info.minKeyBits / 8));
	globalThis.crypto.getRandomValues(secret);
	return createLacewingKey(alg, "secret", secret);
}
