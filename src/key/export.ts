/**
 * Key export to JWK / PEM. Only works on extractable keys - keys from
 * `generateKeyPair` are non-extractable unless you asked otherwise.
 */

import { exportJWK, exportPKCS8, exportSPKI } from "jose";
import { KeyExportFailed } from "../util/errors.js";
import { encodeBase64url } from "../lib/base64url.js";
import type { LacewingKey, StaticJWK } from "../types.js";

/** Export a key as a JWK, with its bound `alg` and `use: "sig"` set. */
export async function exportKeyJWK(key: LacewingKey): Promise<StaticJWK> {
	try {
		if (key.keyType === "secret") {
			return {
				kty: "oct",
				k: encodeBase64url(key.key as Uint8Array),
				alg: key.algorithm,
				use: "sig",
			};
		}
		const jwk = await exportJWK(key.key as CryptoKey);
		return { ...jwk, alg: key.algorithm, use: "sig" } as StaticJWK;
	} catch (cause) {
		if (cause instanceof KeyExportFailed) throw cause;
		throw new KeyExportFailed("Key export failed - is the key extractable?", {
			cause,
		});
	}
}

/** Export an asymmetric key as PEM (PKCS#8 for private, SPKI for public). */
export async function exportKeyPEM(key: LacewingKey): Promise<string> {
	if (key.keyType === "secret") {
		throw new KeyExportFailed("Symmetric secrets have no PEM representation");
	}
	try {
		return key.keyType === "private"
			? await exportPKCS8(key.key as CryptoKey)
			: await exportSPKI(key.key as CryptoKey);
	} catch (cause) {
		throw new KeyExportFailed("Key export failed - is the key extractable?", {
			cause,
		});
	}
}
