/**
 * The one and only decryption path (the JWE analogue of `jwtVerify`).
 *
 * Order of operations, fail-fast, all-or-nothing:
 *   1. structural parse (5 segments, length cap, strict base64url/UTF-8/JSON)
 *   2. header validation (alg + enc allowlists, typ, kid hygiene, forbidden
 *      params - including `zip`, the JWE decompression-bomb vector)
 *   3. decryption with the profile's key, restricted to the allowlisted alg+enc
 *   4. claims validation
 *   5. revocation check - last, so unauthenticated input can never drive the
 *      store (LW-rev.3)
 *
 * A JWS (three segments) handed here is rejected at step 1, and a JWE handed to
 * `jwtVerify` is rejected there in turn - the two formats never cross over.
 */

import { compactDecrypt } from "jose";
import { JWTError } from "../util/errors.js";
import { decodeBase64url } from "../lib/base64url.js";
import { decodeUTF8 } from "../lib/utf8.js";
import { MAX_TOKEN_LENGTH } from "../lib/limits.js";
import { parseJsonObject } from "../lib/json.js";
import { FORBIDDEN_PARAMS, sanitizeKid, normalizeTyp } from "../lib/headers.js";
import {
	getContentEncryptionProperties,
	getKeyManagementProperties,
} from "../lib/jwe_algorithms.js";
import { validateClaims } from "../lib/claims.js";
import { assertNotRevoked } from "../revocation/store.js";
import { isDecryptionProfile } from "./decryption_profile.js";
import {
	SetAlg,
	type DecryptedJwt,
	type ExpectedDecryptionProfile,
	type JweHeader,
	type JwtPayLoad,
} from "../types.js";

function validateJweHeader(raw: Record<string, unknown>, profile: ExpectedDecryptionProfile): JweHeader {
	for (const param of FORBIDDEN_PARAMS) {
		if (param in raw) throw new JWTError(
			"JWT_INVALID",
			`Token header parameter "${param}" is not supported`
		);
	}

	const alg = raw.alg;
	if (typeof alg !== "string" || alg.toLowerCase() === "none") {
		throw new JWTError(
			"ALGORITHM_NOT_ALLOWED",
			"Key-management algorithm 'none' (or a missing alg) is not allowed"
		);
	}
	if (!profile.keyManagementAlgorithms.some((allowed) => (allowed as string) === alg)) {
		throw new JWTError(
			"ALGORITHM_NOT_ALLOWED",
			"Token key-management algorithm is not in this profile's allowlist"
		);
	}
	getKeyManagementProperties(alg); // defense in depth

	const enc = raw.enc;
	if (typeof enc !== "string" || enc.toLowerCase() === "none") {
		throw new JWTError(
			"ALGORITHM_NOT_ALLOWED",
			"Content-encryption algorithm 'none' (or a missing enc) is not allowed"
		);
	}
	if (!profile.contentEncryptionAlgorithms.some((allowed) => (allowed as string) === enc)) {
		throw new JWTError(
			"ALGORITHM_NOT_ALLOWED",
			"Token content-encryption algorithm is not in this profile's allowlist"
		);
	}
	getContentEncryptionProperties(enc);

	const typ = raw.typ;
	if (typeof typ !== "string" || typ.length === 0) {
		throw new JWTError(
			"JWT_INVALID",
			"Token header is missing a typ (explicit typing is mandatory)"
		);
	}
	if (normalizeTyp(typ) !== normalizeTyp(profile.typ)) {
		throw new JWTError(
			"JWT_CLAIM_VALIDATION_FAILED",
			"Unexpected token type for this profile",
			{ claim: "typ" }
		);
	}

	const header: JweHeader = { alg: SetAlg(alg), enc: SetAlg(enc), typ };
	if (raw.kid !== undefined) header.kid = sanitizeKid(raw.kid);
	if (raw.cty !== undefined) {
		if (typeof raw.cty !== "string") throw new JWTError(
			"JWT_INVALID",
			"Token header cty must be a string"
		);
		header.cty = raw.cty;
	}
	return header;
}

/**
 * Decrypt and validate a compact JWE against a profile. The returned
 * {@link DecryptedJwt} is the only way to obtain one - there is no backdoor,
 * and it is a distinct type from a `VerifiedJwt` (the signed-token proof).
 */
export async function jwtDecrypt(
	token: string,
	profile: ExpectedDecryptionProfile
): Promise<DecryptedJwt> {
	if (!isDecryptionProfile(profile)) {
		throw new TypeError(
			"jwtDecrypt needs a profile built by defineDecryptionProfile(); a hand-built or copied one skips its checks"
		);
	}
	if (typeof token !== "string" || token.length === 0) {
		throw new JWTError("JWT_INVALID", "Token must be a non-empty string");
	}
	if (token.length > MAX_TOKEN_LENGTH) {
		throw new JWTError("JWT_INVALID", "Token exceeds the maximum length");
	}
	const segments = token.split(".");
	if (segments.length !== 5) {
		// A JWS has three segments; anything but five is not a compact JWE.
		throw new JWTError("JWT_INVALID", "Token is not a compact JWE (expected five segments)");
	}
	const rawHeader = segments[0] as string;
	if (rawHeader === "") throw new JWTError("JWT_INVALID", "Token has an empty header segment");

	const header = validateJweHeader(
		parseJsonObject(decodeUTF8(decodeBase64url(rawHeader)), "header"),
		profile
	);

	// Strict decoding is authoritative for every segment, not just the header:
	// the AEAD ignores the unused trailing bits of a segment whose length is not
	// a multiple of four, so a lenient parser accepts several distinct token
	// strings that decrypt to the same plaintext. Rejecting non-canonical
	// base64url keeps the token string a stable identity for revocation and
	// replay caches. The encrypted key is empty under `dir`, which is canonical.

	// https://github.com/Smiduweorc/lacewing/issues/12
	for (const segment of segments.slice(1)) {
		decodeBase64url(segment);
	}

	if ((profile.key.algorithm as string) !== (header.alg as string)) {
		throw new JWTError(
			"ALGORITHM_NOT_ALLOWED",
			"Token key-management algorithm does not match the profile's key"
		);
	}

	let plaintext: Uint8Array;
	try {
		const result = await compactDecrypt(
			token,
			profile.key.key as Parameters<typeof compactDecrypt>[1],
			{
				keyManagementAlgorithms: [header.alg as string],
				contentEncryptionAlgorithms: [header.enc as string],
			}
		);
		plaintext = result.plaintext;
	} catch (cause) {
		throw new JWTError("JWT_INVALID", "Token decryption failed", { cause });
	}

	const payload = parseJsonObject(decodeUTF8(plaintext), "payload");
	await validateClaims(payload, profile);

	await assertNotRevoked(payload, profile);

	return { header, payload: payload as JwtPayLoad } as DecryptedJwt;
}
