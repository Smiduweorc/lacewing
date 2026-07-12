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
import {
	AlgorithmNotAllowed,
	JWTClaimValidationFailed,
	JWTInvalid,
	JWTRevoked,
	MissingClaim,
	RevocationCheckFailed,
} from "../util/errors.js";
import { decodeBase64url } from "../lib/base64url.js";
import { decodeUTF8 } from "../lib/utf8.js";
import { parseJsonObject } from "../lib/json.js";
import { sanitizeKid, normalizeTyp } from "../lib/headers.js";
import {
	getContentEncryptionProperties,
	getKeyManagementProperties,
} from "../lib/jwe_algorithms.js";
import { validateClaims } from "../lib/claims.js";
import { buildRevocationContext } from "../revocation/store.js";
import {
	SetAlg,
	type DecryptedJwt,
	type ExpectedDecryptionProfile,
	type JweHeader,
	type JwtPayLoad,
} from "../types.js";

const MAX_TOKEN_LENGTH = 16384;

// Never honored on a JWE header. `zip` is here for the same reason as on the
// JWS side and then some: an attacker-set `zip: DEF` is a decompression bomb.
const FORBIDDEN_PARAMS = ["jku", "x5u", "jwk", "x5c", "x5t", "zip", "crit"] as const;

function validateJweHeader(raw: Record<string, unknown>, profile: ExpectedDecryptionProfile): JweHeader {
	for (const param of FORBIDDEN_PARAMS) {
		if (param in raw) throw new JWTInvalid(`Token header parameter "${param}" is not supported`);
	}

	const alg = raw.alg;
	if (typeof alg !== "string" || alg.toLowerCase() === "none") {
		throw new AlgorithmNotAllowed("Key-management algorithm 'none' (or a missing alg) is not allowed");
	}
	if (!profile.keyManagementAlgorithms.some((allowed) => (allowed as string) === alg)) {
		throw new AlgorithmNotAllowed("Token key-management algorithm is not in this profile's allowlist");
	}
	getKeyManagementProperties(alg); // defense in depth

	const enc = raw.enc;
	if (typeof enc !== "string" || enc.toLowerCase() === "none") {
		throw new AlgorithmNotAllowed("Content-encryption algorithm 'none' (or a missing enc) is not allowed");
	}
	if (!profile.contentEncryptionAlgorithms.some((allowed) => (allowed as string) === enc)) {
		throw new AlgorithmNotAllowed("Token content-encryption algorithm is not in this profile's allowlist");
	}
	getContentEncryptionProperties(enc);

	const typ = raw.typ;
	if (typeof typ !== "string" || typ.length === 0) {
		throw new JWTInvalid("Token header is missing a typ (explicit typing is mandatory)");
	}
	if (normalizeTyp(typ) !== normalizeTyp(profile.typ)) {
		throw new JWTClaimValidationFailed("typ", "Unexpected token type for this profile");
	}

	const header: JweHeader = { alg: SetAlg(alg), enc: SetAlg(enc), typ };
	if (raw.kid !== undefined) header.kid = sanitizeKid(raw.kid);
	if (raw.cty !== undefined) {
		if (typeof raw.cty !== "string") throw new JWTInvalid("Token header cty must be a string");
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
	if (typeof token !== "string" || token.length === 0) {
		throw new JWTInvalid("Token must be a non-empty string");
	}
	if (token.length > MAX_TOKEN_LENGTH) {
		throw new JWTInvalid("Token exceeds the maximum length");
	}
	const segments = token.split(".");
	if (segments.length !== 5) {
		// A JWS has three segments; anything but five is not a compact JWE.
		throw new JWTInvalid("Token is not a compact JWE (expected five segments)");
	}
	const rawHeader = segments[0] as string;
	if (rawHeader === "") throw new JWTInvalid("Token has an empty header segment");

	const header = validateJweHeader(
		parseJsonObject(decodeUTF8(decodeBase64url(rawHeader)), "header"),
		profile
	);

	if ((profile.key.algorithm as string) !== (header.alg as string)) {
		throw new AlgorithmNotAllowed("Token key-management algorithm does not match the profile's key");
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
		throw new JWTInvalid("Token decryption failed", { cause });
	}

	const payload = parseJsonObject(decodeUTF8(plaintext), "payload");
	await validateClaims(payload, profile);

	if (profile.revocation !== undefined) {
		if (typeof payload.jti !== "string") {
			throw new MissingClaim("jti", "This profile has a revocation store but the token carries no jti");
		}
		let revoked: boolean;
		try {
			revoked = await profile.revocation.isRevoked(buildRevocationContext(payload));
		} catch (cause) {
			if (profile.unsafeFailOpenOnRevocationError === true) {
				revoked = false;
			} else {
				throw new RevocationCheckFailed("Revocation store errored - failing closed (LW-rev.4)", { cause });
			}
		}
		if (revoked) throw new JWTRevoked("Token has been revoked");
	}

	return { header, payload: payload as JwtPayLoad } as DecryptedJwt;
}
