/**
 * DANGER: decode-without-verify, for debugging and inspection only.
 */

import { JWTInvalid } from "./errors.js";
import { decodeBase64url } from "../lib/base64url.js";
import { decodeUTF8 } from "../lib/utf8.js";
import { parseJsonObject } from "../lib/json.js";
import type { JwtHeader, JwtPayLoad, UntrustedJwt } from "../types.js";

const MAX_TOKEN_LENGTH = 16384;

function parseSegment(segment: string, what: string): Record<string, unknown> {
	return parseJsonObject(decodeUTF8(decodeBase64url(segment)), what);
}

/**
 * DANGER: Decodes a JWT **without verifying the signature** and without
 * validating a single claim - expired, forged and `alg: none` tokens all
 * decode successfully. The returned {@link UntrustedJwt} is type-branded
 * and incompatible with `VerifiedJwt`, so it cannot flow into
 * authentication logic. Never base an auth decision on it.
 *
 * Legitimate uses: inspecting expired tokens while debugging, examining
 * token structure without the key, observability of token contents.
 * Since the token is unverified, fields the types mark mandatory may be
 * absent at runtime.
 *
 * Throws only on malformed structure (base64url / UTF-8 / JSON) - never
 * because a signature is missing or wrong.
 */
export function unsafeDecode(token: string): UntrustedJwt {
	if (typeof token !== "string" || token.length === 0) {
		throw new JWTInvalid("Token must be a non-empty string");
	}
	if (token.length > MAX_TOKEN_LENGTH) {
		throw new JWTInvalid("Token exceeds the maximum length");
	}
	const segments = token.split(".");
	if (segments.length !== 3) {
		throw new JWTInvalid("Token must have exactly three segments");
	}
	const [rawHeader, rawPayload] = segments as [string, string, string];
	// Deliberately no allowlist, typ, or kid checks here - this is a raw
	// view of untrusted data, and the brand says exactly that.
	const header = parseSegment(rawHeader, "header") as unknown as JwtHeader;
	const payload = parseSegment(rawPayload, "payload") as unknown as JwtPayLoad;
	return { header, payload } as UntrustedJwt;
}
