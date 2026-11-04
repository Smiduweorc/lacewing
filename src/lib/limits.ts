/**
 * The size bounds a token has to fit, shared by the side that makes tokens
 * and the side that checks them. A signer that emits what its own verifier
 * refuses hands the caller a token that fails only once it is in use, so
 * `SignJWT` and `EncryptJWT` refuse up front everything `jwtVerify` and
 * `jwtDecrypt` would.
 */

import { assertNoDuplicateKeys } from "./json.js";

/** Longest compact token accepted, checked before any parsing so garbage can't allocate unboundedly. */
export const MAX_TOKEN_LENGTH = 16384;

/** Longest `iss`, `sub` or `jti` accepted. */
export const MAX_STRING_CLAIM_LENGTH = 1024;

const CAPPED_CLAIMS = ["iss", "sub", "jti"] as const;

/**
 * Refuse a payload the verifier would refuse: a capped claim that is too
 * long, or a `__proto__`/`constructor`/`prototype` member at any depth (the
 * verifier rejects those as prototype-pollution vectors). `json` is the
 * exact text about to be signed or encrypted.
 */
export function assertPayloadIsVerifiable(payload: Record<string, unknown>, json: string, builder: string): void {
	for (const claim of CAPPED_CLAIMS) {
		const value = payload[claim];
		if (typeof value === "string" && value.length > MAX_STRING_CLAIM_LENGTH) {
			throw new TypeError(
				`${builder}: "${claim}" is longer than ${MAX_STRING_CLAIM_LENGTH} characters, which verification refuses`
			);
		}
	}
	try {
		assertNoDuplicateKeys(json, "payload");
	} catch {
		throw new TypeError(
			`${builder}: the payload has a member named __proto__, constructor or prototype, which verification refuses`
		);
	}
}

/** Refuse a finished token longer than verification accepts. */
export function assertTokenIsVerifiable(token: string, builder: string): string {
	if (token.length > MAX_TOKEN_LENGTH) {
		throw new TypeError(
			`${builder}: the token is ${token.length} characters, over the ${MAX_TOKEN_LENGTH} verification accepts`
		);
	}
	return token;
}
