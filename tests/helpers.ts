/** Shared test utilities: crafting arbitrary (including malicious) tokens. */

import { Buffer } from "node:buffer";
import { createHmac } from "node:crypto";

export function nowSeconds(): number {
	return Math.floor(Date.now() / 1000);
}

export function b64uJson(value: unknown): string {
	return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function b64u(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

const HMAC_HASH: Record<string, string> = {
	HS256: "sha256",
	HS384: "sha384",
	HS512: "sha512",
};

/** Craft a real HMAC-signed token with full control over header/payload. */
export function craftHmacToken(
	header: Record<string, unknown>,
	payload: Record<string, unknown>,
	secret: Uint8Array,
	alg: string = "HS256"
): string {
	const signingInput = `${b64uJson(header)}.${b64uJson(payload)}`;
	const signature = createHmac(HMAC_HASH[alg] as string, secret)
		.update(signingInput)
		.digest();
	return `${signingInput}.${b64u(signature)}`;
}

/**
 * Craft a real HMAC-signed token from *raw* header/payload JSON text, so the
 * exact byte sequence (duplicate keys, whitespace, non-canonical numbers) is
 * under the test's control - `JSON.stringify` would normalize these away.
 */
export function craftHmacTokenRaw(
	headerJson: string,
	payloadJson: string,
	secret: Uint8Array,
	alg: string = "HS256"
): string {
	const signingInput = `${Buffer.from(headerJson).toString("base64url")}.${Buffer.from(payloadJson).toString("base64url")}`;
	const signature = createHmac(HMAC_HASH[alg] as string, secret)
		.update(signingInput)
		.digest();
	return `${signingInput}.${b64u(signature)}`;
}

/** Craft a token with an arbitrary (e.g. empty or bogus) signature segment. */
export function craftUnsignedToken(
	header: Record<string, unknown>,
	payload: Record<string, unknown>,
	signature: string = ""
): string {
	return `${b64uJson(header)}.${b64uJson(payload)}.${signature}`;
}

/** A standard well-formed claim set for the default test profile. */
export function standardClaims(
	overrides: Record<string, unknown> = {}
): Record<string, unknown> {
	const now = nowSeconds();
	return {
		iss: "https://auth.example.com",
		aud: "https://api.example.com",
		sub: "user-42",
		jti: "test-jti-1",
		iat: now,
		exp: now + 300,
		...overrides,
	};
}

/** Expect an error that is an instance of `type` with the given `code`. */
export function errorWithCode(
	type: abstract new (...args: never[]) => Error,
	code: string
): (error: unknown) => boolean {
	return (error: unknown): boolean =>
		error instanceof type && (error as { code?: string }).code === code;
}
