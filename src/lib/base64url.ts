/**
 * Strict base64url (RFC 7515 §2: no padding, no whitespace, no URL-unsafe
 * characters). Non-canonical encodings are rejected to close parser
 * differentials between Lacewing and other JWT consumers.
 */

import { Buffer } from "node:buffer";
import { JWTInvalid } from "../util/errors.js";

const B64URL = /^[A-Za-z0-9_-]*$/;

export function encodeBase64url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("base64url");
}

export function decodeBase64url(encoded: string): Uint8Array {
	if (typeof encoded !== "string" || !B64URL.test(encoded)) {
		throw new JWTInvalid("Invalid base64url");
	}
	// A single leftover character can never encode a full byte.
	if (encoded.length % 4 === 1) {
		throw new JWTInvalid("Invalid base64url length");
	}
	const bytes = Buffer.from(encoded, "base64url");
	// Canonical check: trailing bits that don't round-trip are rejected
	// (two encodings of the same bytes would otherwise both verify).
	if (bytes.toString("base64url") !== encoded) {
		throw new JWTInvalid("Non-canonical base64url");
	}
	return new Uint8Array(bytes);
}
