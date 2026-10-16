/**
 * Strict base64url (RFC 7515 §2: no padding, no whitespace, no URL-unsafe
 * characters). Non-canonical encodings are rejected to close parser
 * differentials between Lacewing and other JWT consumers.
 *
 * Written against plain `Uint8Array` rather than Node's `Buffer` so the
 * library runs unchanged in browsers, Deno, Bun and workers. `atob` is no
 * shortcut here: it accepts whitespace and padding, both of which must fail.
 */

import { JWTError } from "../util/errors.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL = /^[A-Za-z0-9_-]*$/;

// Callers have already confined every character to the alphabet with B64URL.
function sextet(encoded: string, index: number): number {
	const c = encoded.charCodeAt(index);
	if (c >= 0x61) return c - 0x61 + 26; // a-z
	if (c >= 0x41) return c === 0x5f ? 63 : c - 0x41; // A-Z, and "_" (0x5f)
	if (c >= 0x30) return c - 0x30 + 52; // 0-9
	return 62; // "-"
}

function char(sixBits: number): string {
	return ALPHABET.charAt(sixBits);
}

export function encodeBase64url(bytes: Uint8Array): string {
	let out = "";
	let i = 0;
	for (; i + 2 < bytes.length; i += 3) {
		const n =
			((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
		out += char(n >> 18) + char((n >> 12) & 63) + char((n >> 6) & 63) + char(n & 63);
	}
	const rest = bytes.length - i;
	if (rest === 1) {
		const n = (bytes[i] as number) << 16;
		out += char(n >> 18) + char((n >> 12) & 63);
	} else if (rest === 2) {
		const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
		out += char(n >> 18) + char((n >> 12) & 63) + char((n >> 6) & 63);
	}
	return out;
}

export function decodeBase64url(encoded: string): Uint8Array {
	if (typeof encoded !== "string" || !B64URL.test(encoded)) {
		throw new JWTError("JWT_INVALID", "Invalid base64url");
	}
	// A single leftover character can never encode a full byte.
	const tail = encoded.length % 4;
	if (tail === 1) {
		throw new JWTError("JWT_INVALID", "Invalid base64url length");
	}
	// Canonical check: the bits of the last character that fall past the final
	// byte must be zero, or two encodings of the same bytes would both verify
	// ("_w" and "_x" both carry 0xff).
	if (tail !== 0) {
		const unused = tail === 2 ? 0b1111 : 0b11;
		if ((sextet(encoded, encoded.length - 1) & unused) !== 0) {
			throw new JWTError("JWT_INVALID", "Non-canonical base64url");
		}
	}
	const bytes = new Uint8Array(Math.floor((encoded.length * 3) / 4));
	let o = 0;
	let i = 0;
	for (; i + 3 < encoded.length; i += 4) {
		const n =
			(sextet(encoded, i) << 18) |
			(sextet(encoded, i + 1) << 12) |
			(sextet(encoded, i + 2) << 6) |
			sextet(encoded, i + 3);
		bytes[o++] = n >> 16;
		bytes[o++] = (n >> 8) & 255;
		bytes[o++] = n & 255;
	}
	if (tail >= 2) {
		const third = tail === 3 ? sextet(encoded, i + 2) << 6 : 0;
		const n = (sextet(encoded, i) << 18) | (sextet(encoded, i + 1) << 12) | third;
		bytes[o++] = n >> 16;
		if (tail === 3) bytes[o] = (n >> 8) & 255;
	}
	return bytes;
}
