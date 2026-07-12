/**
 * HMAC secret strength checks (RFC 8725 §3.5).
 *
 * Two gates at import time:
 *  1. Minimum length per algorithm (RFC 7518: >= hash output size).
 *  2. A heuristic that rejects password-looking strings - the classic
 *     `secret: "my-secret"` misuse - even when they are long enough.
 */

import { EntropyCheckFailed } from "../util/errors.js";
import { getAlgorithmProperties } from "./algorithms.js";

// Substrings that only ever show up in human-chosen secrets.
const COMMON_WORDS = [
	"password",
	"passwort",
	"secret",
	"letmein",
	"qwerty",
	"123456",
	"abcdef",
	"changeme",
	"default",
];

function shannonBitsPerByte(bytes: Uint8Array): number {
	const counts = new Map<number, number>();
	for (const byte of bytes) {
		counts.set(byte, (counts.get(byte) ?? 0) + 1);
	}
	let bits = 0;
	for (const count of counts.values()) {
		const p = count / bytes.length;
		bits -= p * Math.log2(p);
	}
	return bits;
}

/**
 * Heuristic: does this byte sequence look like a human-chosen password
 * rather than a random key? Only printable-ASCII inputs are suspected -
 * raw random bytes virtually never stay inside that range.
 */
export function isPasswordLike(bytes: Uint8Array): boolean {
	const printableAscii = bytes.every((b) => b >= 0x20 && b <= 0x7e);
	if (!printableAscii) {
		return false;
	}
	const text = String.fromCharCode(...bytes).toLowerCase();
	if (COMMON_WORDS.some((word) => text.includes(word))) {
		return true;
	}
	// Random keys encoded as hex/base64 sit well above 3.5 bits/byte at
	// these lengths; keyboard-pattern and dictionary strings sit below.
	return shannonBitsPerByte(bytes) < 3.5;
}

/**
 * Validate an HMAC secret for the given HS* algorithm.
 * Throws {@link EntropyCheckFailed} when the secret is too short or
 * looks like a password.
 */
export function validateHMACSecret(secret: Uint8Array, algorithmName: string): void {
	const { minKeyBits } = getAlgorithmProperties(algorithmName);
	const minBytes = Math.ceil(minKeyBits / 8);
	if (secret.length < minBytes) {
		throw new EntropyCheckFailed(
			`HMAC secret for ${algorithmName} must be at least ${minBytes} bytes ` +
				"of cryptographically random data"
		);
	}
	if (isPasswordLike(secret)) {
		throw new EntropyCheckFailed(
			"HMAC secret looks like a human-chosen password; use " +
				"cryptographically random bytes (e.g. generateSecret())"
		);
	}
}
