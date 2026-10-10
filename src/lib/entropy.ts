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

const HEX = /^[0-9a-f]+$/i;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

// Lowercased QWERTY rows, for spotting keyboard walks like "qazwsx".
const KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];
const KEY_POSITIONS = new Map<string, [number, number]>();
KEYBOARD_ROWS.forEach((row, r) => {
	[...row].forEach((key, c) => KEY_POSITIONS.set(key, [r, c]));
});

function areKeyboardNeighbours(a: string, b: string): boolean {
	const pa = KEY_POSITIONS.get(a);
	const pb = KEY_POSITIONS.get(b);
	if (pa === undefined || pb === undefined) return false;
	const rows = Math.abs(pa[0] - pb[0]);
	const cols = Math.abs(pa[1] - pb[1]);
	return rows + cols > 0 && rows <= 1 && cols <= 1;
}

/**
 * Longest run of consecutive ascending characters ("123456", "abcdef"),
 * counted on the lowercased text.
 */
function longestAscendingRun(text: string): number {
	let longest = 1;
	let run = 1;
	for (let i = 1; i < text.length; i++) {
		run = text.charCodeAt(i) === text.charCodeAt(i - 1) + 1 ? run + 1 : 1;
		longest = Math.max(longest, run);
	}
	return longest;
}

/** Whether the text is one shorter chunk repeated ("deadbeefdeadbeef..."). */
function isPeriodic(text: string): boolean {
	for (let period = 1; period <= text.length / 2; period++) {
		if (text.length % period !== 0) continue;
		if (text.slice(period) === text.slice(0, -period)) return true;
	}
	return false;
}

/** Share of adjacent character pairs that sit next to each other on a keyboard. */
function keyboardWalkRatio(text: string): number {
	let neighbours = 0;
	for (let i = 1; i < text.length; i++) {
		if (areKeyboardNeighbours(text[i - 1] as string, text[i] as string)) neighbours += 1;
	}
	return neighbours / Math.max(1, text.length - 1);
}

/**
 * Bits of key material a printable secret can carry: 4 per character for
 * hex, 6 for base64 or base64url. Anything else is not an encoded random key,
 * so it carries none we can vouch for.
 */
export function encodedSecretBits(text: string): number {
	if (HEX.test(text)) return text.length * 4;
	const unpadded = text.replace(/=+$/, "");
	if (BASE64.test(text) || BASE64URL.test(text)) return unpadded.length * 6;
	return 0;
}

/**
 * Heuristic: does this byte sequence look like a human-chosen password
 * rather than a random key? Only printable-ASCII inputs are suspected -
 * raw random bytes virtually never stay inside that range.
 *
 * A printable secret must look like an encoded random key: hex, base64 or
 * base64url, with no common word, no keyboard walk, and the character spread
 * random output has. Spaces and punctuation fail outright, which also turns
 * away random secrets from generators that add symbols; encode random bytes
 * instead. A passphrase made only of letters and digits can still pass.
 */
export function isPasswordLike(bytes: Uint8Array): boolean {
	const printableAscii = bytes.every((b) => b >= 0x20 && b <= 0x7e);
	if (!printableAscii) {
		return false;
	}
	// Chunked rather than spread: `k` can arrive from a JWKS document, and
	// String.fromCharCode(...megabyte) overflows the call stack.
	let text = "";
	for (let i = 0; i < bytes.length; i += 4096) {
		text += String.fromCharCode(...bytes.subarray(i, i + 4096));
	}
	if (encodedSecretBits(text) === 0) {
		return true;
	}
	const lower = text.toLowerCase();
	const hex = HEX.test(text);
	if (COMMON_WORDS.some((word) => lower.includes(word))) {
		return true;
	}
	// Every threshold below was set against millions of random keys; see
	// the random-key regression test in tests/unit/lib/entropy.test.ts.
	if (isPeriodic(lower) || longestAscendingRun(lower) >= (hex ? 10 : 8)) {
		return true;
	}
	if (keyboardWalkRatio(lower) > 0.6) {
		return true;
	}
	// Random hex sits near 3.8 bits/byte (its ceiling is 4) and random base64
	// near 4.6, so each alphabet gets its own floor.
	return shannonBitsPerByte(bytes) < (hex ? 3 : 3.5);
}

/**
 * Validate an HMAC secret for the given HS* algorithm.
 * Throws {@link EntropyCheckFailed} when the secret is too short or
 * looks like a password.
 *
 * A printable secret is measured by what its encoding carries, not its byte
 * count: 64 hex characters are 64 bytes but only 256 bits of key.
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
	const printable = secret.every((b) => b >= 0x20 && b <= 0x7e);
	if (printable && encodedSecretBits(new TextDecoder().decode(secret)) < minKeyBits) {
		throw new EntropyCheckFailed(
			`HMAC secret for ${algorithmName} must encode at least ${minKeyBits} bits; ` +
				`that is ${Math.ceil(minKeyBits / 4)} hex or ${Math.ceil(minKeyBits / 6)} base64 characters`
		);
	}
}
