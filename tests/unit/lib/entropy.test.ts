import { test } from "node:test";
import assert from "node:assert/strict";
import { refusal } from "../../helpers.js";
import fc from "fast-check";
import { isPasswordLike, validateHMACSecret } from "../../../src/lib/entropy.js";
import { resolveAlgorithm } from "../../../src/lib/algorithms.js";

const encoder = new TextEncoder();

test("[8725-3.5.1] random 256-bit secrets pass for HS256", () => {
	const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
	assert.doesNotThrow(() => validateHMACSecret(secret, resolveAlgorithm("HS256")));
});

test("[8725-3.5.1] minimum length scales with the algorithm", () => {
	const secret48 = globalThis.crypto.getRandomValues(new Uint8Array(48));
	assert.doesNotThrow(() => validateHMACSecret(secret48, resolveAlgorithm("HS384")));
	assert.throws(() => validateHMACSecret(secret48, resolveAlgorithm("HS512")), refusal("ENTROPY_CHECK_FAILED"));
});

test("[8725-3.5.1] 128-bit secrets are rejected", () => {
	const secret = globalThis.crypto.getRandomValues(new Uint8Array(16));
	assert.throws(() => validateHMACSecret(secret, resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
});

test("[8725-3.5.2] obvious passwords are rejected even when long enough", () => {
	const passwords = [
		"password-password-password-password",
		"my-super-secret-signing-key-please-dont-guess",
		"correct horse battery staple correct horse battery",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"qwertyqwertyqwertyqwertyqwertyqwerty",
	];
	for (const password of passwords) {
		assert.throws(
			() => validateHMACSecret(encoder.encode(password), resolveAlgorithm("HS256")),
			refusal("ENTROPY_CHECK_FAILED"),
			`expected rejection: ${password}`
		);
	}
});

test("hex- and base64-encoded random keys are not flagged as passwords", () => {
	const random = globalThis.crypto.getRandomValues(new Uint8Array(32));
	const hex = Buffer.from(random).toString("hex");
	const base64 = Buffer.from(random).toString("base64");
	assert.equal(isPasswordLike(encoder.encode(hex)), false);
	assert.equal(isPasswordLike(encoder.encode(base64)), false);
	assert.doesNotThrow(() => validateHMACSecret(encoder.encode(hex), resolveAlgorithm("HS256")));
});

test("raw random bytes are never password-like", () => {
	const random = globalThis.crypto.getRandomValues(new Uint8Array(32));
	// Force at least one byte outside printable ASCII to avoid flakes.
	random[0] = 0x01;
	assert.equal(isPasswordLike(random), false);
});

test("a megabyte of printable bytes is screened without blowing the stack", () => {
	// `k` can arrive from a JWKS document, so this path takes attacker-sized
	// input; String.fromCharCode(...bytes) used to overflow here.
	const huge = encoder.encode("a".repeat(1_000_000));
	assert.equal(isPasswordLike(huge), true);
	assert.throws(() => validateHMACSecret(huge, resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
});

test("[8725-3.5.2] passphrases and keyboard walks are rejected even when long enough", () => {
	const humanChosen = [
		"correct-horse-battery-staple-9!-Zq",
		"MyDogSpotLovesChasingSquirrels2024!!",
		"qazwsxedcrfvtgbyhnujmikolpQAZWSXEDqazwsxedcrfvtgb",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"deadbeef".repeat(8),
		"abcdefghijk".repeat(4),
	];
	for (const secret of humanChosen) {
		assert.throws(() => validateHMACSecret(encoder.encode(secret), resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"), `expected rejection: ${secret}`);
	}
});

test("[8725-3.5.2] a printable secret is measured by the bits its encoding carries, not its byte count", () => {
	const random = globalThis.crypto.getRandomValues(new Uint8Array(32));
	const hex = Buffer.from(random).toString("hex");
	// 64 hex characters carry 256 bits: exactly HS256, one character short is not.
	assert.doesNotThrow(() => validateHMACSecret(encoder.encode(hex), resolveAlgorithm("HS256")));
	assert.throws(() => validateHMACSecret(encoder.encode(hex.slice(0, 63)), resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
	// 32 hex characters were accepted before: 32 bytes long, but only 128 bits.
	assert.throws(() => validateHMACSecret(encoder.encode(hex.slice(0, 32)), resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
	// 43 base64url characters carry 258 bits; 42 carry 252.
	const b64 = Buffer.from(random).toString("base64url");
	assert.doesNotThrow(() => validateHMACSecret(encoder.encode(b64), resolveAlgorithm("HS256")));
	assert.throws(() => validateHMACSecret(encoder.encode(b64.slice(0, 42)), resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
});

test("[8725-3.5.2] secrets with spaces or punctuation are not an encoded random key and are rejected", () => {
	const random = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(48))).toString("base64url");
	assert.throws(() => validateHMACSecret(encoder.encode(`${random}!`), resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
	assert.throws(() => validateHMACSecret(encoder.encode(`${random} x`), resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
});

test("random hex and base64 keys are never flagged, over many samples", () => {
	// The thresholds were tuned against a 7M-key sweep; this keeps a cheap
	// regression check in the suite. The old 3.5 bits/byte floor failed here.
	// The keys come from a fixed seed: a uniformly random base64 key contains
	// a COMMON_WORDS entry such as "secret" about once in 14 million draws
	// (case folding makes each letter a 1-in-32 match), and that rejection is
	// intended, so an unseeded sample could fail on a key that deserved it.
	fc.assert(
		fc.property(fc.noBias(fc.uint8Array({ minLength: 32, maxLength: 32 })), (bytes) => {
			const random = Buffer.from(bytes);
			for (const encoded of [random.toString("hex"), random.toString("hex").toUpperCase(), random.toString("base64"), random.toString("base64url")]) {
				assert.doesNotThrow(() => validateHMACSecret(encoder.encode(encoded), resolveAlgorithm("HS256")), encoded);
			}
		}),
		{ numRuns: 20000, seed: 8725 }
	);
});

test("a random key whose base64 happens to spell a common word is rejected", () => {
	// Why the many-samples test above is seeded: this is a real 32-byte key,
	// and the word check refuses it on purpose.
	const bytes = Buffer.from("x7SeCrEtq0Zp4LmN2vB8wK1yR5tH9jD3fG6aQcU0oIs=", "base64");
	assert.equal(bytes.length, 32);
	assert.equal(isPasswordLike(encoder.encode(bytes.toString("base64"))), true);
	assert.throws(() => validateHMACSecret(encoder.encode(bytes.toString("base64")), resolveAlgorithm("HS256")), refusal("ENTROPY_CHECK_FAILED"));
	assert.doesNotThrow(() => validateHMACSecret(encoder.encode(bytes.toString("hex")), resolveAlgorithm("HS256")));
});
