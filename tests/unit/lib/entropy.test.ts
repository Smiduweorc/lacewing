import { test } from "node:test";
import assert from "node:assert/strict";
import { isPasswordLike, validateHMACSecret } from "../../../src/lib/entropy.js";
import { EntropyCheckFailed } from "../../../src/util/errors.js";

const encoder = new TextEncoder();

test("[8725-3.5.1] random 256-bit secrets pass for HS256", () => {
	const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
	assert.doesNotThrow(() => validateHMACSecret(secret, "HS256"));
});

test("[8725-3.5.1] minimum length scales with the algorithm", () => {
	const secret48 = globalThis.crypto.getRandomValues(new Uint8Array(48));
	assert.doesNotThrow(() => validateHMACSecret(secret48, "HS384"));
	assert.throws(() => validateHMACSecret(secret48, "HS512"), EntropyCheckFailed);
});

test("[8725-3.5.1] 128-bit secrets are rejected", () => {
	const secret = globalThis.crypto.getRandomValues(new Uint8Array(16));
	assert.throws(() => validateHMACSecret(secret, "HS256"), EntropyCheckFailed);
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
			() => validateHMACSecret(encoder.encode(password), "HS256"),
			EntropyCheckFailed,
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
	assert.doesNotThrow(() => validateHMACSecret(encoder.encode(hex), "HS256"));
});

test("raw random bytes are never password-like", () => {
	const random = globalThis.crypto.getRandomValues(new Uint8Array(32));
	// Force at least one byte outside printable ASCII to avoid flakes.
	random[0] = 0x01;
	assert.equal(isPasswordLike(random), false);
});
