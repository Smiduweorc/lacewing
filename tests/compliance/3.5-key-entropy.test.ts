/**
 * RFC 8725 §3.5 - ensure cryptographic keys have sufficient entropy. Weak or
 * short HMAC secrets never enter the library; generated secrets always pass.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { importKey, generateSecret, defineProfile, jwtVerify, EntropyCheckFailed } from "../../index.js";
import { craftHmacToken } from "../helpers.js";

test("[8725-3.5.1] HMAC secrets below the algorithm's minimum size are rejected at import", async () => {
	// HS256 needs >= 256 bits (32 bytes). A 16-byte secret is too short.
	await assert.rejects(importKey(new Uint8Array(16).fill(7), "HS256"), EntropyCheckFailed);
	// A generated secret is always long enough by construction.
	const good = generateSecret("HS256");
	assert.equal(good.algorithm, "HS256");
});

test("[8725-3.5.2] human-memorizable passwords are rejected as HMAC secrets", async () => {
	for (const weak of ["secret", "password123", "changeme", "0123456789abcdef"]) {
		await assert.rejects(importKey(weak, "HS256"), EntropyCheckFailed);
	}
});

test("[8725-3.5.2] a custom key source cannot hand back a weak HMAC secret", async () => {
	const weak = new TextEncoder().encode("password-password-password-password");
	const now = Math.floor(Date.now() / 1000);
	const token = craftHmacToken({ alg: "HS256", typ: "at+jwt" }, { iss: "https://auth.example.com", aud: "https://api.example.com", exp: now + 300, iat: now }, weak);
	const profile = defineProfile({
		typ: "at+jwt",
		issuer: "https://auth.example.com",
		audience: "https://api.example.com",
		algorithms: ["HS256"],
		keys: { getVerificationKey: async () => ({ alg: "HS256", key: weak }) } as never,
		maxTokenAge: "15m",
	});
	await assert.rejects(jwtVerify(token, profile), EntropyCheckFailed);
});
