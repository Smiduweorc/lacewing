/**
 * RFC 8725 §3.5 - ensure cryptographic keys have sufficient entropy. Weak or
 * short HMAC secrets never enter the library; generated secrets always pass.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { importKey, generateSecret, EntropyCheckFailed } from "../../index.js";

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
