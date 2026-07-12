/**
 * @security - revocation store ordering, fail-closed behavior and eviction
 *. The store is a stateful backend an attacker would love to
 * probe or flood; these tests pin down that they cannot.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	SignJWT,
	jwtVerify,
	defineProfile,
	generateSecret,
	MemoryRevocationStore,
	RevocationCheckFailed,
	type ExpectedJwtProfile,
	type RevocationStore,
	type TokenRevocationContext,
} from "../../index.js";
import { craftHmacToken, nowSeconds, standardClaims } from "../helpers.js";

const skip = process.env.LACEWING_SKIP_SECURITY === "1";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";
const hmac = generateSecret("HS256");

function profileWith(store: RevocationStore): ExpectedJwtProfile {
	return defineProfile({
		typ: "at+jwt",
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["HS256"],
		keys: hmac,
		maxTokenAge: "15m",
		revocation: store,
	});
}

class RecordingStore implements RevocationStore {
	calls = 0;
	async isRevoked(_context: TokenRevocationContext): Promise<boolean> {
		this.calls += 1;
		return false;
	}
}

test("@security [LW-rev.3] forged-token flooding never reaches the store", { skip }, async () => {
	const store = new RecordingStore();
	const profile = profileWith(store);
	// 200 tokens with valid structure but bogus signatures.
	for (let i = 0; i < 200; i++) {
		const token = craftHmacToken(
			{ alg: "HS256", typ: "at+jwt" },
			standardClaims({ jti: `forged-${i}` }),
			// A secret the profile does not trust: signatures never verify.
			generateSecret("HS256").key as Uint8Array
		);
		await assert.rejects(jwtVerify(token, profile));
	}
	assert.equal(store.calls, 0, "not one forged token may cause a store lookup");
});

test("@security [LW-rev.4] a store that hangs then times out fails closed", { skip }, async () => {
	const slow: RevocationStore = {
		async isRevoked(): Promise<boolean> {
			await new Promise((resolve) => setTimeout(resolve, 5));
			throw new Error("store timeout");
		},
	};
	const token = await new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m").sign(hmac);
	await assert.rejects(jwtVerify(token, profileWith(slow)), RevocationCheckFailed);
});

test("@security [LW-rev.2] the in-memory store does not treat an expired revocation as live", { skip }, async () => {
	const store = new MemoryRevocationStore();
	const now = nowSeconds();
	// Revoke a jti whose token already expired: the revocation need not outlive it.
	store.revoke("stale-jti", now - 10);
	const revoked = await store.isRevoked({ jti: "stale-jti", exp: now - 10, iat: now - 310 });
	assert.equal(revoked, false, "an expired revocation must not report as revoked");
});
