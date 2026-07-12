/**
 * Property: revocation soundness (LW-rev).
 *
 *  - Revoking *other* jtis never affects a token: verification is identical
 *    whether the store is empty or holds only unrelated revocations.
 *  - Revoking a token's own jti always causes the next verification to fail.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
	SignJWT,
	jwtVerify,
	unsafeDecode,
	defineProfile,
	generateSecret,
	MemoryRevocationStore,
	JWTRevoked,
	type ExpectedJwtProfile,
	type RevocationStore,
} from "../../index.js";

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

function freshToken(): Promise<string> {
	return new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).subject("user-42").expiresIn("5m").sign(hmac);
}

const otherJtis = fc.array(fc.string({ minLength: 1, maxLength: 24 }), { maxLength: 6 });

test("[LW-rev.2] revoking unrelated jtis never affects an untouched token", async () => {
	await fc.assert(
		fc.asyncProperty(otherJtis, async (jtis) => {
			const token = await freshToken();
			const jti = unsafeDecode(token).payload.jti as string;
			const store = new MemoryRevocationStore();
			for (const other of jtis) {
				if (other !== jti) store.revoke(other, Math.floor(Date.now() / 1000) + 3600);
			}
			const { payload } = await jwtVerify(token, profileWith(store));
			assert.equal(payload.jti, jti);
		}),
		{ numRuns: 30 }
	);
});

test("[LW-rev.2] revoking a token's own jti always rejects the next verification", async () => {
	await fc.assert(
		fc.asyncProperty(fc.constant(null), async () => {
			const token = await freshToken();
			const payload = unsafeDecode(token).payload;
			const store = new MemoryRevocationStore();
			store.revoke(payload.jti as string, payload.exp);
			await assert.rejects(jwtVerify(token, profileWith(store)), JWTRevoked);
		}),
		{ numRuns: 15 }
	);
});
