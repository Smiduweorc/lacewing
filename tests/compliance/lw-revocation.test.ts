/**
 * LW-rev.1–.4 - stateless JWTs get revocation as a first-class feature, not
 * homework: every token carries a `jti`, profiles take a store, the store is
 * consulted *only after* signature and claims pass, and store errors fail
 * closed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	SignJWT,
	jwtVerify,
	unsafeDecode,
	MemoryRevocationStore,
	JWTRevoked,
	JWTInvalid,
	JWTExpired,
	RevocationCheckFailed,
	type RevocationStore,
	type TokenRevocationContext,
} from "../../index.js";
import { craftHmacToken, nowSeconds, standardClaims } from "../helpers.js";
import { AUDIENCE, ISSUER, hmac, hmacProfile } from "./_shared.js";

function sign(build: (b: SignJWT) => SignJWT = (b) => b): Promise<string> {
	return build(new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m")).sign(hmac);
}

/** A store that records every call, so we can assert *when* it is consulted. */
class RecordingStore implements RevocationStore {
	readonly calls: TokenRevocationContext[] = [];
	async isRevoked(context: TokenRevocationContext): Promise<boolean> {
		this.calls.push(context);
		return false;
	}
}

test("[LW-rev.1] every signed token carries a unique jti by default", async () => {
	const a = unsafeDecode(await sign()).payload.jti;
	const b = unsafeDecode(await sign()).payload.jti;
	assert.equal(typeof a, "string");
	assert.notEqual(a, b);
});

test("[LW-rev.2] a revoked jti is rejected on the next verification", async () => {
	const revocation = new MemoryRevocationStore();
	const profile = hmacProfile({ revocation });
	const token = await sign();
	const { payload } = await jwtVerify(token, profile); // fine before revocation

	revocation.revoke(payload.jti as string, payload.exp);
	await assert.rejects(jwtVerify(token, profile), JWTRevoked);
});

test("[LW-rev.3] the store is never consulted for a token that fails signature or claims", async () => {
	const store = new RecordingStore();
	const profile = hmacProfile({ revocation: store });

	// Forged signature.
	const good = await sign();
	const [h, p] = good.split(".") as [string, string, string];
	await assert.rejects(jwtVerify(`${h}.${p}.AAAA`, profile), JWTInvalid);
	assert.equal(store.calls.length, 0, "a forged token must not reach the store");

	// Valid signature, but expired - claims fail before the store is asked.
	const now = nowSeconds();
	const expired = craftHmacToken(
		{ alg: "HS256", typ: "at+jwt" },
		standardClaims({ iat: now - 600, exp: now - 300 }),
		hmac.key as Uint8Array
	);
	await assert.rejects(jwtVerify(expired, profile), JWTExpired);
	assert.equal(store.calls.length, 0, "an expired token must not reach the store");

	// A fully valid token does reach it.
	await jwtVerify(good, profile);
	assert.equal(store.calls.length, 1);
});

test("[LW-rev.4] a store that errors fails closed", async () => {
	const exploding: RevocationStore = {
		async isRevoked(): Promise<boolean> {
			throw new Error("redis is down");
		},
	};
	const token = await sign();
	await assert.rejects(jwtVerify(token, hmacProfile({ revocation: exploding })), RevocationCheckFailed);
});

test("[LW-rev.4] failing open is possible, but only through a deliberately ugly flag", async () => {
	const exploding: RevocationStore = {
		async isRevoked(): Promise<boolean> {
			throw new Error("redis is down");
		},
	};
	const token = await sign();
	const profile = hmacProfile({ revocation: exploding, unsafeFailOpenOnRevocationError: true });
	const { payload } = await jwtVerify(token, profile);
	assert.equal(payload.iss, ISSUER);
});
