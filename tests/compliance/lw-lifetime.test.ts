/**
 * LW-life.1/.2 - token lifetimes are bounded on both ends: the signer cannot
 * mint a token longer than the profile's cap, and the verifier enforces
 * `maxTokenAge` independently of whatever `exp` the token happens to carry.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, jwtVerify, MaxLifetimeExceeded, JWTExpired } from "../../index.js";
import { craftHmacToken, nowSeconds, standardClaims } from "../helpers.js";
import { AUDIENCE, ISSUER, hmac, hmacProfile } from "./_shared.js";

test("[LW-life.1] sign refuses a lifetime beyond the cap (default 1h)", async () => {
	await assert.rejects(
		new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("3650d").sign(hmac),
		MaxLifetimeExceeded
	);
	await assert.rejects(
		new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("2h").sign(hmac),
		MaxLifetimeExceeded
	);
});

test("[LW-life.1] raising the cap is possible, but it is an explicit, visible choice", async () => {
	const token = await new SignJWT("rt+jwt", { maxLifetime: "30d" })
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.expiresIn("7d")
		.sign(hmac);
	assert.equal(token.split(".").length, 3);
});

test("[LW-life.2] verify enforces maxTokenAge even when exp is far in the future", async () => {
	// A compromised or over-generous signer emits a 10-year token. The profile
	// caps accepted age at 15 minutes, so it is refused on age alone - exp is
	// perfectly valid here.
	const now = nowSeconds();
	const longLived = craftHmacToken(
		{ alg: "HS256", typ: "at+jwt" },
		standardClaims({ iat: now - 3600, exp: now + 10 * 365 * 24 * 3600 }),
		hmac.key as Uint8Array
	);
	await assert.rejects(jwtVerify(longLived, hmacProfile({ maxTokenAge: "15m" })), JWTExpired);
});
