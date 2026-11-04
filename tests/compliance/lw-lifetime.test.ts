/**
 * LW-life.1/.2 - token lifetimes are bounded on both ends: the signer cannot
 * mint a token longer than the profile's cap, and the verifier enforces
 * `maxTokenAge` independently of whatever `exp` the token happens to carry.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { EncryptJWT, SignJWT, jwtVerify, newRefreshToken } from "../../index.js";
import { craftHmacToken, nowSeconds, standardClaims, refusal } from "../helpers.js";
import { AUDIENCE, ISSUER, hmac, hmacProfile } from "./_shared.js";

test("[LW-life.1] sign refuses a lifetime beyond the cap (default 1h)", async () => {
	await assert.rejects(
		new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("3650d").sign(hmac),
		refusal("MAX_LIFETIME_EXCEEDED")
	);
	await assert.rejects(
		new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("2h").sign(hmac),
		refusal("MAX_LIFETIME_EXCEEDED")
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

test("[LW-life.1] a cap above 30 days needs unsafeAllowLongLifetime", async () => {
	assert.doesNotThrow(() => new SignJWT("rt+jwt", { maxLifetime: "30d" }));
	assert.throws(() => new SignJWT("rt+jwt", { maxLifetime: 30 * 86400 + 1 }), TypeError);
	assert.throws(() => new SignJWT("rt+jwt", { maxLifetime: "3650d" }), TypeError);
	const token = await new SignJWT("rt+jwt", { maxLifetime: "3650d", unsafeAllowLongLifetime: true })
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.expiresIn("365d")
		.sign(hmac);
	assert.equal(token.split(".").length, 3);
});

test("[LW-life.1] the EncryptJWT cap above 30 days needs unsafeAllowLongLifetime too", () => {
	assert.doesNotThrow(() => new EncryptJWT("at+jwt", { maxLifetime: "30d" }));
	assert.throws(() => new EncryptJWT("at+jwt", { maxLifetime: 30 * 86400 + 1 }), TypeError);
	assert.doesNotThrow(() => new EncryptJWT("at+jwt", { maxLifetime: "90d", unsafeAllowLongLifetime: true }));
});

// Found while triaging the v2.0.1 review: newRefreshToken allowed 90d while
// refreshTokenProfile stopped accepting at 30d.
test("[LW-life.1] the refresh signer never outlives the refresh profile's default age", async () => {
	await assert.rejects(
		newRefreshToken().issuer(ISSUER).audience(AUDIENCE).expiresIn(30 * 86400 + 1).sign(hmac),
		refusal("MAX_LIFETIME_EXCEEDED")
	);
	await assert.doesNotReject(newRefreshToken().issuer(ISSUER).audience(AUDIENCE).expiresIn("30d").sign(hmac));
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
	await assert.rejects(jwtVerify(longLived, hmacProfile({ maxTokenAge: "15m" })), refusal("JWT_EXPIRED"));
});
