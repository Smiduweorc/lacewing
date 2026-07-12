/**
 * RFC 8725 §3.8 - validate the issuer and subject; §3.9 - use and validate the
 * audience. The key source is scoped to the profile (and thus to one issuer),
 * and iss/aud/sub are checked against the profile, never trusted blindly.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { jwtVerify, JWTClaimValidationFailed, MissingClaim } from "../../index.js";
import { craftHmacToken, standardClaims } from "../helpers.js";
import { hmac, hmacProfile } from "./_shared.js";

test("[8725-3.8.1] a token from an untrusted issuer is rejected", async () => {
	const token = craftHmacToken(
		{ alg: "HS256", typ: "at+jwt" },
		standardClaims({ iss: "https://other-tenant.example.com" }),
		hmac.key as Uint8Array
	);
	await assert.rejects(jwtVerify(token, hmacProfile()), JWTClaimValidationFailed);
});

test("[8725-3.8.2] when the profile pins a subject, a mismatched sub is rejected", async () => {
	const profile = hmacProfile({ subject: "user-42" });
	const wrong = craftHmacToken({ alg: "HS256", typ: "at+jwt" }, standardClaims({ sub: "attacker" }), hmac.key as Uint8Array);
	await assert.rejects(jwtVerify(wrong, profile), JWTClaimValidationFailed);
	const right = craftHmacToken({ alg: "HS256", typ: "at+jwt" }, standardClaims({ sub: "user-42" }), hmac.key as Uint8Array);
	const { payload } = await jwtVerify(right, profile);
	assert.equal(payload.sub, "user-42");
});

test("[8725-3.9.1] a missing or mismatched audience is rejected", async () => {
	const mismatched = craftHmacToken({ alg: "HS256", typ: "at+jwt" }, standardClaims({ aud: "https://other-api.example.com" }), hmac.key as Uint8Array);
	await assert.rejects(jwtVerify(mismatched, hmacProfile()), JWTClaimValidationFailed);

	const claims = standardClaims();
	delete (claims as Record<string, unknown>).aud;
	const missing = craftHmacToken({ alg: "HS256", typ: "at+jwt" }, claims, hmac.key as Uint8Array);
	await assert.rejects(jwtVerify(missing, hmacProfile()), MissingClaim);
});
