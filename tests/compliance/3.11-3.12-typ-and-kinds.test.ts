/**
 * RFC 8725 §3.11 - use explicit typing; §3.12 - use mutually exclusive
 * validation rules for different kinds of JWT. `typ` is a constructor argument
 * on sign and a required field on every profile, so an access-token profile
 * and a refresh-token profile can never accept each other's tokens.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, jwtVerify, unsafeDecode, JWTClaimValidationFailed } from "../../index.js";
import { AUDIENCE, ISSUER, hmac, hmacProfile } from "./_shared.js";

test("[8725-3.11.1] sign cannot produce a token without an explicit typ", () => {
	// `typ` is the constructor's first argument - omitting it is a TypeError,
	// not a silent default.
	assert.throws(() => new SignJWT("" as string), TypeError);
	assert.throws(() => new SignJWT(undefined as unknown as string), TypeError);
});

test("[8725-3.11.1] every issued token carries the typ it was constructed with", async () => {
	const token = await new SignJWT("at+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.expiresIn("5m")
		.sign(hmac);
	assert.equal(unsafeDecode(token).header.typ, "at+jwt");
});

test("[8725-3.11.2] the verifier rejects a token whose typ is not the profile's", async () => {
	const refresh = await new SignJWT("rt+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.expiresIn("5m")
		.sign(hmac);
	// hmacProfile() expects "at+jwt".
	await assert.rejects(jwtVerify(refresh, hmacProfile()), JWTClaimValidationFailed);
});

test("[8725-3.12.1] access and refresh profiles are mutually exclusive by typ", async () => {
	const accessProfile = hmacProfile({ typ: "at+jwt" });
	const refreshProfile = hmacProfile({ typ: "rt+jwt" });

	const access = await new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m").sign(hmac);
	const refresh = await new SignJWT("rt+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m").sign(hmac);

	// Each profile accepts its own kind...
	assert.equal((await jwtVerify(access, accessProfile)).header.typ, "at+jwt");
	assert.equal((await jwtVerify(refresh, refreshProfile)).header.typ, "rt+jwt");
	// ...and refuses the other's, even though the key and claims are identical.
	await assert.rejects(jwtVerify(refresh, accessProfile), JWTClaimValidationFailed);
	await assert.rejects(jwtVerify(access, refreshProfile), JWTClaimValidationFailed);
});
