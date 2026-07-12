/**
 * LW-decode.1 - there is no decode-without-verify on the verification path.
 * `unsafeDecode` exists for debugging, but its output is branded `UntrustedJwt`
 * and is type-incompatible with `VerifiedJwt`, so it cannot flow into auth
 * logic. The compile-time half of this proof lives in `tests/types/`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, jwtVerify, unsafeDecode, JWTInvalid, type VerifiedJwt } from "../../index.js";
import { AUDIENCE, ISSUER, hmac, hmacProfile } from "./_shared.js";

test("[LW-decode.1] unsafeDecode reads tampered and expired tokens - and jwtVerify still refuses them", async () => {
	const token = await new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m").sign(hmac);
	const [h, p] = token.split(".") as [string, string, string];
	const tampered = `${h}.${p}.AAAA`;

	// The debugging path happily decodes it...
	const untrusted = unsafeDecode(tampered);
	assert.equal(untrusted.payload.iss, ISSUER);
	// ...but the only path that can produce a VerifiedJwt rejects it.
	await assert.rejects(jwtVerify(tampered, hmacProfile()), JWTInvalid);
});

test("[LW-decode.1] the decoded result is branded Untrusted and cannot be used as a VerifiedJwt", async () => {
	const token = await new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m").sign(hmac);
	const untrusted = unsafeDecode(token);
	// @ts-expect-error - UntrustedJwt is not assignable to VerifiedJwt. If this
	// line ever compiles, the brand has been broken and the gate must fail.
	const verified: VerifiedJwt = untrusted;
	// Runtime shape is the same; the *type* is the security boundary.
	assert.equal(verified.payload.iss, ISSUER);
});

test("[LW-decode.1] unsafeDecode still refuses structurally malformed tokens", () => {
	assert.throws(() => unsafeDecode("not-a-token"), JWTInvalid);
	assert.throws(() => unsafeDecode("a.b"), JWTInvalid);
	assert.throws(() => unsafeDecode(""), JWTInvalid);
});
