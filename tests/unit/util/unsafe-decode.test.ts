import { test } from "node:test";
import assert from "node:assert/strict";
import { unsafeDecode } from "../../../src/util/unsafe-decode.js";
import { SignJWT } from "../../../src/jwt/sign.js";
import { generateSecret } from "../../../src/key/generate.js";
import { JWTInvalid } from "../../../src/util/errors.js";
import { craftHmacToken, craftUnsignedToken, nowSeconds } from "../../helpers.js";
import type { UntrustedJwt, VerifiedJwt } from "../../../src/types.js";

const secret = generateSecret("HS256");

test("[LW-decode.1] decodes without verifying - tampered and expired tokens included", () => {
	const expired = craftHmacToken(
		{ alg: "HS256", typ: "at+jwt" },
		{ iss: "i", aud: "a", exp: nowSeconds() - 9999, iat: nowSeconds() - 10_000, jti: "x" },
		secret.key as Uint8Array
	);
	const decoded = unsafeDecode(expired);
	assert.equal(decoded.payload.iss, "i");
	// Tampered signature decodes fine - nothing here is trusted.
	const tampered = `${expired.slice(0, -4)}AAAA`;
	assert.equal(unsafeDecode(tampered).payload.iss, "i");
	// Even an alg:none token decodes (it can never verify).
	const none = craftUnsignedToken({ alg: "none", typ: "JWT" }, { iss: "i" }, "sig");
	assert.equal(unsafeDecode(none).payload.iss, "i");
});

test("[LW-decode.1] the result is branded Untrusted and incompatible with VerifiedJwt", async () => {
	const token = await new SignJWT("at+jwt")
		.issuer("i")
		.audience("a")
		.expiresIn(60)
		.sign(secret);
	const untrusted: UntrustedJwt = unsafeDecode(token);
	// @ts-expect-error - UntrustedJwt must never flow into VerifiedJwt positions
	const impossible: VerifiedJwt = untrusted;
	void impossible;
	assert.equal(untrusted.payload.iss, "i");
});

test("malformed structure still throws (strict base64url/UTF-8/JSON)", () => {
	for (const input of ["", "a.b", "a.b.c.d", "!!.!!.!!", "eyJ=.e30.x"]) {
		assert.throws(() => unsafeDecode(input), JWTInvalid);
	}
	assert.throws(() => unsafeDecode("x".repeat(100_000)), JWTInvalid);
});
