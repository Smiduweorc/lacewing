/**
 * LW-payload.1/.2 - a JWS payload is base64url-encoded *plaintext*. The
 * sign-time hygiene scanner refuses claim names that look sensitive and claim
 * values that match high-confidence secret patterns, at any nesting depth.
 * (LW-payload.3, the documentation requirement, is proved in `docs.test.ts`.)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, PayloadHygieneViolation } from "../../index.js";
import { AUDIENCE, ISSUER, hmac } from "./_shared.js";

function signWith(claim: string, value: unknown): Promise<string> {
	return new SignJWT("at+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.expiresIn("5m")
		.claim(claim, value)
		.sign(hmac);
}

test("[LW-payload.1] claim names matching the sensitive-name heuristic are refused", async () => {
	for (const name of ["password", "user_secret", "apiKey", "ssn", "creditCard", "cvv", "authorization"]) {
		await assert.rejects(signWith(name, "anything"), PayloadHygieneViolation, `claim: ${name}`);
	}
});

test("[LW-payload.1] nesting is not a blind spot - a sensitive name deep in a value is still caught", async () => {
	await assert.rejects(signWith("profile", { contact: { password: "hunter2" } }), PayloadHygieneViolation);
	await assert.rejects(signWith("items", [{ ok: 1 }, { apiKey: "x" }]), PayloadHygieneViolation);
});

test("[LW-payload.2] high-confidence secret *values* are refused (PEM, nested JWT, Luhn card)", async () => {
	await assert.rejects(
		signWith("blob", "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"),
		PayloadHygieneViolation
	);
	await assert.rejects(
		signWith("upstream", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
		PayloadHygieneViolation
	);
	// 4111111111111111 is the canonical Luhn-valid test Visa number.
	await assert.rejects(signWith("payment", "4111111111111111"), PayloadHygieneViolation);
});

test("[LW-payload.1] a false positive can be waived, loudly and per claim", async () => {
	const token = await new SignJWT("at+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.expiresIn("5m")
		.claim("token_use", "access") // matches the "token" fragment
		.unsafeAllowClaim("token_use")
		.sign(hmac);
	assert.equal(typeof token, "string");
});

test("[LW-payload.1] an ordinary payload signs without complaint", async () => {
	const token = await signWith("scope", "read:things");
	assert.equal(token.split(".").length, 3);
});
