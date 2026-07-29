import { test } from "node:test";
import assert from "node:assert/strict";
import { scanPayloadForSensitiveData } from "../../../src/lib/payload_hygiene.js";
import { PayloadHygieneViolation } from "../../../src/util/errors.js";

test("[LW-payload.1] sensitive claim names are rejected", () => {
	const payloads = [
		{ password: "hunter2" },
		{ Password: "hunter2" },
		{ user_password: "hunter2" },
		{ api_key: "abc" },
		{ apiKey: "abc" },
		{ clientSecret: "abc" },
		{ ssn: "078-05-1120" },
		{ creditCard: "x" },
		{ "credit-card-number": "x" },
		{ cvv: "123" },
		{ refresh_token: "x" },
		{ authorization: "x" },
	];
	for (const payload of payloads) {
		assert.throws(
			() => scanPayloadForSensitiveData(payload),
			PayloadHygieneViolation,
			`expected rejection: ${Object.keys(payload)[0]}`
		);
	}
});

test("[LW-payload.1] nested sensitive names have no blind spots", () => {
	assert.throws(
		() => scanPayloadForSensitiveData({ profile: { settings: { apiKey: "x" } } }),
		PayloadHygieneViolation
	);
	assert.throws(
		() => scanPayloadForSensitiveData({ items: [{ password: "x" }] }),
		PayloadHygieneViolation
	);
});

test("[LW-payload.2] Luhn-valid card numbers are rejected, with separators too", () => {
	for (const card of ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111"]) {
		assert.throws(
			() => scanPayloadForSensitiveData({ note: card }),
			PayloadHygieneViolation
		);
	}
	// Luhn-invalid digit strings are allowed (could be an order id).
	assert.doesNotThrow(() => scanPayloadForSensitiveData({ note: "4111111111111112" }));
});

test("[LW-payload.2] PEM private-key blocks are rejected", () => {
	assert.throws(
		() =>
			scanPayloadForSensitiveData({
				config: "-----BEGIN PRIVATE KEY-----\nMC4C...\n-----END PRIVATE KEY-----",
			}),
		PayloadHygieneViolation
	);
	assert.throws(
		() => scanPayloadForSensitiveData({ config: "-----BEGIN RSA PRIVATE KEY-----" }),
		PayloadHygieneViolation
	);
	// Public certificates are not secrets.
	assert.doesNotThrow(() =>
		scanPayloadForSensitiveData({ config: "-----BEGIN CERTIFICATE-----" })
	);
});

test("[LW-payload.2] values that look like other JWTs are rejected", () => {
	const jwtish =
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	assert.throws(
		() => scanPayloadForSensitiveData({ upstream: jwtish }),
		PayloadHygieneViolation
	);
});

test("ordinary claims pass", () => {
	assert.doesNotThrow(() =>
		scanPayloadForSensitiveData({
			iss: "https://auth.example.com",
			aud: "https://api.example.com",
			nickname: "Alice",
			roles: ["admin", "user"],
			org: { name: "ACME", plan: "enterprise" },
			exp: 1234567890,
		})
	);
});

test("[LW-payload] errors name the claim but never echo its value", () => {
	try {
		scanPayloadForSensitiveData({ password: "hunter2-super-secret" });
		assert.fail("should have thrown");
	} catch (error) {
		assert.ok(error instanceof PayloadHygieneViolation);
		assert.equal(error.claim, "password");
		assert.ok(!error.message.includes("hunter2"));
	}
});

test("unsafeAllowClaim-style waivers skip the whole subtree", () => {
	assert.doesNotThrow(() =>
		scanPayloadForSensitiveData(
			{ passwordHint: "favorite color", meta: { note: "ok" } },
			new Set(["passwordHint"])
		)
	);
});

// --- heuristic precision (issue #14) -------------------------------------
// A scanner that rejects valid payloads pushes developers to unsafeAllowClaim,
// which is the marker code review depends on staying rare.

test("[LW-payload.2] numeric ids are not mistaken for payment cards", () => {
	// Luhn alone is a 1-in-10 coin flip; snowflake-style ids must survive it.
	for (const id of [
		"4532015112830366", // 16 digits, Luhn-valid, but Visa-prefixed -> still a card
	]) {
		assert.throws(() => scanPayloadForSensitiveData({ sub: id }), PayloadHygieneViolation);
	}
	for (const id of [
		"755193776567357440", // Discord-style snowflake, 18 digits, Luhn-valid
		"1234567890123456789", // 19 digits, no card prefix
		"9876543210987654", // 16 digits, no card prefix
	]) {
		assert.doesNotThrow(() => scanPayloadForSensitiveData({ sub: id }), `rejected ${id}`);
	}
});

test("[LW-payload.2] every card brand is still caught", () => {
	for (const card of [
		"4111111111111111", // Visa
		"5555555555554444", // Mastercard
		"2223003122003222", // Mastercard 2-series
		"378282246310005", // American Express
		"6011111111111117", // Discover
		"3530111333300000", // JCB
	]) {
		assert.throws(
			() => scanPayloadForSensitiveData({ note: card }),
			PayloadHygieneViolation,
			`missed ${card}`
		);
	}
});

test("[LW-payload.2] dotted identifiers are not mistaken for embedded JWTs", () => {
	// A compact JWS always starts `eyJ` - a bare hostname does not.
	for (const value of [
		"authentication.microsoftonline.production",
		"eu-west-1.identity-provider.internal",
	]) {
		assert.doesNotThrow(() => scanPayloadForSensitiveData({ aud: value }), `rejected ${value}`);
	}
	// Real tokens, including an unsigned one, still trip it.
	assert.throws(
		() => scanPayloadForSensitiveData({ upstream: "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0." }),
		PayloadHygieneViolation
	);
});

test("[LW-payload.1] standard OAuth metadata claims are not sensitive names", () => {
	// token_use (AWS Cognito) and token_type describe this token, not another.
	assert.doesNotThrow(() => scanPayloadForSensitiveData({ token_use: "access" }));
	assert.doesNotThrow(() => scanPayloadForSensitiveData({ token_type: "Bearer" }));
	// The fragment still bites where it should.
	assert.throws(() => scanPayloadForSensitiveData({ access_token: "x" }), PayloadHygieneViolation);
	assert.throws(() => scanPayloadForSensitiveData({ refresh_token: "x" }), PayloadHygieneViolation);
});
