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
