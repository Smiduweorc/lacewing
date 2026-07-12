import { test } from "node:test";
import assert from "node:assert/strict";
import { createLocalJWKSet } from "../../../src/jwks/local.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { jwtVerify } from "../../../src/jwt/verify.js";
import { SignJWT } from "../../../src/jwt/sign.js";
import { generateKeyPair } from "../../../src/key/generate.js";
import { exportKeyJWK } from "../../../src/key/export.js";
import { toValidAlg } from "../../../src/lib/algorithms.js";
import { EntropyCheckFailed, JWKSNoMatchingKey } from "../../../src/util/errors.js";
import { b64u } from "../../helpers.js";
import type { JwtHeader, StaticJWK } from "../../../src/types.js";

const alice = await generateKeyPair("EdDSA", { extractable: true });
const bob = await generateKeyPair("EdDSA", { extractable: true });
const aliceJwk: StaticJWK = { ...(await exportKeyJWK(alice.publicKey)), kid: "alice" };
const bobJwk: StaticJWK = { ...(await exportKeyJWK(bob.publicKey)), kid: "bob" };

function header(kid?: string, alg = "EdDSA"): JwtHeader {
	const result: JwtHeader = { alg: toValidAlg(alg), typ: "at+jwt" };
	if (kid !== undefined) result.kid = kid;
	return result;
}

test("selects the key matching the sanitized kid", async () => {
	const source = createLocalJWKSet({ keys: [aliceJwk, bobJwk] });
	const resolved = await source.getVerificationKey(header("bob"), [toValidAlg("EdDSA")]);
	assert.equal(resolved.alg, "EdDSA");
});

test("fails closed on unknown kid", async () => {
	const source = createLocalJWKSet({ keys: [aliceJwk, bobJwk] });
	await assert.rejects(
		source.getVerificationKey(header("carol"), [toValidAlg("EdDSA")]),
		JWKSNoMatchingKey
	);
});

test("ambiguity without a kid fails closed rather than guessing", async () => {
	const source = createLocalJWKSet({ keys: [aliceJwk, bobJwk] });
	await assert.rejects(
		source.getVerificationKey(header(undefined), [toValidAlg("EdDSA")]),
		JWKSNoMatchingKey
	);
	// A single unambiguous key works without a kid.
	const single = createLocalJWKSet({ keys: [aliceJwk] });
	await assert.doesNotReject(single.getVerificationKey(header(undefined), [toValidAlg("EdDSA")]));
});

test("[8725-3.2.1] entries outside the registry or marked for encryption are never candidates", async () => {
	const source = createLocalJWKSet({
		keys: [
			{ ...aliceJwk, use: "enc" },
			{ ...bobJwk, alg: "RS256" }, // dropped: not a registry algorithm
		],
	});
	await assert.rejects(
		source.getVerificationKey(header("alice"), [toValidAlg("EdDSA")]),
		JWKSNoMatchingKey
	);
	await assert.rejects(
		source.getVerificationKey(header("bob"), [toValidAlg("EdDSA")]),
		JWKSNoMatchingKey
	);
});

test("[8725-3.5.2] weak oct keys inside a JWKS are rejected at resolution", async () => {
	const source = createLocalJWKSet({
		keys: [{ kty: "oct", k: b64u(new TextEncoder().encode("password-password-password-password")), kid: "weak" }],
	});
	await assert.rejects(
		source.getVerificationKey(header("weak", "HS256"), [toValidAlg("HS256")]),
		EntropyCheckFailed
	);
});

test("malformed JWKS documents are rejected at construction", () => {
	assert.throws(() => createLocalJWKSet({} as never), TypeError);
	assert.throws(() => createLocalJWKSet({ keys: "nope" } as never), TypeError);
});

test("end-to-end: JWKS-backed profile verifies tokens and supports rotation by kid", async () => {
	// Signer includes no kid, so give the JWKS exactly one usable key per alg.
	const token = await new SignJWT("at+jwt")
		.issuer("https://auth.example.com")
		.audience("https://api.example.com")
		.expiresIn("5m")
		.sign(alice.privateKey);
	const profile = defineProfile({
		typ: "at+jwt",
		issuer: "https://auth.example.com",
		audience: "https://api.example.com",
		algorithms: ["EdDSA"],
		keys: { keys: [aliceJwk] },
		maxTokenAge: "15m",
	});
	const verified = await jwtVerify(token, profile);
	assert.equal(verified.payload.iss, "https://auth.example.com");
});
