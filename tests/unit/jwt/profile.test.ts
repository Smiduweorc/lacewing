import { test } from "node:test";
import assert from "node:assert/strict";
import { defineProfile } from "../../../src/jwt/profile.js";
import { generateKeyPair, generateSecret } from "../../../src/key/generate.js";
import { AlgorithmNotAllowed } from "../../../src/util/errors.js";

const { publicKey, privateKey } = await generateKeyPair("EdDSA");

function base(): Parameters<typeof defineProfile>[0] {
	return {
		typ: "at+jwt",
		issuer: "https://auth.example.com",
		audience: "https://api.example.com",
		algorithms: ["EdDSA"],
		keys: publicKey,
		maxTokenAge: "15m",
	};
}

test("[8725-3.1.1] typ, issuer, audience, algorithms, keys and maxTokenAge are structurally mandatory", () => {
	for (const field of ["typ", "issuer", "audience", "algorithms", "keys", "maxTokenAge"]) {
		const options = base() as Record<string, unknown>;
		delete options[field];
		assert.throws(
			() => defineProfile(options as never),
			`expected ${field} to be required`
		);
	}
	assert.throws(() => defineProfile({ ...base(), issuer: "" }), TypeError);
	assert.throws(() => defineProfile({ ...base(), algorithms: [] }), TypeError);
});

test("[8725-3.2.1] the allowlist only accepts registry algorithms", () => {
	assert.throws(() => defineProfile({ ...base(), algorithms: ["none"] }), AlgorithmNotAllowed);
	assert.throws(() => defineProfile({ ...base(), algorithms: ["RS256"] }), AlgorithmNotAllowed);
	assert.throws(
		() => defineProfile({ ...base(), algorithms: ["EdDSA", "nOnE"] }),
		AlgorithmNotAllowed
	);
});

test("clock skew has a sane default and a hard cap", () => {
	assert.equal(defineProfile(base()).maxClockSkew, 5);
	assert.equal(defineProfile({ ...base(), maxClockSkew: "30s" }).maxClockSkew, 30);
	assert.throws(() => defineProfile({ ...base(), maxClockSkew: "10m" }), TypeError);
});

test("verification profiles refuse private keys", () => {
	assert.throws(() => defineProfile({ ...base(), keys: privateKey }), TypeError);
});

test("a profile key must be inside the profile's own allowlist", () => {
	assert.throws(
		() => defineProfile({ ...base(), algorithms: ["ES256"], keys: publicKey }),
		TypeError
	);
	const secret = generateSecret("HS256");
	assert.doesNotThrow(() =>
		defineProfile({ ...base(), algorithms: ["HS256"], keys: secret })
	);
});

test("remote JWKS configs must be https", () => {
	assert.throws(
		() => defineProfile({ ...base(), keys: { jwksUri: "http://auth.example.com/jwks" } }),
		TypeError
	);
	assert.doesNotThrow(() =>
		defineProfile({ ...base(), keys: { jwksUri: "https://auth.example.com/jwks" } })
	);
});

test("nonsense key configs are rejected", () => {
	assert.throws(() => defineProfile({ ...base(), keys: {} as never }), TypeError);
	assert.throws(() => defineProfile({ ...base(), keys: "key" as never }), TypeError);
});

test("profiles are frozen - the security boundary can't be edited later", () => {
	const profile = defineProfile(base());
	assert.ok(Object.isFrozen(profile));
	assert.throws(() => {
		(profile as { iss: string }).iss = "https://evil.example.com";
	}, TypeError);
});

test("durations accept both seconds and shorthand", () => {
	assert.equal(defineProfile({ ...base(), maxTokenAge: 900 }).maxTokenAge, 900);
	assert.equal(defineProfile({ ...base(), maxTokenAge: "15m" }).maxTokenAge, 900);
	assert.throws(() => defineProfile({ ...base(), maxTokenAge: "15 minutes" }), TypeError);
	assert.throws(() => defineProfile({ ...base(), maxTokenAge: -5 }), TypeError);
});
