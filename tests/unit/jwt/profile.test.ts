import { test } from "node:test";
import assert from "node:assert/strict";
import { refusal } from "../../helpers.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { generateKeyPair, generateSecret } from "../../../src/key/generate.js";
import { SignJWT } from "../../../src/jwt/sign.js";
import { jwtVerify } from "../../../src/jwt/verify.js";
import { LEGACY_RS256 } from "../../../src/legacy/rsa.js";
import { unsafeCustomKeySource } from "../../../src/jwks/trusted.js";
import { createLocalJWKSet } from "../../../src/jwks/local.js";
import type { ExpectedJwtProfile } from "../../../src/types.js";

const { publicKey, privateKey } = await generateKeyPair("EdDSA");
const REMOTE = { cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 5000 };

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
		const options = base() as unknown as Record<string, unknown>;
		delete options[field];
		assert.throws(
			() => defineProfile(options as never),
			`expected ${field} to be required`
		);
	}
	assert.throws(() => defineProfile({ ...base(), issuer: "" }), TypeError);
	assert.throws(() => defineProfile({ ...base(), algorithms: [] }), TypeError);
});

test("[8725-3.2.1] the allowlist only accepts default-set names and Lacewing descriptors", () => {
	assert.throws(() => defineProfile({ ...base(), algorithms: ["none"] }), refusal("ALGORITHM_NOT_ALLOWED"));
	assert.throws(() => defineProfile({ ...base(), algorithms: ["RS256"] }), refusal("ALGORITHM_NOT_ALLOWED"));
	assert.throws(
		() => defineProfile({ ...base(), algorithms: ["EdDSA", "nOnE"] }),
		refusal("ALGORITHM_NOT_ALLOWED")
	);
});

test("[8725-3.2.3] the allowlist mixes default names with legacy descriptors, resolved to descriptors", () => {
	const profile = defineProfile({ ...base(), algorithms: ["EdDSA", LEGACY_RS256] });
	assert.deepEqual(profile.alg.map((info) => info.name), ["EdDSA", "RS256"]);
	assert.equal(profile.alg[1], LEGACY_RS256);
	assert.equal(Object.isFrozen(profile.alg), true);
});

test("[8725-3.2.3] a hand-built descriptor in the allowlist is refused", () => {
	const forged = Object.freeze({ name: "RS256", kty: "RSA", minKeyBits: 1024 } as const);
	assert.throws(() => defineProfile({ ...base(), algorithms: ["EdDSA", forged] }), refusal("ALGORITHM_NOT_ALLOWED"));
});

test("[8725-3.2.3] a hand-built or spread profile cannot verify anything, forged descriptor or not", async () => {
	const secret = generateSecret("HS256");
	const token = await new SignJWT("at+jwt")
		.issuer("https://auth.example.com")
		.audience("https://api.example.com")
		.expiresIn("5m")
		.sign(secret);
	const real = defineProfile({ ...base(), algorithms: ["HS256"], keys: secret });
	await assert.doesNotReject(jwtVerify(token, real));
	const forged = Object.freeze({ name: "HS256", kty: "oct", minKeyBits: 8 } as const);
	const handBuilt: ExpectedJwtProfile = { ...real, alg: [forged] };
	await assert.rejects(jwtVerify(token, handBuilt), TypeError);
	// A copy with nothing changed is refused too: it never went through defineProfile.
	await assert.rejects(jwtVerify(token, { ...real }), TypeError);
});

test("clock skew has a sane default and a hard cap", () => {
	assert.equal(defineProfile(base()).maxClockSkew, 5);
	assert.equal(defineProfile({ ...base(), maxClockSkew: "30s" }).maxClockSkew, 30);
	assert.throws(() => defineProfile({ ...base(), maxClockSkew: "31s" }), TypeError);
	assert.equal(
		defineProfile({ ...base(), maxClockSkew: "120s", unsafeAllowLargeClockSkew: true }).maxClockSkew,
		120
	);
	assert.throws(
		() => defineProfile({ ...base(), maxClockSkew: "10m", unsafeAllowLargeClockSkew: true }),
		TypeError
	);
});

test("maxTokenAge above 30 days needs unsafeAllowLongTokenAge", () => {
	assert.equal(defineProfile({ ...base(), maxTokenAge: "30d" }).maxTokenAge, 30 * 86400);
	assert.throws(() => defineProfile({ ...base(), maxTokenAge: "3650d" }), TypeError);
	assert.equal(
		defineProfile({ ...base(), maxTokenAge: "3650d", unsafeAllowLongTokenAge: true }).maxTokenAge,
		3650 * 86400
	);
});

test("custom key sources must go through unsafeCustomKeySource()", () => {
	const source = { getVerificationKey: async () => ({ alg: "EdDSA", key: publicKey }) } as never;
	assert.throws(() => defineProfile({ ...base(), keys: source }), TypeError);
	assert.doesNotThrow(() => defineProfile({ ...base(), keys: unsafeCustomKeySource(source) }));
	assert.doesNotThrow(() => defineProfile({ ...base(), keys: createLocalJWKSet({ keys: [] }) }));
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
		() => defineProfile({ ...base(), keys: { ...REMOTE, jwksUri: "http://auth.example.com/jwks" } }),
		TypeError
	);
	assert.doesNotThrow(() =>
		defineProfile({ ...base(), keys: { ...REMOTE, jwksUri: "https://auth.example.com/jwks" } })
	);
});

test("a remote JWKS config must name its cache, cooldown and timeout numbers", () => {
	assert.throws(
		() => defineProfile({ ...base(), keys: { jwksUri: "https://auth.example.com/jwks" } as never }),
		(error: unknown) => error instanceof TypeError && error.message.includes("cacheTtlSeconds")
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
