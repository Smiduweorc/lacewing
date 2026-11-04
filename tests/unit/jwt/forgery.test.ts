import { test } from "node:test";
import assert from "node:assert/strict";
import {
	SignJWT,
	EncryptJWT,
	jwtVerify,
	jwtDecrypt,
	defineProfile,
	defineDecryptionProfile,
	generateSecret,
	generateDirectKey,
	importKey,
	createLocalJWKSet,
	unsafeCustomKeySource,
	type KeySource,
} from "../../../index.js";

const ISS = "https://auth.example.com";
const AUD = "https://api.example.com";

function lookAlikeKey(key: Uint8Array): never {
	return Object.freeze({ __brand: "LacewingKey", algorithm: "HS256", keyType: "secret", key }) as never;
}

// Found in the v3 house-rules audit: a plain object with the right __brand
// string signed and verified with a 6-byte "secret", skipping importKey.
test("[8725-3.5.1] a look-alike key object can neither sign nor back a profile", async () => {
	const weak = lookAlikeKey(new TextEncoder().encode("secret"));
	await assert.rejects(new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign(weak), TypeError);
	assert.throws(
		() => defineProfile({ typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: weak, maxTokenAge: "5m" }),
		TypeError
	);
});

test("[8725-3.5.1] a copy of a real key is not a key either", async () => {
	const real = generateSecret("HS256");
	await assert.doesNotReject(new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign(real));
	await assert.rejects(
		new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign({ ...real }),
		TypeError
	);
});

test("[LW-enc.2] a look-alike or copied encryption key is refused", async () => {
	const real = generateDirectKey("A256GCM");
	const lookAlike = Object.freeze({ ...real, __brand: "LacewingEncryptionKey" }) as never;
	await assert.rejects(new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(lookAlike), TypeError);
	const options = {
		typ: "at+jwt",
		issuer: ISS,
		audience: AUD,
		keyManagementAlgorithms: ["dir"],
		contentEncryptionAlgorithms: ["A256GCM"],
		maxTokenAge: "5m",
	};
	assert.throws(() => defineDecryptionProfile({ ...options, key: lookAlike }), TypeError);
	assert.doesNotThrow(() => defineDecryptionProfile({ ...options, key: real }));
});

// Found in the same audit: an object shaped like a profile, with a decade of
// accepted age and an unwrapped key source, verified a token.
test("[8725-3.12.1] jwtVerify refuses a profile defineProfile did not build", async () => {
	const secret = generateSecret("HS256");
	const token = await new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign(secret);
	const real = defineProfile({ typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: secret, maxTokenAge: "5m" });
	await assert.doesNotReject(jwtVerify(token, real));
	const widened = { ...real, maxTokenAge: 10 * 365 * 86400, maxClockSkew: 86400 } as never;
	await assert.rejects(jwtVerify(token, widened), (error: unknown) => {
		assert.ok(error instanceof TypeError);
		assert.match(error.message, /defineProfile/);
		return true;
	});
	await assert.rejects(jwtVerify(token, Object.create(real) as never), TypeError, "a prototype child is not one either");
});

test("[8725-3.12.1] jwtDecrypt refuses a profile defineDecryptionProfile did not build", async () => {
	const key = generateDirectKey("A256GCM");
	const token = await new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(key);
	const real = defineDecryptionProfile({
		typ: "at+jwt",
		issuer: ISS,
		audience: AUD,
		keyManagementAlgorithms: ["dir"],
		contentEncryptionAlgorithms: ["A256GCM"],
		key,
		maxTokenAge: "5m",
	});
	await assert.doesNotReject(jwtDecrypt(token, real));
	await assert.rejects(jwtDecrypt(token, { ...real } as never), TypeError);
	const verifyProfile = defineProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: generateSecret("HS256"), maxTokenAge: "5m",
	});
	await assert.rejects(jwtDecrypt(token, verifyProfile as never), TypeError, "a verification profile is not a decryption profile");
});

test("[8725-3.8.1] only the wrapper unsafeCustomKeySource returns counts, not the object it wrapped", async () => {
	const secret = await importKey(globalThis.crypto.getRandomValues(new Uint8Array(32)), "HS256");
	const source: KeySource = { getVerificationKey: async () => ({ alg: "HS256" as never, key: secret.key }) };
	const base = { typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], maxTokenAge: "5m" };
	const wrapped = unsafeCustomKeySource(source);
	assert.notEqual(wrapped, source);
	assert.throws(() => defineProfile({ ...base, keys: source }), TypeError);
	assert.throws(() => defineProfile({ ...base, keys: { ...wrapped } }), TypeError, "a copy of the wrapper is refused");
	const profile = defineProfile({ ...base, keys: wrapped });
	const token = await new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign(secret);
	await assert.doesNotReject(jwtVerify(token, profile));
});

test("built-in key sources are accepted without a wrapper, and their copies are not", () => {
	const local = createLocalJWKSet({ keys: [] });
	const base = { typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["EdDSA"], maxTokenAge: "5m" };
	assert.doesNotThrow(() => defineProfile({ ...base, keys: local }));
	assert.throws(() => defineProfile({ ...base, keys: { ...local } }), TypeError);
});

test("minted keys, profiles and sources are frozen", () => {
	const secret = generateSecret("HS256");
	const profile = defineProfile({ typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: secret, maxTokenAge: "5m" });
	assert.ok(Object.isFrozen(secret));
	assert.ok(Object.isFrozen(profile));
	assert.ok(Object.isFrozen(createLocalJWKSet({ keys: [] })));
	assert.throws(() => {
		(profile as { maxTokenAge: number }).maxTokenAge = 1e9;
	}, TypeError);
});
