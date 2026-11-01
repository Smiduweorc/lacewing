import { test } from "node:test";
import assert from "node:assert/strict";
import {
	SignJWT,
	EncryptJWT,
	jwtVerify,
	jwtDecrypt,
	defineProfile,
	defineDecryptionProfile,
	createRemoteJWKSet,
	generateSecret,
	generateDirectKey,
	generateKeyPair,
	exportKeyJWK,
	unsafeDecode,
	MemoryRevocationStore,
	type StaticJWK,
} from "../../../index.js";
import { resolveAlgorithm } from "../../../src/lib/algorithms.js";
import { SetAlg } from "../../../src/types.js";

const ISS = "https://auth.example.com";
const AUD = "https://api.example.com";
const T0 = 1_767_225_600_000; // 2026-01-01T00:00:00Z
const T0_SECONDS = T0 / 1000;

test("SignJWT stamps iat, nbf and exp from its clock", async () => {
	const token = await new SignJWT("at+jwt", { now: () => T0 + 999 })
		.issuer(ISS).audience(AUD).notBefore("1m").expiresIn("10m")
		.sign(generateSecret("HS256"));
	const { payload } = unsafeDecode(token);
	assert.equal(payload.iat, T0_SECONDS, "milliseconds are floored to whole seconds");
	assert.equal(payload.nbf, T0_SECONDS + 60);
	assert.equal(payload.exp, T0_SECONDS + 600);
});

test("EncryptJWT stamps from its clock, and the decryption profile judges by its own", async () => {
	const key = generateDirectKey("A256GCM");
	const token = await new EncryptJWT("at+jwt", { now: () => T0 }).issuer(ISS).audience(AUD).expiresIn("10m").encrypt(key);
	let clockMs = T0 + 60_000;
	const profile = defineDecryptionProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD, keyManagementAlgorithms: ["dir"], contentEncryptionAlgorithms: ["A256GCM"],
		key, maxTokenAge: "15m", now: () => clockMs,
	});
	await assert.doesNotReject(jwtDecrypt(token, profile));
	clockMs = T0 + 600_000 + 5_000; // exp plus the default 5s skew
	await assert.rejects(jwtDecrypt(token, profile), { name: "JWTError", code: "JWT_EXPIRED" });
});

test("a verification profile judges expiry by its clock, not the system's", async () => {
	const secret = generateSecret("HS256");
	const token = await new SignJWT("at+jwt", { now: () => T0 }).issuer(ISS).audience(AUD).expiresIn("10m").sign(secret);
	const at = (ms: number): ReturnType<typeof defineProfile> => defineProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: secret, maxTokenAge: "15m", now: () => ms,
	});
	await assert.doesNotReject(jwtVerify(token, at(T0 + 600_000 + 4_999)), "one ms inside exp + skew");
	await assert.rejects(jwtVerify(token, at(T0 + 600_000 + 5_000)), { name: "JWTError", code: "JWT_EXPIRED" });
});

test("the default clock is Date.now, read at call time", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: T0 });
	const secret = generateSecret("HS256");
	const profile = defineProfile({ typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: secret, maxTokenAge: "15m" });
	const token = await new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("10m").sign(secret);
	assert.equal(unsafeDecode(token).payload.iat, T0_SECONDS);
	t.mock.timers.tick(600_000 + 5_000);
	await assert.rejects(jwtVerify(token, profile), { name: "JWTError", code: "JWT_EXPIRED" });
});

test("a remote JWKS expires its cache by its clock", async () => {
	const { publicKey } = await generateKeyPair("EdDSA", { extractable: true });
	const jwk: StaticJWK = { ...(await exportKeyJWK(publicKey)), kid: "k" };
	let calls = 0;
	const fetch = (async () => {
		calls += 1;
		return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
	}) as unknown as typeof globalThis.fetch;
	let clockMs = T0;
	const source = createRemoteJWKSet("https://auth.example.com/jwks", {
		cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 5000, fetch, now: () => clockMs,
	});
	const header = { alg: SetAlg("EdDSA"), typ: "at+jwt", kid: "k" };
	const allowed = [resolveAlgorithm("EdDSA")];
	await source.getVerificationKey(header, allowed);
	clockMs = T0 + 299_999;
	await source.getVerificationKey(header, allowed);
	assert.equal(calls, 1, "still fresh one ms before the TTL");
	clockMs = T0 + 300_000;
	await source.getVerificationKey(header, allowed);
	assert.equal(calls, 2, "refetched at the TTL");
});

test("MemoryRevocationStore drops entries by its clock", async () => {
	let clockMs = T0;
	const store = new MemoryRevocationStore({ now: () => clockMs });
	const context = { jti: "t", exp: T0_SECONDS + 60, iat: T0_SECONDS };
	store.revoke("t", T0_SECONDS + 60);
	assert.equal(await store.isRevoked(context), true);
	clockMs = T0 + 60_000;
	assert.equal(await store.isRevoked(context), false);
	assert.equal(store.size, 0);
});

test("now must be a function everywhere it is accepted", () => {
	const bad = { now: 123 as never };
	assert.throws(() => new SignJWT("at+jwt", bad), TypeError);
	assert.throws(() => new EncryptJWT("at+jwt", bad), TypeError);
	assert.throws(() => new MemoryRevocationStore(bad), TypeError);
	assert.throws(() => createRemoteJWKSet("https://a.example.com/jwks", { cacheTtlSeconds: 1, cooldownSeconds: 1, timeoutMs: 1, ...bad }), TypeError);
	assert.throws(() => defineProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: generateSecret("HS256"), maxTokenAge: "5m", ...bad,
	}), TypeError);
});

test("notBefore at or after expiresIn is refused, one second before is fine", async () => {
	const secret = generateSecret("HS256");
	const key = generateDirectKey("A256GCM");
	const sign = (nbf: number): Promise<string> => new SignJWT("at+jwt").issuer(ISS).audience(AUD).notBefore(nbf).expiresIn(600).sign(secret);
	const encrypt = (nbf: number): Promise<string> => new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).notBefore(nbf).expiresIn(600).encrypt(key);
	for (const build of [sign, encrypt]) {
		await assert.rejects(build(600), TypeError, "nbf equal to exp");
		await assert.rejects(build(601), TypeError, "nbf after exp");
		await assert.doesNotReject(build(599));
	}
});
