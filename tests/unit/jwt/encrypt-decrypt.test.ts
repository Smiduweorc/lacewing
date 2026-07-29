/**
 * Unit tests for the JWE encrypt/decrypt path. Rejection-heavy, per the suite
 * convention: the interesting behavior is everything the path refuses to do.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import {
	EncryptJWT,
	jwtDecrypt,
	defineDecryptionProfile,
	generateEncryptionKeyPair,
	generateEncryptionSecret,
	generateDirectKey,
	importEncryptionKey,
	generateSecret,
	MemoryRevocationStore,
	JWTRevoked,
	JWTInvalid,
	KeyTypeMismatch,
	type ExpectedDecryptionProfile,
	type LacewingEncryptionKey,
} from "../../../index.js";

const ISS = "https://auth.example.com";
const AUD = "https://api.example.com";

const ecdh = await generateEncryptionKeyPair("ECDH-ES+A256KW", { extractable: true });
const aeskw = generateEncryptionSecret("A256KW");
const dir = generateDirectKey("A256GCM");

function profile(key: LacewingEncryptionKey, algs: string[], encs: string[], overrides = {}): ExpectedDecryptionProfile {
	return defineDecryptionProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD,
		keyManagementAlgorithms: algs, contentEncryptionAlgorithms: encs,
		key, maxTokenAge: "15m", ...overrides,
	});
}

test("round-trips through the asymmetric, AES-KW and dir families", async () => {
	const cases: Array<[string, LacewingEncryptionKey, LacewingEncryptionKey, string, string]> = [
		["ecdh", ecdh.publicKey, ecdh.privateKey, "ECDH-ES+A256KW", "A256GCM"],
		["aeskw", aeskw, aeskw, "A256KW", "A192GCM"],
		["dir", dir, dir, "dir", "A256GCM"],
	];
	for (const [label, encKey, decKey, alg, enc] of cases) {
		const token = await new EncryptJWT("at+jwt", { contentEncryption: enc })
			.issuer(ISS).audience(AUD).subject("user-42").claim("card", "4111111111111111").expiresIn("5m")
			.encrypt(encKey);
		const { header, payload } = await jwtDecrypt(token, profile(decKey, [alg], [enc]));
		assert.equal(header.alg, alg, label);
		assert.equal(header.enc, enc, label);
		// The whole point of JWE: a "sensitive" value that the JWS hygiene scanner
		// would have refused is fine here, because the payload is not plaintext.
		assert.equal(payload.card, "4111111111111111", label);
	}
});

test("encrypt() refuses a private key and a raw CryptoKey", async () => {
	await assert.rejects(new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(ecdh.privateKey), KeyTypeMismatch);
	// A bare object is not a LacewingEncryptionKey.
	await assert.rejects(
		new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt({} as unknown as LacewingEncryptionKey),
		TypeError
	);
});

test("a signing key cannot be used to encrypt (distinct brand)", async () => {
	const signingKey = generateSecret("HS256");
	await assert.rejects(
		new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(signingKey as unknown as LacewingEncryptionKey),
		TypeError
	);
});

test("a tampered ciphertext fails to decrypt", async () => {
	const token = await new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(dir);
	const parts = token.split(".");
	// Flip a byte in the ciphertext segment (index 3).
	const ct = Buffer.from(parts[3] as string, "base64url");
	ct[0] = (ct[0] as number) ^ 0xff;
	parts[3] = ct.toString("base64url");
	await assert.rejects(jwtDecrypt(parts.join("."), profile(dir, ["dir"], ["A256GCM"])), JWTInvalid);
});

test("a zip header is rejected before decryption (decompression bomb)", async () => {
	const header = Buffer.from(JSON.stringify({ alg: "dir", enc: "A256GCM", typ: "at+jwt", zip: "DEF" })).toString("base64url");
	const bogus = `${header}..aaaa.bbbb.cccc`;
	await assert.rejects(jwtDecrypt(bogus, profile(dir, ["dir"], ["A256GCM"])), JWTInvalid);
});

test("wrong number of segments is rejected (JWS shape, garbage)", async () => {
	await assert.rejects(jwtDecrypt("a.b.c", profile(dir, ["dir"], ["A256GCM"])), JWTInvalid);
	await assert.rejects(jwtDecrypt("a.b.c.d.e.f", profile(dir, ["dir"], ["A256GCM"])), JWTInvalid);
	await assert.rejects(jwtDecrypt("", profile(dir, ["dir"], ["A256GCM"])), JWTInvalid);
});

test("revocation applies to encrypted tokens too, after decryption", async () => {
	const revocation = new MemoryRevocationStore();
	const p = profile(dir, ["dir"], ["A256GCM"], { revocation });
	const token = await new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(dir);
	const { payload } = await jwtDecrypt(token, p);
	revocation.revoke(payload.jti as string, payload.exp);
	await assert.rejects(jwtDecrypt(token, p), JWTRevoked);
});

test("importEncryptionKey binds symmetric keys to a size", async () => {
	// A256KW needs 32 bytes; 16 is refused.
	await assert.rejects(importEncryptionKey(new Uint8Array(16), "A256KW"), KeyTypeMismatch);
	const ok = await importEncryptionKey(new Uint8Array(32), "A256KW");
	assert.equal(ok.algorithm, "A256KW");
});

test("a dir key sized for one enc cannot encrypt under another", async () => {
	const dir32 = generateDirectKey("A256GCM"); // 32 bytes
	await assert.rejects(
		new EncryptJWT("at+jwt", { contentEncryption: "A128GCM" }).issuer(ISS).audience(AUD).expiresIn("5m").encrypt(dir32),
		KeyTypeMismatch
	);
});

// Regression: a base64url segment whose length is not a multiple of four
// carries unused trailing bits. The AEAD never sees them, so a lenient parser
// accepts several distinct strings for one token - and a token string that is
// not a stable identity breaks revocation and replay caches keyed on it.

// https://github.com/Smiduweorc/lacewing/issues/12
test("[strictness] non-canonical trailing bits are rejected in every JWE segment", async () => {
	const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	const p = profile(aeskw, ["A256KW"], ["A256GCM"]);
	const token = await new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(aeskw);
	const segments = token.split(".");

	let exercised = 0;
	for (let i = 0; i < segments.length; i++) {
		const segment = segments[i] as string;
		// Two chars carry one byte (4 slack bits), three carry two bytes (2 slack
		// bits); a multiple of four is exact and has no room to be malleable.
		const slack = segment.length % 4;
		if (slack !== 2 && slack !== 3) continue;

		const last = segment.length - 1;
		const index = ALPHABET.indexOf(segment[last] as string);
		// Flipping the lowest bit stays inside the slack: same bytes, new string.
		const variant = segment.slice(0, last) + (ALPHABET[index ^ 1] as string);
		assert.notEqual(variant, segment);

		const mutated = segments.map((s, n) => (n === i ? variant : s)).join(".");
		await assert.rejects(jwtDecrypt(mutated, p), JWTInvalid, `segment ${i} accepted a non-canonical twin`);
		exercised++;
	}
	// The header, the A256KW encrypted key and the tag always have slack.
	assert.ok(exercised >= 3, `expected at least 3 malleable segments, exercised ${exercised}`);
});
