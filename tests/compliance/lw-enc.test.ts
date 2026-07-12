/**
 * LW-enc.1–.4 - encrypted JWTs (JWE) held to the same discipline as signed
 * ones, through the public API only.
 *
 *  - LW-enc.1: the JWE algorithm set is curated; `none` and weak key
 *    management (RSA1_5, RSA-OAEP-SHA1, PBES2*) are unrepresentable.
 *  - LW-enc.2: decryption uses only the profile's allowlisted alg + enc.
 *  - LW-enc.3: the same claim discipline (typ/iss/aud/exp, unique jti,
 *    lifetime cap) is enforced on encrypt and validated on decrypt.
 *  - LW-enc.4: JWS and JWE never cross over.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	EncryptJWT,
	jwtDecrypt,
	jwtVerify,
	defineDecryptionProfile,
	defineProfile,
	generateEncryptionKeyPair,
	generateDirectKey,
	importEncryptionKey,
	SignJWT,
	generateSecret,
	AlgorithmNotAllowed,
	JWTClaimValidationFailed,
	JWTInvalid,
	MaxLifetimeExceeded,
	MissingClaim,
	type ExpectedDecryptionProfile,
} from "../../index.js";

const ISS = "https://auth.example.com";
const AUD = "https://api.example.com";

const ecdh = await generateEncryptionKeyPair("ECDH-ES+A256KW");

function decProfile(overrides: Partial<Parameters<typeof defineDecryptionProfile>[0]> = {}): ExpectedDecryptionProfile {
	return defineDecryptionProfile({
		typ: "at+jwt",
		issuer: ISS,
		audience: AUD,
		keyManagementAlgorithms: ["ECDH-ES+A256KW"],
		contentEncryptionAlgorithms: ["A256GCM"],
		key: ecdh.privateKey,
		maxTokenAge: "15m",
		...overrides,
	});
}

function encToken(build: (b: EncryptJWT) => EncryptJWT = (b) => b): Promise<string> {
	return build(new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).subject("user-42").expiresIn("5m")).encrypt(ecdh.publicKey);
}

test("[LW-enc.1] 'none' and weak key-management algorithms are unrepresentable", async () => {
	for (const alg of ["none", "RSA1_5", "RSA-OAEP", "PBES2-HS256+A128KW", "made-up"]) {
		await assert.rejects(importEncryptionKey(new Uint8Array(32), alg), AlgorithmNotAllowed, alg);
	}
	// A profile cannot allowlist an absent algorithm or a 'none' enc.
	assert.throws(() => decProfile({ keyManagementAlgorithms: ["RSA1_5"] }), AlgorithmNotAllowed);
	assert.throws(() => decProfile({ contentEncryptionAlgorithms: ["none"] }), AlgorithmNotAllowed);
	// And the builder rejects an unknown enc up front.
	assert.throws(() => new EncryptJWT("at+jwt", { contentEncryption: "none" }), AlgorithmNotAllowed);
});

test("[LW-enc.2] decryption honors only the profile's allowlisted alg + enc", async () => {
	const token = await encToken(); // ECDH-ES+A256KW / A256GCM
	// enc not in the allowlist:
	await assert.rejects(jwtDecrypt(token, decProfile({ contentEncryptionAlgorithms: ["A128CBC-HS256"] })), AlgorithmNotAllowed);
	// alg not in the allowlist (and the key would not match either):
	const rsa = await generateEncryptionKeyPair("RSA-OAEP-256");
	await assert.rejects(
		jwtDecrypt(token, decProfile({ keyManagementAlgorithms: ["RSA-OAEP-256"], key: rsa.privateKey })),
		AlgorithmNotAllowed
	);
	// The right profile accepts it.
	const { header } = await jwtDecrypt(token, decProfile());
	assert.equal(header.alg, "ECDH-ES+A256KW");
	assert.equal(header.enc, "A256GCM");
});

test("[LW-enc.3] encrypt enforces the claim discipline; decrypt validates it", async () => {
	// Missing iss / aud / exp are refused at encrypt time.
	await assert.rejects(new EncryptJWT("at+jwt").audience(AUD).expiresIn("5m").encrypt(ecdh.publicKey), MissingClaim);
	await assert.rejects(new EncryptJWT("at+jwt").issuer(ISS).expiresIn("5m").encrypt(ecdh.publicKey), MissingClaim);
	await assert.rejects(new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).encrypt(ecdh.publicKey), MissingClaim);
	// Over-cap lifetime is refused.
	await assert.rejects(new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("2h").encrypt(ecdh.publicKey), MaxLifetimeExceeded);

	// Every token gets a unique jti (readable only after decryption).
	const a = (await jwtDecrypt(await encToken(), decProfile())).payload.jti;
	const b = (await jwtDecrypt(await encToken(), decProfile())).payload.jti;
	assert.equal(typeof a, "string");
	assert.notEqual(a, b);

	// Decrypt validates typ/iss/aud: a token typed rt+jwt is refused by an at+jwt profile.
	const refresh = await new EncryptJWT("rt+jwt").issuer(ISS).audience(AUD).expiresIn("5m").encrypt(ecdh.publicKey);
	await assert.rejects(jwtDecrypt(refresh, decProfile()), JWTClaimValidationFailed);
	// Wrong audience is refused.
	const wrongAud = await new EncryptJWT("at+jwt").issuer(ISS).audience("https://evil.example.com").expiresIn("5m").encrypt(ecdh.publicKey);
	await assert.rejects(jwtDecrypt(wrongAud, decProfile()), JWTClaimValidationFailed);
});

test("[LW-enc.4] JWS and JWE never cross over", async () => {
	// A signed token (3 segments) handed to jwtDecrypt is rejected.
	const secret = generateSecret("HS256");
	const jws = await new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign(secret);
	assert.equal(jws.split(".").length, 3);
	await assert.rejects(jwtDecrypt(jws, decProfile()), JWTInvalid);

	// An encrypted token (5 segments) handed to jwtVerify is rejected.
	const jwe = await encToken();
	assert.equal(jwe.split(".").length, 5);
	const verifyProfile = defineProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: secret, maxTokenAge: "15m",
	});
	await assert.rejects(jwtVerify(jwe, verifyProfile), JWTInvalid);

	// And a real round-trip still works.
	const { payload } = await jwtDecrypt(jwe, decProfile());
	assert.equal(payload.iss, ISS);
});

test("[LW-enc.1] a dir key must match its content-encryption size", async () => {
	const dir = generateDirectKey("A256GCM"); // 32 bytes
	// Using it with a differently-sized enc is refused at encrypt time.
	await assert.rejects(
		new EncryptJWT("at+jwt", { contentEncryption: "A128GCM" }).issuer(ISS).audience(AUD).expiresIn("5m").encrypt(dir),
		Error
	);
});
