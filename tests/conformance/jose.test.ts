/**
 * Conformance / additive-strictness suite.
 *
 * Honesty note: this is **not** cross-implementation interop. jose is
 * Lacewing's own crypto engine, so a round-trip against jose proves
 * that Lacewing's strict pre-parse layer and policy checks are *additive* -
 * standard JOSE output passes through untouched when it meets policy, and is
 * rejected (typed) when it does not. The actual "the rest of the world can
 * read our tokens" proof lives in `golden.test.ts`, whose fixtures come from
 * RFC worked examples and non-jose tooling.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	SignJWT as JoseSignJWT,
	jwtVerify as joseJwtVerify,
	EncryptJWT as JoseEncryptJWT,
	jwtDecrypt as joseJwtDecrypt,
} from "jose";
import { SignJWT } from "../../src/jwt/sign.js";
import { jwtVerify } from "../../src/jwt/verify.js";
import { defineProfile } from "../../src/jwt/profile.js";
import { generateKeyPair } from "../../src/key/generate.js";
import { EncryptJWT } from "../../src/jwt/encrypt.js";
import { jwtDecrypt } from "../../src/jwt/decrypt.js";
import { defineDecryptionProfile } from "../../src/jwt/decryption_profile.js";
import { generateDirectKey } from "../../src/key/encryption.js";
import { JWTInvalid, MissingClaim } from "../../src/util/errors.js";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

// JWS: signed tokens

const { publicKey, privateKey } = await generateKeyPair("EdDSA");

const profile = defineProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	algorithms: ["EdDSA"],
	keys: publicKey,
	maxTokenAge: "15m",
});

function joseBuilder(): JoseSignJWT {
	return new JoseSignJWT({ scope: "read" })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setIssuedAt()
		.setJti("jose-jti-1")
		.setExpirationTime("5m");
}

test("Lacewing-signed tokens verify with jose (we emit standard JWTs)", async () => {
	const token = await new SignJWT("at+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.subject("user-42")
		.expiresIn("5m")
		.sign(privateKey);
	const result = await joseJwtVerify(token, publicKey.key as CryptoKey, {
		issuer: ISSUER,
		audience: AUDIENCE,
		typ: "at+jwt",
	});
	assert.equal(result.payload.sub, "user-42");
});

test("jose-signed tokens verify with Lacewing when they meet policy", async () => {
	const token = await joseBuilder()
		.setProtectedHeader({ alg: "EdDSA", typ: "at+jwt" })
		.sign(privateKey.key as CryptoKey);
	const verified = await jwtVerify(token, profile);
	assert.equal(verified.payload.scope, "read");
});

test("valid JOSE, invalid Lacewing: a token without typ is rejected", async () => {
	const token = await joseBuilder()
		.setProtectedHeader({ alg: "EdDSA" })
		.sign(privateKey.key as CryptoKey);
	await assert.rejects(jwtVerify(token, profile), JWTInvalid);
});

test("valid JOSE, invalid Lacewing: a token without exp is rejected", async () => {
	const token = await new JoseSignJWT({})
		.setProtectedHeader({ alg: "EdDSA", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setIssuedAt()
		.sign(privateKey.key as CryptoKey);
	await assert.rejects(jwtVerify(token, profile), MissingClaim);
});

// JWE: encrypted tokens (same additive-strictness contract)

const dirKey = generateDirectKey("A256GCM");
const dirKeyBytes = dirKey.key as Uint8Array;

const decryptionProfile = defineDecryptionProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	keyManagementAlgorithms: ["dir"],
	contentEncryptionAlgorithms: ["A256GCM"],
	key: dirKey,
	maxTokenAge: "15m",
});

function joseEncryptBuilder(): JoseEncryptJWT {
	return new JoseEncryptJWT({ scope: "read" })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setIssuedAt()
		.setJti("jose-jwe-jti-1")
		.setExpirationTime("5m");
}

test("[LW-enc.3] Lacewing-encrypted tokens decrypt with jose (we emit standard JWEs)", async () => {
	const token = await new EncryptJWT("at+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.subject("user-42")
		.expiresIn("5m")
		.encrypt(dirKey);
	const result = await joseJwtDecrypt(token, dirKeyBytes, {
		issuer: ISSUER,
		audience: AUDIENCE,
		typ: "at+jwt",
	});
	assert.equal(result.payload.sub, "user-42");
	assert.equal(result.protectedHeader.enc, "A256GCM");
});

test("[LW-enc.2] jose-encrypted tokens decrypt with Lacewing when they meet policy", async () => {
	const token = await joseEncryptBuilder()
		.setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "at+jwt" })
		.encrypt(dirKeyBytes);
	const decrypted = await jwtDecrypt(token, decryptionProfile);
	assert.equal(decrypted.payload.scope, "read");
});

test("[LW-enc.3] valid JOSE, invalid Lacewing: an encrypted token without typ is rejected", async () => {
	const token = await joseEncryptBuilder()
		.setProtectedHeader({ alg: "dir", enc: "A256GCM" })
		.encrypt(dirKeyBytes);
	await assert.rejects(jwtDecrypt(token, decryptionProfile), JWTInvalid);
});

test("[LW-enc.3] valid JOSE, invalid Lacewing: an encrypted token without exp is rejected", async () => {
	const token = await new JoseEncryptJWT({})
		.setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setIssuedAt()
		.setJti("jose-jwe-jti-2")
		.encrypt(dirKeyBytes);
	await assert.rejects(jwtDecrypt(token, decryptionProfile), MissingClaim);
});
