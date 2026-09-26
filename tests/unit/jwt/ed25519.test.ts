/**
 * `Ed25519` is RFC 9864's fully-specified name for the signature `EdDSA`
 * already covers. It is its own registry entry, so a key or profile bound to
 * one name does not accept the other: a token says which name it was signed
 * under, and the profile decides which names it allows.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { exportJWK, generateKeyPair as joseGenerateKeyPair, SignJWT as JoseSignJWT } from "jose";
import { SignJWT } from "../../../src/jwt/sign.js";
import { jwtVerify } from "../../../src/jwt/verify.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { generateKeyPair } from "../../../src/key/generate.js";
import { importKey } from "../../../src/key/import.js";
import { exportKeyJWK } from "../../../src/key/export.js";
import { createLocalJWKSet } from "../../../src/jwks/local.js";
import {
	AlgorithmNotAllowed,
	JWKSNoMatchingKey,
	KeyTypeMismatch,
} from "../../../src/util/errors.js";
import type { StaticJWK } from "../../../src/types.js";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

function sign(privateKey: Parameters<SignJWT["sign"]>[0]): Promise<string> {
	return new SignJWT("at+jwt")
		.issuer(ISSUER)
		.audience(AUDIENCE)
		.subject("user-42")
		.expiresIn("5m")
		.sign(privateKey);
}

function profile(
	algorithms: string[],
	keys: Parameters<typeof defineProfile>[0]["keys"]
): ReturnType<typeof defineProfile> {
	return defineProfile({
		typ: "at+jwt",
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms,
		keys,
		maxTokenAge: "15m",
	});
}

// Raw WebCrypto keys, as a client holding its own key would have them, never
// having passed through Lacewing.
function webCryptoPair(): ReturnType<typeof joseGenerateKeyPair> {
	return joseGenerateKeyPair("Ed25519", { extractable: true });
}

test("[8725-3.2.4] Ed25519 signs and verifies from its one registry entry", async () => {
	const { publicKey, privateKey } = await generateKeyPair("Ed25519");
	assert.equal(publicKey.algorithm, "Ed25519");
	const token = await sign(privateKey);
	const verified = await jwtVerify(token, profile(["Ed25519"], publicKey));
	assert.equal(verified.header.alg, "Ed25519");
	assert.equal(verified.payload.sub, "user-42");
});

test("a WebCrypto Ed25519 CryptoKey imports under the Ed25519 name", async () => {
	const pair = await webCryptoPair();
	const publicKey = await importKey(pair.publicKey, "Ed25519");
	const privateKey = await importKey(pair.privateKey, "Ed25519");
	assert.equal(publicKey.keyType, "public");
	assert.equal(privateKey.keyType, "private");
	await jwtVerify(await sign(privateKey), profile(["Ed25519"], publicKey));
});

test("a non-Ed25519 CryptoKey is refused under the Ed25519 name", async () => {
	const ec = await joseGenerateKeyPair("ES256");
	await assert.rejects(importKey(ec.publicKey, "Ed25519"), KeyTypeMismatch);
});

test("a JWK that declares EdDSA is not imported as Ed25519, and the reverse", async () => {
	const pair = await webCryptoPair();
	const jwk = (await exportJWK(pair.publicKey)) as StaticJWK;
	await assert.rejects(importKey({ ...jwk, alg: "EdDSA" }, "Ed25519"), KeyTypeMismatch);
	await assert.rejects(importKey({ ...jwk, alg: "Ed25519" }, "EdDSA"), KeyTypeMismatch);
	assert.equal((await importKey(jwk, "Ed25519")).algorithm, "Ed25519");
	assert.equal((await importKey({ ...jwk, alg: "Ed25519" }, "Ed25519")).algorithm, "Ed25519");
});

test("an exported Ed25519 key carries the Ed25519 name", async () => {
	const { publicKey } = await generateKeyPair("Ed25519", { extractable: true });
	const jwk = await exportKeyJWK(publicKey);
	assert.equal(jwk.alg, "Ed25519");
	assert.equal(jwk.kty, "OKP");
	assert.equal(jwk.crv, "Ed25519");
});

test("[8725-3.1.1] an EdDSA-only profile refuses a token signed under Ed25519", async () => {
	const { publicKey, privateKey } = await generateKeyPair("Ed25519");
	const eddsa = await generateKeyPair("EdDSA");
	const token = await sign(privateKey);
	await assert.rejects(jwtVerify(token, profile(["EdDSA"], eddsa.publicKey)), AlgorithmNotAllowed);
	// Allowlisting both names does not let a key bound to one verify the other.
	const jwk = (await exportJWK(publicKey.key as CryptoKey)) as StaticJWK;
	const eddsaBound = await importKey(jwk, "EdDSA");
	await assert.rejects(
		jwtVerify(token, profile(["EdDSA", "Ed25519"], eddsaBound)),
		AlgorithmNotAllowed
	);
});

test("a JWKS entry with no alg serves an Ed25519 token; one pinned to EdDSA does not", async () => {
	const pair = await webCryptoPair();
	const jwk = { ...((await exportJWK(pair.publicKey)) as StaticJWK), kid: "k1" };
	const token = await new JoseSignJWT({ sub: "user-42" })
		.setProtectedHeader({ alg: "Ed25519", typ: "at+jwt", kid: "k1" })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setIssuedAt()
		.setJti("ed25519-jwks")
		.setExpirationTime("5m")
		.sign(pair.privateKey);

	const open = profile(["Ed25519"], createLocalJWKSet({ keys: [jwk] }));
	assert.equal((await jwtVerify(token, open)).header.alg, "Ed25519");

	const pinned = profile(["Ed25519"], createLocalJWKSet({ keys: [{ ...jwk, alg: "EdDSA" }] }));
	await assert.rejects(jwtVerify(token, pinned), JWKSNoMatchingKey);
});
