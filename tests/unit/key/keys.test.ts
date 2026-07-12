import { test } from "node:test";
import assert from "node:assert/strict";
import { exportJWK as joseExportJWK, generateKeyPair as joseGenerateKeyPair } from "jose";
import { importKey } from "../../../src/key/import.js";
import { generateKeyPair, generateSecret } from "../../../src/key/generate.js";
import { exportKeyJWK, exportKeyPEM } from "../../../src/key/export.js";
import {
	AlgorithmNotAllowed,
	EntropyCheckFailed,
	KeyExportFailed,
	KeyImportFailed,
	KeyTypeMismatch,
} from "../../../src/util/errors.js";
import type { StaticJWK } from "../../../src/types.js";

async function es256Jwks(): Promise<{ publicJwk: StaticJWK; privateJwk: StaticJWK }> {
	const { publicKey, privateKey } = await joseGenerateKeyPair("ES256", {
		extractable: true,
	});
	return {
		publicJwk: (await joseExportJWK(publicKey)) as StaticJWK,
		privateJwk: (await joseExportJWK(privateKey)) as StaticJWK,
	};
}

test("[8725-3.1.2] importKey binds the key to one algorithm", async () => {
	const { publicJwk } = await es256Jwks();
	const key = await importKey(publicJwk, "ES256");
	assert.equal(key.algorithm, "ES256");
	assert.equal(key.keyType, "public");
	assert.equal(key.__brand, "LacewingKey");
});

test("[8725-3.1.2] an EC JWK cannot be imported for a different key family", async () => {
	const { publicJwk } = await es256Jwks();
	await assert.rejects(importKey(publicJwk, "HS256"), KeyImportFailed);
	await assert.rejects(importKey(publicJwk, "PS256"), KeyTypeMismatch);
	await assert.rejects(importKey(publicJwk, "EdDSA"), KeyTypeMismatch);
});

test("[8725-3.1.2] curve mismatches are rejected", async () => {
	const { publicJwk } = await es256Jwks();
	await assert.rejects(importKey(publicJwk, "ES384"), KeyTypeMismatch);
});

test("a JWK declaring a conflicting alg is rejected", async () => {
	const { publicJwk } = await es256Jwks();
	await assert.rejects(
		importKey({ ...publicJwk, alg: "ES384" }, "ES256"),
		KeyTypeMismatch
	);
});

test("[8725-3.2.2] 'none' and legacy algorithms are not importable", async () => {
	const { publicJwk } = await es256Jwks();
	await assert.rejects(importKey(publicJwk, "none"), AlgorithmNotAllowed);
	await assert.rejects(importKey(publicJwk, "RS256"), AlgorithmNotAllowed);
});

test("[8725-3.5.2] weak HMAC secrets are rejected at import", async () => {
	await assert.rejects(importKey("secret123", "HS256"), EntropyCheckFailed);
	await assert.rejects(
		importKey("password-password-password-password", "HS256"),
		EntropyCheckFailed
	);
});

test("[8725-3.1.2] PEM key material is never accepted as an HMAC secret (CVE-2016-5431 class)", async () => {
	const { publicKey } = await generateKeyPair("ES256", { extractable: true });
	const pem = await exportKeyPEM(publicKey);
	await assert.rejects(importKey(pem, "HS256"), KeyTypeMismatch);
});

test("strong HMAC secrets import as secret keys", async () => {
	const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
	const key = await importKey(secret, "HS256");
	assert.equal(key.keyType, "secret");
	assert.equal(key.algorithm, "HS256");
});

test("PEM round-trip: private -> PKCS#8, public -> SPKI", async () => {
	const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
	const publicPem = await exportKeyPEM(publicKey);
	const privatePem = await exportKeyPEM(privateKey);
	assert.match(publicPem, /-----BEGIN PUBLIC KEY-----/);
	assert.match(privatePem, /-----BEGIN PRIVATE KEY-----/);
	const reimportedPublic = await importKey(publicPem, "EdDSA");
	const reimportedPrivate = await importKey(privatePem, "EdDSA");
	assert.equal(reimportedPublic.keyType, "public");
	assert.equal(reimportedPrivate.keyType, "private");
});

test("unsupported PEM types are rejected", async () => {
	await assert.rejects(
		importKey("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----", "PS256"),
		KeyImportFailed
	);
});

test("generateKeyPair defaults to EdDSA (asymmetric-first)", async () => {
	const { publicKey, privateKey } = await generateKeyPair();
	assert.equal(publicKey.algorithm, "EdDSA");
	assert.equal(privateKey.algorithm, "EdDSA");
	assert.equal(publicKey.keyType, "public");
	assert.equal(privateKey.keyType, "private");
});

test("generateKeyPair refuses symmetric algorithms and vice versa", async () => {
	await assert.rejects(generateKeyPair("HS256"), KeyTypeMismatch);
	assert.throws(() => generateSecret("ES256"), KeyTypeMismatch);
});

test("generateSecret produces entropy-valid secrets at the minimum size", async () => {
	const key = generateSecret();
	assert.equal(key.algorithm, "HS256");
	assert.equal((key.key as Uint8Array).length, 32);
	assert.equal((generateSecret("HS512").key as Uint8Array).length, 64);
	// It must be re-importable (passes its own entropy checks).
	await assert.doesNotReject(importKey(key.key as Uint8Array, "HS256"));
});

test("keys are non-extractable by default; export fails loudly", async () => {
	const { privateKey } = await generateKeyPair("EdDSA");
	await assert.rejects(exportKeyPEM(privateKey), KeyExportFailed);
	await assert.rejects(exportKeyJWK(privateKey), KeyExportFailed);
});

test("exported JWKs carry their bound alg and use", async () => {
	const { publicKey } = await generateKeyPair("EdDSA", { extractable: true });
	const jwk = await exportKeyJWK(publicKey);
	assert.equal(jwk.alg, "EdDSA");
	assert.equal(jwk.use, "sig");
	assert.equal(jwk.kty, "OKP");
	const secretJwk = await exportKeyJWK(generateSecret("HS256"));
	assert.equal(secretJwk.kty, "oct");
	assert.equal(typeof secretJwk.k, "string");
});

test("symmetric secrets have no PEM form", async () => {
	await assert.rejects(exportKeyPEM(generateSecret("HS256")), KeyExportFailed);
});
