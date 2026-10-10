/**
 * RFC 8725 §3.1 - perform algorithm verification. Public-API proofs that the
 * verifier, not the token header, decides which algorithm is acceptable, and
 * that a key is welded to exactly one algorithm.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { defineProfile, jwtVerify, importKey, exportKeyJWK, AlgorithmNotAllowed, JWKSNoMatchingKey } from "../../index.js";
import { craftHmacToken } from "../helpers.js";
import { AUDIENCE, ISSUER, eddsa, es256, hmac, eddsaProfile, signValid } from "./_shared.js";
import { createHmac } from "node:crypto";
import { Buffer } from "node:buffer";

test("[8725-3.1.1] the verifier's allowlist decides the algorithm, not the token header", async () => {
	// A token whose header names an algorithm the profile does not list is
	// refused before any key is consulted.
	const forged = craftHmacToken({ alg: "HS256", typ: "at+jwt" }, {
		iss: ISSUER,
		aud: AUDIENCE,
		exp: Math.floor(Date.now() / 1000) + 300,
		iat: Math.floor(Date.now() / 1000),
	}, hmac.key as Uint8Array);
	await assert.rejects(jwtVerify(forged, eddsaProfile()), AlgorithmNotAllowed);
});

test("[8725-3.1.2] a key is bound to one algorithm - an ES256 token cannot verify against an EdDSA key", async () => {
	const es256Token = await signValid(es256.privateKey);
	// Profile lists both algorithms, but the trusted key is EdDSA-only, so an
	// ES256 token is rejected at key resolution.
	const profile = defineProfile({
		typ: "at+jwt",
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["EdDSA", "ES256"],
		keys: eddsa.publicKey,
		maxTokenAge: "15m",
	});
	await assert.rejects(jwtVerify(es256Token, profile), AlgorithmNotAllowed);
});

test("[8725-3.1.2] a public key text cannot be re-imported as an HMAC secret (key confusion)", async () => {
	const publicJwk = await exportKeyJWK(eddsa.publicKey);
	await assert.rejects(importKey(publicJwk, "HS256"), Error);
});

test("[8725-3.1.3] the alg header must match the algorithm the signature actually uses", async () => {
	// Header claims HS256; the MAC is really HS384. Verification must fail.
	const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "at+jwt" })).toString("base64url");
	const payload = Buffer.from(
		JSON.stringify({ iss: ISSUER, aud: AUDIENCE, exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000) })
	).toString("base64url");
	const wrongMac = createHmac("sha384", hmac.key as Uint8Array).update(`${header}.${payload}`).digest();
	await assert.rejects(
		jwtVerify(`${header}.${payload}.${Buffer.from(wrongMac).toString("base64url")}`, eddsaProfile({ algorithms: ["HS256"], keys: hmac })),
		Error
	);
});

// An `oct` JWK with no `alg` member, shared by the JWKS binding tests below.
const unboundSecret = new Uint8Array(64).map((_, i) => (i * 97 + 13) & 0xff);
const unboundOctJwk = { kty: "oct" as const, k: Buffer.from(unboundSecret).toString("base64url"), kid: "unbound" };

function hmacProfile(algorithms: string[], keys: Parameters<typeof defineProfile>[0]["keys"]): ReturnType<typeof defineProfile> {
	return defineProfile({ typ: "at+jwt", issuer: ISSUER, audience: AUDIENCE, algorithms, keys, maxTokenAge: "15m" });
}

function unboundToken(alg: string): string {
	const now = Math.floor(Date.now() / 1000);
	return craftHmacToken({ alg, typ: "at+jwt", kid: "unbound" }, { iss: ISSUER, aud: AUDIENCE, exp: now + 300, iat: now }, unboundSecret, alg);
}

test("[8725-3.1.2] a JWKS key without alg is refused when the profile allows several algorithms it could serve", async () => {
	const profile = hmacProfile(["HS256", "HS384", "HS512"], { keys: [unboundOctJwk] });
	for (const alg of ["HS256", "HS384", "HS512"]) {
		await assert.rejects(jwtVerify(unboundToken(alg), profile), JWKSNoMatchingKey);
	}
});

test("[8725-3.1.2] a JWKS key without alg is bound by the allowlist when only one algorithm could use it", async () => {
	const profile = hmacProfile(["HS384", "EdDSA"], { keys: [unboundOctJwk] });
	await assert.doesNotReject(jwtVerify(unboundToken("HS384"), profile));
});

test("[8725-3.1.2] a JWKS key with alg set serves only that algorithm under a multi-algorithm profile", async () => {
	const profile = hmacProfile(["HS256", "HS384", "HS512"], { keys: [{ ...unboundOctJwk, alg: "HS384" }] });
	await assert.doesNotReject(jwtVerify(unboundToken("HS384"), profile));
	await assert.rejects(jwtVerify(unboundToken("HS512"), profile), JWKSNoMatchingKey);
});

test("[8725-3.1.3] a custom key source that resolves a different algorithm than the header is refused", async () => {
	const keys = { getVerificationKey: async () => ({ alg: "HS256", key: unboundSecret }) } as never;
	const profile = hmacProfile(["HS256", "HS512"], keys);
	await assert.doesNotReject(jwtVerify(unboundToken("HS256"), profile));
	await assert.rejects(jwtVerify(unboundToken("HS512"), profile), AlgorithmNotAllowed);
});
