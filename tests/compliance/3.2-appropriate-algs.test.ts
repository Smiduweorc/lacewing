/**
 * RFC 8725 §3.2 - use appropriate algorithms. `none` is unrepresentable,
 * weak algorithms are simply absent, and the registry is the single point of
 * change (cryptographic agility, §3.2.4).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { jwtVerify, importKey, generateKeyPair, AlgorithmNotAllowed } from "../../index.js";
import { craftUnsignedToken, standardClaims } from "../helpers.js";
import { hmacProfile } from "./_shared.js";

test("[8725-3.2.1] every algorithm the public API accepts is a current, appropriate one", async () => {
	// Importing under a bogus/legacy identifier is refused outright.
	for (const bogus of ["RS256", "RSA1_5", "HS1", "made-up"]) {
		await assert.rejects(importKey("x".repeat(64), bogus), AlgorithmNotAllowed);
	}
	// A profile cannot even be scoped to an absent algorithm (checked at build).
	const { generateSecret, defineProfile } = await import("../../index.js");
	assert.throws(
		() =>
			defineProfile({
				typ: "at+jwt",
				issuer: "https://a",
				audience: "https://b",
				algorithms: ["RS256"],
				keys: generateSecret("HS256"),
				maxTokenAge: "5m",
			}),
		Error
	);
});

test("[8725-3.2.2] alg 'none' is rejected on verify, in every casing", async () => {
	for (const alg of ["none", "None", "NONE", "nOnE"]) {
		await assert.rejects(
			jwtVerify(craftUnsignedToken({ alg, typ: "at+jwt" }, standardClaims(), "AA"), hmacProfile()),
			AlgorithmNotAllowed,
			`alg: ${alg}`
		);
	}
});

test("[8725-3.2.2] 'none' is unrepresentable on the sign path - there is no key for it", async () => {
	// generateKeyPair/importKey never yield a `none` key: the registry has no
	// such entry, so an attacker cannot construct a signer for it.
	await assert.rejects(importKey("x".repeat(64), "none"), AlgorithmNotAllowed);
	await assert.rejects(generateKeyPair("none" as "EdDSA"), Error);
});

test("[8725-3.2.3] RSAES-PKCS1-v1_5 / RS* signatures are not in the default registry", async () => {
	await assert.rejects(importKey("x".repeat(64), "RS256"), AlgorithmNotAllowed);
	await assert.rejects(importKey("x".repeat(64), "RSA1_5"), AlgorithmNotAllowed);
});

test("[8725-3.2.4] cryptographic agility: adding an algorithm is one registry entry (the legacy opt-in proves it)", async () => {
	// RS256 is absent by default...
	await assert.rejects(importKey("x".repeat(64), "RS256"), AlgorithmNotAllowed);
	// ...and enabling it touches only the registry, after which the rest of the
	// stack (importKey, profiles, JWKS) accepts it - no other code changes.
	const rsa = await generateKeyPair("PS256", { extractable: true }); // a real RSA key pair
	const { exportKeyPEM } = await import("../../index.js");
	const spki = await exportKeyPEM(rsa.publicKey);
	await assert.rejects(importKey(spki, "RS256"), AlgorithmNotAllowed);
	const { enableLegacyRS256 } = await import("../../src/legacy/rs256.js");
	enableLegacyRS256();
	const imported = await importKey(spki, "RS256");
	assert.equal(imported.algorithm, "RS256");
});
