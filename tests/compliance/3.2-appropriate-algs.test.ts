/**
 * RFC 8725 §3.2 - use appropriate algorithms. `none` is unrepresentable,
 * weak algorithms are absent from the default set, and that set is the single
 * point of change (cryptographic agility, §3.2.4).
 *
 * The default set is a constant, not process state: these tests opt into the
 * legacy RS* descriptors first and then prove the defaults are untouched, so
 * they hold however the test runner groups files into processes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	jwtVerify,
	importKey,
	generateKeyPair,
	generateSecret,
	defineProfile,
	exportKeyPEM,
	createLocalJWKSet,
	exportKeyJWK,
} from "../../index.js";
import { getAlgorithmProperties } from "../../src/extension.js";
import { LEGACY_RS256, LEGACY_RSA } from "../../src/legacy/rsa.js";
import { SetAlg } from "../../src/types.js";
import { craftUnsignedToken, standardClaims, refusal } from "../helpers.js";
import { hmacProfile } from "./_shared.js";

test("[8725-3.2.1] every algorithm the public API accepts is a current, appropriate one", async () => {
	// Importing under a bogus/legacy identifier is refused outright.
	for (const bogus of ["RS256", "RSA1_5", "HS1", "made-up"]) {
		await assert.rejects(importKey("x".repeat(64), bogus), refusal("ALGORITHM_NOT_ALLOWED"));
	}
	// A profile cannot even be scoped to an absent algorithm (checked at build).
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
		refusal("ALGORITHM_NOT_ALLOWED")
	);
});

test("[8725-3.2.2] alg 'none' is rejected on verify, in every casing", async () => {
	for (const alg of ["none", "None", "NONE", "nOnE"]) {
		await assert.rejects(
			jwtVerify(craftUnsignedToken({ alg, typ: "at+jwt" }, standardClaims(), "AA"), hmacProfile()),
			refusal("ALGORITHM_NOT_ALLOWED"),
			`alg: ${alg}`
		);
	}
});

test("[8725-3.2.2] 'none' is unrepresentable on the sign path - there is no key for it", async () => {
	// generateKeyPair/importKey never yield a `none` key: there is no
	// descriptor for it, so an attacker cannot construct a signer for it.
	await assert.rejects(importKey("x".repeat(64), "none"), refusal("ALGORITHM_NOT_ALLOWED"));
	await assert.rejects(generateKeyPair("none"), refusal("ALGORITHM_NOT_ALLOWED"));
	// Nor through a descriptor: a forged one is refused by identity.
	const forged = Object.freeze({ name: "none", kty: "oct", minKeyBits: 0 } as const);
	await assert.rejects(importKey("x".repeat(64), forged), refusal("ALGORITHM_NOT_ALLOWED"));
	assert.equal(LEGACY_RSA.some((info) => info.name.toLowerCase() === "none"), false);
});

test("[8725-3.2.3] RSAES-PKCS1-v1_5 / RS* signatures are not in the default set", async () => {
	await assert.rejects(importKey("x".repeat(64), "RS256"), refusal("ALGORITHM_NOT_ALLOWED"));
	await assert.rejects(importKey("x".repeat(64), "RSA1_5"), refusal("ALGORITHM_NOT_ALLOWED"));
});

test("[8725-3.2.3] the defaults refuse RS256 even after another caller in the same process opted in", async () => {
	const rsa = await generateKeyPair("PS256", { extractable: true });
	const spki = await exportKeyPEM(rsa.publicKey);
	// Another part of this process opts in, with a key and a profile of its own:
	const legacyKey = await importKey(spki, LEGACY_RS256);
	defineProfile({
		typ: "at+jwt",
		issuer: "https://legacy-idp.example.com",
		audience: "https://b",
		algorithms: [LEGACY_RS256],
		keys: legacyKey,
		maxTokenAge: "5m",
	});
	// Every default path is exactly as strict as before.
	await assert.rejects(importKey(spki, "RS256"), refusal("ALGORITHM_NOT_ALLOWED"));
	await assert.rejects(generateKeyPair("RS256"), refusal("ALGORITHM_NOT_ALLOWED"));
	assert.throws(() => getAlgorithmProperties("RS256"), refusal("ALGORITHM_NOT_ALLOWED"));
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
		refusal("ALGORITHM_NOT_ALLOWED")
	);
	// And a JWKS holding an RS256 key serves it to no profile that left RS256 out.
	const jwks = createLocalJWKSet({ keys: [{ ...(await exportKeyJWK(legacyKey)), kid: "k" }] });
	await assert.rejects(
		jwks.getVerificationKey({ alg: SetAlg("RS256"), typ: "at+jwt", kid: "k" }, [getAlgorithmProperties("PS256")]),
		refusal("ALGORITHM_NOT_ALLOWED")
	);
});

test("[8725-3.2.4] cryptographic agility: an algorithm outside the defaults is one descriptor, accepted by the whole stack", async () => {
	// RS256 is absent by default...
	const rsa = await generateKeyPair("PS256", { extractable: true }); // a real RSA key pair
	const spki = await exportKeyPEM(rsa.publicKey);
	await assert.rejects(importKey(spki, "RS256"), refusal("ALGORITHM_NOT_ALLOWED"));
	// ...and its descriptor, passed where it is wanted, is all importKey,
	// profiles and JWKS sets need: no other code changes.
	const imported = await importKey(spki, LEGACY_RS256);
	assert.equal(imported.algorithm, "RS256");
	const profile = defineProfile({
		typ: "at+jwt",
		issuer: "https://a",
		audience: "https://b",
		algorithms: [LEGACY_RS256],
		keys: imported,
		maxTokenAge: "5m",
	});
	assert.deepEqual(profile.alg, [LEGACY_RS256]);
});
