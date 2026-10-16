/**
 * The legacy RS* opt-in is a value passed at the call site. Nothing here
 * relies on test files running in separate processes: every test opts in and
 * then checks that a caller who did not is still refused, in this process.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { generateKeyPair as joseGenerateKeyPair, SignJWT as JoseSignJWT } from "jose";
import { refusal } from "../../helpers.js";
import * as rsa from "../../../src/legacy/rsa.js";
import * as rs256 from "../../../src/legacy/rs256.js";
import { LEGACY_RS256, LEGACY_RS384, LEGACY_RS512, LEGACY_RSA } from "../../../src/legacy/rsa.js";
import { importKey } from "../../../src/key/import.js";
import { exportKeyJWK } from "../../../src/key/export.js";
import { generateKeyPair } from "../../../src/key/generate.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { jwtVerify } from "../../../src/jwt/verify.js";
import { getAlgorithmProperties } from "../../../src/extension.js";
import type { AlgorithmInfo } from "../../../src/lib/algorithms.js";
import type { StaticJWK } from "../../../src/types.js";

const ISSUER = "https://legacy-idp.example.com";
const AUDIENCE = "https://api.example.com";

async function legacyToken(alg: string): Promise<{ token: string; publicKey: CryptoKey }> {
	const { publicKey, privateKey } = await joseGenerateKeyPair(alg);
	const token = await new JoseSignJWT({})
		.setProtectedHeader({ alg, typ: "at+jwt" })
		.setIssuer(ISSUER)
		.setAudience(AUDIENCE)
		.setIssuedAt()
		.setJti(`legacy-${alg}`)
		.setExpirationTime("5m")
		.sign(privateKey);
	return { token, publicKey };
}

function profileFor(algorithms: ReadonlyArray<string | AlgorithmInfo>, keys: Parameters<typeof defineProfile>[0]["keys"]): ReturnType<typeof defineProfile> {
	return defineProfile({ typ: "at+jwt", issuer: ISSUER, audience: AUDIENCE, algorithms, keys, maxTokenAge: "15m" });
}

test("the legacy modules export descriptors only, and the rs256 entry re-exports the same object", () => {
	assert.deepEqual(Object.keys(rsa).sort(), ["LEGACY_RS256", "LEGACY_RS384", "LEGACY_RS512", "LEGACY_RSA"]);
	assert.deepEqual(Object.keys(rs256), ["LEGACY_RS256"]);
	assert.equal(rs256.LEGACY_RS256, LEGACY_RS256);
	assert.deepEqual(LEGACY_RSA, [LEGACY_RS256, LEGACY_RS384, LEGACY_RS512]);
	assert.equal(Object.isFrozen(LEGACY_RSA), true);
});

for (const descriptor of [LEGACY_RS256, LEGACY_RS384, LEGACY_RS512]) {
	const alg = descriptor.name;

	test(`[8725-3.2.3] ${alg} interops where its descriptor is passed, and nowhere else`, async () => {
		const { token, publicKey } = await legacyToken(alg);

		const key = await importKey(publicKey, descriptor);
		assert.equal(key.algorithm, alg);
		const verified = await jwtVerify(token, profileFor([descriptor], key));
		assert.equal(verified.header.alg, alg);

		// Same process, right after the opt-in above: the name as a string is
		// still refused everywhere.
		await assert.rejects(importKey(publicKey, alg), refusal("ALGORITHM_NOT_ALLOWED"));
		assert.throws(() => profileFor([alg], key), refusal("ALGORITHM_NOT_ALLOWED"));
		assert.throws(() => getAlgorithmProperties(alg), refusal("ALGORITHM_NOT_ALLOWED"));
		// A profile that lists only modern algorithms refuses the token.
		const modern = profileFor(["PS256"], { keys: [await exportKeyJWK(key)] });
		await assert.rejects(jwtVerify(token, modern), refusal("ALGORITHM_NOT_ALLOWED"));
	});
}

test("[8725-3.2.3] a profile listing a legacy descriptor verifies through a JWKS too", async () => {
	const { token, publicKey } = await legacyToken("RS256");
	const jwk = { ...(await exportKeyJWK(await importKey(publicKey, LEGACY_RS256))), kid: "legacy" };
	const profile = profileFor(LEGACY_RSA, { keys: [jwk] });
	const verified = await jwtVerify(token, profile);
	assert.equal(verified.header.alg, "RS256");
});

test("a key bound to a legacy algorithm is refused by a profile that does not list it", async () => {
	const { publicKey } = await legacyToken("RS256");
	const key = await importKey(publicKey, LEGACY_RS256);
	assert.throws(() => profileFor(["PS256"], key), TypeError);
	assert.throws(() => profileFor([LEGACY_RS384], key), TypeError);
});

test("legacy key pairs can be generated from the descriptor, never from the name", async () => {
	const pair = await generateKeyPair(LEGACY_RS256);
	assert.equal(pair.privateKey.algorithm, "RS256");
	await assert.rejects(generateKeyPair("RS256"), refusal("ALGORITHM_NOT_ALLOWED"));
});

test("[8725-3.2.3] legacy RSA keys keep the 2048-bit floor", async () => {
	// jose will not generate a key this small; node:crypto still will.
	const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
	const jwk = publicKey.export({ format: "jwk" }) as StaticJWK;
	await assert.rejects(importKey(jwk, LEGACY_RS256), refusal("KEY_TYPE_MISMATCH"));
});
