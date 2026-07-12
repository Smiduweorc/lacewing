/**
 * Runs in its own process (node --test isolates files), so enabling the
 * legacy algorithm here cannot leak into other suites.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair as joseGenerateKeyPair, SignJWT as JoseSignJWT } from "jose";
import { enableLegacyRS256 } from "../../../src/legacy/rs256.js";
import { isValidAlgorithm } from "../../../src/lib/algorithms.js";
import { importKey } from "../../../src/key/import.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { jwtVerify } from "../../../src/jwt/verify.js";
import { AlgorithmNotAllowed } from "../../../src/util/errors.js";

test("[8725-3.2.3] RS256 requires the explicit legacy opt-in, then interops", async () => {
	assert.equal(isValidAlgorithm("RS256"), false);
	assert.throws(
		() =>
			defineProfile({
				typ: "at+jwt",
				issuer: "https://legacy-idp.example.com",
				audience: "https://api.example.com",
				algorithms: ["RS256"],
				keys: { keys: [] },
				maxTokenAge: "15m",
			}),
		AlgorithmNotAllowed
	);

	// The grep-loud opt-in:
	enableLegacyRS256();
	assert.equal(isValidAlgorithm("RS256"), true);

	// Interop: verify a token from a legacy RS256 issuer (simulated by jose).
	const { publicKey, privateKey } = await joseGenerateKeyPair("RS256");
	const token = await new JoseSignJWT({})
		.setProtectedHeader({ alg: "RS256", typ: "at+jwt" })
		.setIssuer("https://legacy-idp.example.com")
		.setAudience("https://api.example.com")
		.setIssuedAt()
		.setJti("legacy-1")
		.setExpirationTime("5m")
		.sign(privateKey);
	const key = await importKey(publicKey, "RS256");
	const profile = defineProfile({
		typ: "at+jwt",
		issuer: "https://legacy-idp.example.com",
		audience: "https://api.example.com",
		algorithms: ["RS256"],
		keys: key,
		maxTokenAge: "15m",
	});
	const verified = await jwtVerify(token, profile);
	assert.equal(verified.header.alg, "RS256");

	// 'none' can never ride in through the legacy door.
	assert.equal(isValidAlgorithm("none"), false);
});
