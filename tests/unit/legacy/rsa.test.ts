/**
 * Runs in its own process (node --test isolates files), so enabling legacy
 * algorithms here cannot leak into other suites.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair as joseGenerateKeyPair, SignJWT as JoseSignJWT } from "jose";
import { enableLegacyRSA } from "../../../src/legacy/rsa.js";
import { isValidAlgorithm } from "../../../src/lib/algorithms.js";
import { importKey } from "../../../src/key/import.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { jwtVerify } from "../../../src/jwt/verify.js";

const ISSUER = "https://legacy-idp.example.com";
const AUDIENCE = "https://api.example.com";

test("[8725-3.2.3] the whole RS* family requires the explicit opt-in, then interops", async () => {
	for (const alg of ["RS256", "RS384", "RS512"]) {
		assert.equal(isValidAlgorithm(alg), false, `${alg} must be absent by default`);
	}

	enableLegacyRSA(); // grep-loud opt-in for RS256 + RS384 + RS512

	for (const alg of ["RS256", "RS384", "RS512"]) {
		assert.equal(isValidAlgorithm(alg), true, `${alg} present after opt-in`);

		const { publicKey, privateKey } = await joseGenerateKeyPair(alg);
		const token = await new JoseSignJWT({})
			.setProtectedHeader({ alg, typ: "at+jwt" })
			.setIssuer(ISSUER)
			.setAudience(AUDIENCE)
			.setIssuedAt()
			.setJti(`legacy-${alg}`)
			.setExpirationTime("5m")
			.sign(privateKey);

		const key = await importKey(publicKey, alg);
		const profile = defineProfile({
			typ: "at+jwt",
			issuer: ISSUER,
			audience: AUDIENCE,
			algorithms: [alg],
			keys: key,
			maxTokenAge: "15m",
		});
		const verified = await jwtVerify(token, profile);
		assert.equal(verified.header.alg, alg);
	}

	// 'none' can never ride in through the legacy door.
	assert.equal(isValidAlgorithm("none"), false);
});

test("[8725-3.2.3] the rs256 backwards-compat entry still works", async () => {
	const { enableLegacyRS256 } = await import("../../../src/legacy/rs256.js");
	assert.equal(typeof enableLegacyRS256, "function");
});
