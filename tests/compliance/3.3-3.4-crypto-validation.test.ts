/**
 * RFC 8725 §3.3 - validate cryptographic operations; §3.4 - validate
 * cryptographic inputs (curve points, signature encoding).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { defineProfile, jwtVerify, generateSecret, JWTInvalid } from "../../index.js";
import { b64u, craftUnsignedToken, standardClaims } from "../helpers.js";
import { createHmac } from "node:crypto";
import { AUDIENCE, ISSUER, es256, hmac, hmacProfile, signValid } from "./_shared.js";

test("[8725-3.3.1] tampered, truncated and empty signatures are all rejected", async () => {
	const token = await signValid(hmac);
	const [h, p] = token.split(".") as [string, string, string];
	const otherSecret = generateSecret("HS256").key as Uint8Array;
	const forgedMac = createHmac("sha256", otherSecret).update(`${h}.${p}`).digest();
	for (const bad of [`${h}.${p}.`, `${h}.${p}.AAAA`, `${h}.${p}.${b64u(forgedMac)}`]) {
		await assert.rejects(jwtVerify(bad, hmacProfile()), JWTInvalid);
	}
});

test("[8725-3.4.1] all-zero ECDSA signatures (psychic signatures, CVE-2022-21449 class) are rejected", async () => {
	const es256Profile = defineProfile({
		typ: "at+jwt",
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["ES256"],
		keys: es256.publicKey,
		maxTokenAge: "15m",
	});
	const token = craftUnsignedToken({ alg: "ES256", typ: "at+jwt" }, standardClaims(), b64u(new Uint8Array(64)));
	await assert.rejects(jwtVerify(token, es256Profile), JWTInvalid);
});
