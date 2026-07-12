/**
 * @security - error-message hygiene. A rejection message
 * must never echo raw token content: no signature bytes, no claim values, no
 * attacker-chosen strings. Otherwise the error becomes a log-injection vector
 * or an oracle. This sweeps tokens that fail at every stage of the pipeline.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
	jwtVerify,
	defineProfile,
	generateSecret,
	type ExpectedJwtProfile,
} from "../../index.js";
import { craftHmacToken, craftUnsignedToken, nowSeconds, standardClaims } from "../helpers.js";

const skip = process.env.LACEWING_SKIP_SECURITY === "1";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";
const hmac = generateSecret("HS256");
const MARKER = "MARKER-a1b2c3d4e5f6-SENSITIVE";

const profile: ExpectedJwtProfile = defineProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	algorithms: ["HS256"],
	keys: hmac,
	maxTokenAge: "15m",
});

const now = nowSeconds();
// A token that fails at each distinct stage, each carrying the marker somewhere.
const tokens: Array<{ label: string; token: string }> = [
	{
		label: "forbidden header param",
		token: craftHmacToken({ alg: "HS256", typ: "at+jwt", jku: MARKER }, standardClaims(), hmac.key as Uint8Array),
	},
	{
		label: "algorithm not allowed",
		token: craftUnsignedToken({ alg: MARKER, typ: "at+jwt" }, standardClaims(), "AA"),
	},
	{
		label: "bad signature",
		token: craftHmacToken({ alg: "HS256", typ: "at+jwt" }, standardClaims({ sub: MARKER }), generateSecret("HS256").key as Uint8Array),
	},
	{
		label: "expired",
		token: craftHmacToken({ alg: "HS256", typ: "at+jwt" }, standardClaims({ sub: MARKER, iat: now - 600, exp: now - 300 }), hmac.key as Uint8Array),
	},
	{
		label: "wrong audience",
		token: craftHmacToken({ alg: "HS256", typ: "at+jwt" }, standardClaims({ aud: MARKER }), hmac.key as Uint8Array),
	},
];

test("@security [8725-3.10.1] rejection messages never echo the marker or raw token segments", { skip }, async () => {
	for (const { label, token } of tokens) {
		let message = "";
		await assert.rejects(jwtVerify(token, profile), (error) => {
			message = (error as Error).message;
			return true;
		});
		assert.ok(!message.includes(MARKER), `${label}: message leaked the marker: ${message}`);
		for (const segment of token.split(".")) {
			if (segment.length >= 8) {
				assert.ok(!message.includes(segment), `${label}: message leaked a raw segment`);
			}
		}
	}
});
