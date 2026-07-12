/**
 * Property: mutation. Flipping any character of a valid
 * token yields a rejection - and always a *typed* Lacewing error, never an
 * unhandled throw. Because every segment (header, payload, signature) is part
 * of the signing input or the signature itself, no single-character change can
 * survive verification.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
	SignJWT,
	jwtVerify,
	defineProfile,
	generateKeyPair,
	JWTError,
	type ExpectedJwtProfile,
} from "../../index.js";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";
const { publicKey, privateKey } = await generateKeyPair("EdDSA");

const profile: ExpectedJwtProfile = defineProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	algorithms: ["EdDSA"],
	keys: publicKey,
	maxTokenAge: "15m",
});

const validToken = await new SignJWT("at+jwt")
	.issuer(ISSUER)
	.audience(AUDIENCE)
	.subject("user-42")
	.claim("scope", "read")
	.expiresIn("5m")
	.sign(privateKey);

// base64url characters, the segment delimiter, and a couple of characters that
// are outright illegal in a token - all of them must lead to rejection.
const REPLACEMENTS = "ABCabc012-_.! ".split("");

test("[8725-3.3.1] flipping any single character of a valid token causes a typed rejection", async () => {
	await fc.assert(
		fc.asyncProperty(
			fc.nat({ max: validToken.length - 1 }),
			fc.constantFrom(...REPLACEMENTS),
			async (index, replacement) => {
				const original = validToken[index] as string;
				const ch = replacement === original ? (original === "A" ? "B" : "A") : replacement;
				const mutated = validToken.slice(0, index) + ch + validToken.slice(index + 1);
				fc.pre(mutated !== validToken);
				await assert.rejects(jwtVerify(mutated, profile), (error) => {
					assert.ok(error instanceof JWTError, `expected a JWTError, got ${(error as Error)?.constructor?.name}`);
					return true;
				});
			}
		),
		{ numRuns: 80 }
	);
});

test("the unmutated token still verifies (guards against a vacuous mutation test)", async () => {
	const { payload } = await jwtVerify(validToken, profile);
	assert.equal(payload.scope, "read");
});
