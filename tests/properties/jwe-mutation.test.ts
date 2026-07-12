/**
 * Property: JWE mutation - the encrypted-token counterpart
 * of `mutation.test.ts`. Flipping any character of a valid compact JWE yields
 * a rejection, always as a *typed* Lacewing error. Every character is covered:
 * the header is the AEAD's additional authenticated data, the encrypted key /
 * IV / ciphertext / tag are all inputs to authenticated decryption, and a
 * mutated dot breaks the five-segment structure.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
	EncryptJWT,
	jwtDecrypt,
	defineDecryptionProfile,
	generateEncryptionSecret,
	JWTError,
	type ExpectedDecryptionProfile,
} from "../../index.js";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

// A256KW rather than dir, so the encrypted-key segment is non-empty and the
// mutation space includes all five segments.
const key = generateEncryptionSecret("A256KW");

const profile: ExpectedDecryptionProfile = defineDecryptionProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	keyManagementAlgorithms: ["A256KW"],
	contentEncryptionAlgorithms: ["A256GCM"],
	key,
	maxTokenAge: "15m",
});

const validToken = await new EncryptJWT("at+jwt")
	.issuer(ISSUER)
	.audience(AUDIENCE)
	.subject("user-42")
	.claim("scope", "read")
	.expiresIn("5m")
	.encrypt(key);

// base64url characters, the segment delimiter, and characters that are
// outright illegal in a token - all of them must lead to rejection.
const REPLACEMENTS = "ABCabc012-_.! ".split("");

test("[8725-3.3.1][LW-enc.2] flipping any single character of a valid JWE causes a typed rejection", async () => {
	await fc.assert(
		fc.asyncProperty(
			fc.nat({ max: validToken.length - 1 }),
			fc.constantFrom(...REPLACEMENTS),
			async (index, replacement) => {
				const original = validToken[index] as string;
				const ch = replacement === original ? (original === "A" ? "B" : "A") : replacement;
				const mutated = validToken.slice(0, index) + ch + validToken.slice(index + 1);
				fc.pre(mutated !== validToken);
				await assert.rejects(jwtDecrypt(mutated, profile), (error) => {
					assert.ok(error instanceof JWTError, `expected a JWTError, got ${(error as Error)?.constructor?.name}`);
					return true;
				});
			}
		),
		{ numRuns: 80 }
	);
});

test("the unmutated JWE still decrypts (guards against a vacuous mutation test)", async () => {
	const { payload } = await jwtDecrypt(validToken, profile);
	assert.equal(payload.scope, "read");
});
