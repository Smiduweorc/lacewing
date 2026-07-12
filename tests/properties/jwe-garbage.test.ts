/**
 * Property: JWE garbage in - the encrypted-token counterpart
 * of `garbage.test.ts`. Arbitrary strings fed to `jwtDecrypt` never crash,
 * never hang, and never return a decrypted result. They always reject with a
 * typed Lacewing error, and the length cap means a huge input is rejected
 * cheaply rather than parsed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { jwtDecrypt, defineDecryptionProfile, generateDirectKey, JWTError } from "../../index.js";

const profile = defineDecryptionProfile({
	typ: "at+jwt",
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	keyManagementAlgorithms: ["dir"],
	contentEncryptionAlgorithms: ["A256GCM"],
	key: generateDirectKey("A256GCM"),
	maxTokenAge: "15m",
});

test("arbitrary strings never decrypt - they reject with a typed error", async () => {
	await fc.assert(
		fc.asyncProperty(fc.string({ maxLength: 4096 }), async (garbage) => {
			await assert.rejects(jwtDecrypt(garbage, profile), (error) => {
				assert.ok(error instanceof JWTError, `expected a JWTError, got ${(error as Error)?.constructor?.name}`);
				return true;
			});
		}),
		{ numRuns: 200 }
	);
});

test("dotted five-segment garbage (right shape, wrong content) still rejects typed", async () => {
	const seg = fc.string({ maxLength: 64 });
	await fc.assert(
		fc.asyncProperty(seg, seg, seg, seg, seg, async (a, b, c, d, e) => {
			await assert.rejects(jwtDecrypt(`${a}.${b}.${c}.${d}.${e}`, profile), (error) => {
				assert.ok(error instanceof JWTError);
				return true;
			});
		}),
		{ numRuns: 200 }
	);
});

test("three-segment input (a JWS shape) rejects typed - formats never cross over", async () => {
	const seg = fc.string({ maxLength: 64 });
	await fc.assert(
		fc.asyncProperty(seg, seg, seg, async (a, b, c) => {
			await assert.rejects(jwtDecrypt(`${a}.${b}.${c}`, profile), (error) => {
				assert.ok(error instanceof JWTError);
				return true;
			});
		}),
		{ numRuns: 100 }
	);
});

test("over-length input is rejected by the length cap, not parsed", async () => {
	const huge = "a".repeat(64 * 1024);
	await assert.rejects(jwtDecrypt(huge, profile), (error) => {
		assert.ok(error instanceof JWTError);
		assert.match((error as Error).message, /maximum length/);
		return true;
	});
});
