/**
 * Property: garbage in. Arbitrary strings - including very
 * long ones - fed to `jwtVerify` never crash, never hang, and never return a
 * verified result. They always reject with a typed Lacewing error, and the
 * length cap means a huge input is rejected cheaply rather than parsed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { jwtVerify, defineProfile, generateSecret, JWTError } from "../../index.js";

const profile = defineProfile({
	typ: "at+jwt",
	issuer: "https://auth.example.com",
	audience: "https://api.example.com",
	algorithms: ["HS256"],
	keys: generateSecret("HS256"),
	maxTokenAge: "15m",
});

test("arbitrary strings never verify - they reject with a typed error", async () => {
	await fc.assert(
		fc.asyncProperty(fc.string({ maxLength: 4096 }), async (garbage) => {
			await assert.rejects(jwtVerify(garbage, profile), (error) => {
				assert.ok(error instanceof JWTError, `expected a JWTError, got ${(error as Error)?.constructor?.name}`);
				return true;
			});
		}),
		{ numRuns: 200 }
	);
});

test("dotted three-segment garbage (right shape, wrong content) still rejects typed", async () => {
	const seg = fc.string({ maxLength: 64 });
	await fc.assert(
		fc.asyncProperty(seg, seg, seg, async (a, b, c) => {
			await assert.rejects(jwtVerify(`${a}.${b}.${c}`, profile), (error) => {
				assert.ok(error instanceof JWTError);
				return true;
			});
		}),
		{ numRuns: 200 }
	);
});

test("over-length input is rejected by the length cap, not parsed", async () => {
	const huge = "a".repeat(64 * 1024);
	await assert.rejects(jwtVerify(huge, profile), (error) => {
		assert.ok(error instanceof JWTError);
		assert.match((error as Error).message, /maximum length/);
		return true;
	});
});
