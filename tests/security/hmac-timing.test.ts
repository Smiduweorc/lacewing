/**
 * @security - HMAC comparison timing smoke test (aspirational
 * and NON-GATING).
 *
 * A forged signature that differs from the real one in its *first* byte should
 * take about as long to reject as one that differs in its *last* byte; a large
 * gap would hint at a non-constant-time comparison (jose/WebCrypto use one, so
 * we expect none). Timing is inherently noisy in CI, so this test only ever
 * asserts that both inputs are rejected and that we could take a measurement -
 * the ratio is logged for a human, never used to fail the build.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, jwtVerify, defineProfile, generateSecret } from "../../index.js";
import { b64u } from "../helpers.js";

const skip = process.env.LACEWING_SKIP_SECURITY === "1";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";
const hmac = generateSecret("HS256");
const profile = defineProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	algorithms: ["HS256"],
	keys: hmac,
	maxTokenAge: "15m",
});

async function timeRejections(token: string, iterations: number): Promise<number> {
	const start = process.hrtime.bigint();
	for (let i = 0; i < iterations; i++) {
		await jwtVerify(token, profile).then(
			() => assert.fail("forged token must not verify"),
			() => undefined
		);
	}
	return Number(process.hrtime.bigint() - start) / 1e6; // ms
}

test("@security HMAC rejection timing is not obviously input-dependent (smoke, non-gating)", { skip }, async () => {
	const valid = await new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m").sign(hmac);
	const [h, p] = valid.split(".") as [string, string, string];
	const realSig = Buffer.from((valid.split(".")[2]) as string, "base64url");

	const flipFirst = Uint8Array.from(realSig);
	flipFirst[0] ^= 0xff;
	const flipLast = Uint8Array.from(realSig);
	flipLast[flipLast.length - 1] ^= 0xff;

	const tokenFirst = `${h}.${p}.${b64u(flipFirst)}`;
	const tokenLast = `${h}.${p}.${b64u(flipLast)}`;

	const iterations = 200;
	const tFirst = await timeRejections(tokenFirst, iterations);
	const tLast = await timeRejections(tokenLast, iterations);

	// Informational only.
	const ratio = tFirst === 0 ? 1 : tLast / tFirst;
	process.stdout.write(
		`  hmac-timing: first-byte ${tFirst.toFixed(2)}ms, last-byte ${tLast.toFixed(2)}ms over ${iterations} iters (ratio ${ratio.toFixed(2)})\n`
	);

	// Gating assertions: both must reject and both measurements must be real.
	assert.ok(Number.isFinite(tFirst) && tFirst >= 0);
	assert.ok(Number.isFinite(tLast) && tLast >= 0);
});
