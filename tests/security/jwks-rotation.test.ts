/**
 * @security - JWKS client behavior under rotation and hostile load
 *. Uses the client's injectable `fetch` (no network), so the
 * assertions are deterministic.
 *
 * Skippable locally with LACEWING_SKIP_SECURITY=1; always on in CI.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { refusal } from "../helpers.js";
import { createRemoteJWKSet } from "../../index.js";
import { generateKeyPair, exportKeyJWK } from "../../index.js";
import { resolveAlgorithm } from "../../src/lib/algorithms.js";
import { SetAlg, type JwtHeader, type StaticJWK } from "../../src/types.js";

const skip = process.env.LACEWING_SKIP_SECURITY === "1";

const alice = await generateKeyPair("EdDSA", { extractable: true });
const bob = await generateKeyPair("EdDSA", { extractable: true });
const aliceJwk: StaticJWK = { ...(await exportKeyJWK(alice.publicKey)), kid: "alice" };
const bobJwk: StaticJWK = { ...(await exportKeyJWK(bob.publicKey)), kid: "bob" };

/** The options every remote JWKS must name; tests override what they exercise. */
const REQUIRED = { cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 5000 };
const URL_ = "https://auth.example.com/jwks";
const ALLOWED = [resolveAlgorithm("EdDSA")];
const header = (kid: string): JwtHeader => ({ alg: SetAlg("EdDSA"), typ: "at+jwt", kid });

function jwks(keys: StaticJWK[]): Response {
	return new Response(JSON.stringify({ keys }), {
		status: 200,
		headers: { "content-type": "application/jwk-set+json" },
	});
}

function countingFetch(script: Array<() => Response>): { fetch: typeof fetch; calls: () => number } {
	let calls = 0;
	const impl = (async () => {
		const step = script[Math.min(calls, script.length - 1)] as () => Response;
		calls += 1;
		return step();
	}) as unknown as typeof fetch;
	return { fetch: impl, calls: () => calls };
}

test("@security [8725-3.10.2] key rotation: an unknown kid triggers exactly one refetch, then resolves", { skip }, async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: 1_767_225_600_000 });
	const { fetch, calls } = countingFetch([() => jwks([aliceJwk]), () => jwks([aliceJwk, bobJwk])]);
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cooldownSeconds: 1, cacheTtlSeconds: 300 });

	await source.getVerificationKey(header("alice"), ALLOWED); // fetch #1
	t.mock.timers.tick(1000); // past the cooldown, so the rotation refetch is allowed
	const resolved = await source.getVerificationKey(header("bob"), ALLOWED); // unknown -> fetch #2
	assert.equal(resolved.alg, "EdDSA");
	assert.equal(calls(), 2, "one initial fetch + one rotation refetch");
});

test("@security unknown-kid flooding cannot drive a fetch storm (cooldown holds)", { skip }, async () => {
	const { fetch, calls } = countingFetch([() => jwks([aliceJwk])]);
	// Long cooldown: after the first fetch, no unknown kid may trigger another.
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cooldownSeconds: 300, cacheTtlSeconds: 300 });

	await source.getVerificationKey(header("alice"), ALLOWED); // fetch #1 (populates cache)
	for (let i = 0; i < 100; i++) {
		await assert.rejects(source.getVerificationKey(header(`attacker-${i}`), ALLOWED), refusal("JWKS_NO_MATCHING_KEY"));
	}
	assert.equal(calls(), 1, "100 unknown-kid requests must not cause a second fetch");
});

test("@security a JWKS endpoint that goes down does not evict still-valid cached keys", { skip }, async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: 1_767_225_600_000 });
	const counted = countingFetch([
		() => jwks([aliceJwk]),
		() => {
			throw new Error("endpoint down");
		},
	]);
	const { fetch } = counted;
	// TTL 0: once the cooldown passes, every call re-attempts a fetch; the
	// second fails, but the previously-good key must still resolve.
	const { calls } = counted;
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cacheTtlSeconds: 0, cooldownSeconds: 1 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	t.mock.timers.tick(1000);
	const resolved = await source.getVerificationKey(header("alice"), ALLOWED);
	assert.equal(resolved.alg, "EdDSA");
	assert.equal(calls(), 2, "the failing refresh was attempted");
});

test("@security JWKS URLs must be https at construction", { skip }, () => {
	assert.throws(() => createRemoteJWKSet("http://auth.example.com/jwks", REQUIRED), TypeError);
});
