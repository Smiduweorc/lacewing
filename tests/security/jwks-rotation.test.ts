/**
 * @security - JWKS client behavior under rotation and hostile load
 *. Uses the client's injectable `fetch` (no network), so the
 * assertions are deterministic.
 *
 * Skippable locally with LACEWING_SKIP_SECURITY=1; always on in CI.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createRemoteJWKSet } from "../../index.js";
import { generateKeyPair, exportKeyJWK } from "../../index.js";
import { toValidAlg } from "../../src/lib/algorithms.js";
import { JWKSNoMatchingKey } from "../../index.js";
import type { JwtHeader, StaticJWK } from "../../src/types.js";

const skip = process.env.LACEWING_SKIP_SECURITY === "1";

const alice = await generateKeyPair("EdDSA", { extractable: true });
const bob = await generateKeyPair("EdDSA", { extractable: true });
const aliceJwk: StaticJWK = { ...(await exportKeyJWK(alice.publicKey)), kid: "alice" };
const bobJwk: StaticJWK = { ...(await exportKeyJWK(bob.publicKey)), kid: "bob" };

const URL_ = "https://auth.example.com/jwks";
const ALLOWED = [toValidAlg("EdDSA")];
const header = (kid: string): JwtHeader => ({ alg: toValidAlg("EdDSA"), typ: "at+jwt", kid });

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

test("@security [8725-3.10.2] key rotation: an unknown kid triggers exactly one refetch, then resolves", { skip }, async () => {
	const { fetch, calls } = countingFetch([() => jwks([aliceJwk]), () => jwks([aliceJwk, bobJwk])]);
	// cooldown 0 so the rotation refetch is allowed immediately.
	const source = createRemoteJWKSet(URL_, { fetch, cooldownSeconds: 0, cacheTtlSeconds: 300 });

	await source.getVerificationKey(header("alice"), ALLOWED); // fetch #1
	const resolved = await source.getVerificationKey(header("bob"), ALLOWED); // unknown -> fetch #2
	assert.equal(resolved.alg, "EdDSA");
	assert.equal(calls(), 2, "one initial fetch + one rotation refetch");
});

test("@security unknown-kid flooding cannot drive a fetch storm (cooldown holds)", { skip }, async () => {
	const { fetch, calls } = countingFetch([() => jwks([aliceJwk])]);
	// Long cooldown: after the first fetch, no unknown kid may trigger another.
	const source = createRemoteJWKSet(URL_, { fetch, cooldownSeconds: 300, cacheTtlSeconds: 300 });

	await source.getVerificationKey(header("alice"), ALLOWED); // fetch #1 (populates cache)
	for (let i = 0; i < 100; i++) {
		await assert.rejects(source.getVerificationKey(header(`attacker-${i}`), ALLOWED), JWKSNoMatchingKey);
	}
	assert.equal(calls(), 1, "100 unknown-kid requests must not cause a second fetch");
});

test("@security a JWKS endpoint that goes down does not evict still-valid cached keys", { skip }, async () => {
	const { fetch } = countingFetch([
		() => jwks([aliceJwk]),
		() => {
			throw new Error("endpoint down");
		},
	]);
	// TTL 0 + cooldown 0 means every call re-attempts a fetch; the second fails,
	// but the previously-good key must still resolve (stale-while-error).
	const source = createRemoteJWKSet(URL_, { fetch, cacheTtlSeconds: 0, cooldownSeconds: 0 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	const resolved = await source.getVerificationKey(header("alice"), ALLOWED);
	assert.equal(resolved.alg, "EdDSA");
});

test("@security JWKS URLs must be https at construction", { skip }, () => {
	assert.throws(() => createRemoteJWKSet("http://auth.example.com/jwks"), TypeError);
});
