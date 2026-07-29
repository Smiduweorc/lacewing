import { test } from "node:test";
import assert from "node:assert/strict";
import { createRemoteJWKSet } from "../../../src/jwks/remote.js";
import { generateKeyPair } from "../../../src/key/generate.js";
import { exportKeyJWK } from "../../../src/key/export.js";
import { toValidAlg } from "../../../src/lib/algorithms.js";
import { JWKSFetchFailed, JWKSNoMatchingKey } from "../../../src/util/errors.js";
import type { JwtHeader, StaticJWK } from "../../../src/types.js";

const alice = await generateKeyPair("EdDSA", { extractable: true });
const bob = await generateKeyPair("EdDSA", { extractable: true });
const aliceJwk: StaticJWK = { ...(await exportKeyJWK(alice.publicKey)), kid: "alice" };
const bobJwk: StaticJWK = { ...(await exportKeyJWK(bob.publicKey)), kid: "bob" };

const URL_ = "https://auth.example.com/jwks";
const ALLOWED = [toValidAlg("EdDSA")];

function header(kid: string): JwtHeader {
	return { alg: toValidAlg("EdDSA"), typ: "at+jwt", kid };
}

function jwksResponse(keys: StaticJWK[], headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify({ keys }), {
		status: 200,
		headers: { "content-type": "application/jwk-set+json", ...headers },
	});
}

/** fetch stub that serves a scripted sequence of responses/errors. */
function scriptedFetch(script: Array<() => Response>): { fetch: typeof fetch; calls: () => number } {
	let calls = 0;
	const impl = (async () => {
		const step = script[Math.min(calls, script.length - 1)] as () => Response;
		calls += 1;
		return step();
	}) as unknown as typeof fetch;
	return { fetch: impl, calls: () => calls };
}

test("[LW-jwks.1] http URLs are rejected at construction", () => {
	assert.throws(() => createRemoteJWKSet("http://auth.example.com/jwks"), TypeError);
	assert.throws(() => createRemoteJWKSet("not a url"), TypeError);
});

test("fetches once and serves from cache within the TTL", async () => {
	const { fetch, calls } = scriptedFetch([() => jwksResponse([aliceJwk])]);
	const source = createRemoteJWKSet(URL_, { fetch, cacheTtlSeconds: 300 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	await source.getVerificationKey(header("alice"), ALLOWED);
	await source.getVerificationKey(header("alice"), ALLOWED);
	assert.equal(calls(), 1);
});

test("honors Cache-Control max-age over the configured TTL", async () => {
	const { fetch, calls } = scriptedFetch([
		() => jwksResponse([aliceJwk], { "cache-control": "public, max-age=3600" }),
	]);
	const source = createRemoteJWKSet(URL_, { fetch, cacheTtlSeconds: 0, cooldownSeconds: 0 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	await source.getVerificationKey(header("alice"), ALLOWED);
	assert.equal(calls(), 1);
});

test("refetches once on unknown kid (rotation), then fails closed", async () => {
	const { fetch, calls } = scriptedFetch([
		() => jwksResponse([aliceJwk]),
		() => jwksResponse([aliceJwk, bobJwk]),
	]);
	const source = createRemoteJWKSet(URL_, { fetch, cooldownSeconds: 0 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	// "bob" appears after rotation: one refetch finds it.
	await assert.doesNotReject(source.getVerificationKey(header("bob"), ALLOWED));
	assert.equal(calls(), 2);
	// Still-unknown kids fail closed.
	await assert.rejects(source.getVerificationKey(header("carol"), ALLOWED), JWKSNoMatchingKey);
});

test("[LW-jwks.1] cooldown prevents unknown-kid fetch storms", async () => {
	const { fetch, calls } = scriptedFetch([() => jwksResponse([aliceJwk])]);
	const source = createRemoteJWKSet(URL_, { fetch, cooldownSeconds: 60 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	for (let i = 0; i < 25; i++) {
		await assert.rejects(
			source.getVerificationKey(header(`attacker-${i}`), ALLOWED),
			JWKSNoMatchingKey
		);
	}
	assert.equal(calls(), 1, "attacker-driven kids must not trigger refetches during cooldown");
});

test("non-OK responses and invalid bodies are typed fetch failures", async () => {
	const cases: Array<() => Response> = [
		() => new Response("nope", { status: 500 }),
		() => new Response("not json", { status: 200 }),
		() => new Response(JSON.stringify({ nokeys: true }), { status: 200 }),
	];
	for (const respond of cases) {
		const { fetch } = scriptedFetch([respond]);
		const source = createRemoteJWKSet(URL_, { fetch, cooldownSeconds: 0 });
		await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), JWKSFetchFailed);
	}
});

test("network errors surface as JWKSFetchFailed", async () => {
	const failingFetch = (async () => {
		throw new Error("ECONNREFUSED");
	}) as unknown as typeof fetch;
	const source = createRemoteJWKSet(URL_, { fetch: failingFetch, cooldownSeconds: 0 });
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), JWKSFetchFailed);
});

test("stale keys keep serving when the endpoint goes down after a good fetch", async () => {
	let fail = false;
	const impl = (async () => {
		if (fail) throw new Error("endpoint down");
		return jwksResponse([aliceJwk]);
	}) as unknown as typeof fetch;
	// TTL 0: every call is stale and wants a refresh.
	const source = createRemoteJWKSet(URL_, { fetch: impl, cacheTtlSeconds: 0, cooldownSeconds: 0 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	fail = true;
	await assert.doesNotReject(source.getVerificationKey(header("alice"), ALLOWED));
});

test("concurrent verifications share a single fetch", async () => {
	const { fetch, calls } = scriptedFetch([() => jwksResponse([aliceJwk])]);
	const source = createRemoteJWKSet(URL_, { fetch });
	await Promise.all(
		Array.from({ length: 10 }, () => source.getVerificationKey(header("alice"), ALLOWED))
	);
	assert.equal(calls(), 1);
});

// --- bounded stale-serving, byte budget, symmetric keys (issue #14) -------

test("[LW-jwks.2] stale keys stop serving once the stale-while-error window closes", async () => {
	let fail = false;
	const impl = (async () => {
		if (fail) throw new Error("endpoint down");
		return jwksResponse([aliceJwk]);
	}) as unknown as typeof fetch;
	// staleWhileErrorSeconds: 0 - an unreachable endpoint fails closed at once.
	const source = createRemoteJWKSet(URL_, {
		fetch: impl,
		cacheTtlSeconds: 0,
		cooldownSeconds: 0,
		staleWhileErrorSeconds: 0,
	});
	await source.getVerificationKey(header("alice"), ALLOWED);
	fail = true;
	// A key rotated out because it was compromised must not stay trusted for
	// as long as an attacker can keep the endpoint down.
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), JWKSFetchFailed);
});

test("[LW-jwks.2] the stale window is also enforced while cooling down", async () => {
	let fail = false;
	const impl = (async () => {
		if (fail) throw new Error("endpoint down");
		return jwksResponse([aliceJwk]);
	}) as unknown as typeof fetch;
	const source = createRemoteJWKSet(URL_, {
		fetch: impl,
		cacheTtlSeconds: 0,
		cooldownSeconds: 3600, // long cooldown: the stale bound must still apply
		staleWhileErrorSeconds: 0,
	});
	await source.getVerificationKey(header("alice"), ALLOWED);
	fail = true;
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), JWKSFetchFailed);
});

test("staleWhileErrorSeconds is validated", () => {
	assert.throws(() => createRemoteJWKSet(URL_, { staleWhileErrorSeconds: -1 }), TypeError);
	assert.throws(
		() => createRemoteJWKSet(URL_, { staleWhileErrorSeconds: Number.NaN }),
		TypeError
	);
});

test("[LW-jwks.3] an oversized response is refused via Content-Length, before reading", async () => {
	// A ReadableStream pre-fills its queue on its own (highWaterMark 1), so
	// `pull` proves nothing. Watching getReader() is the honest signal.
	let bodyRead = false;
	const impl = (async () => ({
		ok: true,
		status: 200,
		headers: new Headers({ "content-length": String(8 * 1024 * 1024) }),
		get body() {
			return {
				getReader() {
					bodyRead = true;
					throw new Error("the body must never be read");
				},
			};
		},
	})) as unknown as typeof fetch;
	const source = createRemoteJWKSet(URL_, { fetch: impl, cooldownSeconds: 0 });
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), JWKSFetchFailed);
	assert.equal(bodyRead, false, "the body must not be pulled once the declared size is oversized");
});

test("[LW-jwks.3] an oversized chunked response is abandoned mid-stream", async () => {
	// No Content-Length: the cap has to be enforced against bytes as they land,
	// not against a fully buffered string afterwards.
	let bytesProduced = 0;
	const chunk = new TextEncoder().encode("x".repeat(64 * 1024));
	const impl = (async () =>
		new Response(
			new ReadableStream({
				pull(controller) {
					bytesProduced += chunk.byteLength;
					if (bytesProduced > 16 * 1024 * 1024) {
						controller.close();
						return;
					}
					controller.enqueue(chunk.slice());
				},
			}),
			{ status: 200 }
		)) as unknown as typeof fetch;
	const source = createRemoteJWKSet(URL_, { fetch: impl, cooldownSeconds: 0 });
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), JWKSFetchFailed);
	assert.ok(
		bytesProduced <= 2 * 1024 * 1024,
		`stream should be abandoned near the 1MB cap, produced ${bytesProduced} bytes`
	);
});

test("[LW-jwks.4] symmetric keys are refused from a remote JWKS", async () => {
	// A JWKS endpoint is public: a secret served there is one anyone can mint
	// with, not merely verify with.
	const octJwk = { kty: "oct", alg: "HS256", kid: "shared", k: "a".repeat(43) } as StaticJWK;
	const { fetch } = scriptedFetch([() => jwksResponse([octJwk])]);
	const source = createRemoteJWKSet(URL_, { fetch, cooldownSeconds: 0 });
	const hs: JwtHeader = { alg: toValidAlg("HS256"), typ: "at+jwt", kid: "shared" };
	await assert.rejects(source.getVerificationKey(hs, [toValidAlg("HS256")]), JWKSNoMatchingKey);
});
