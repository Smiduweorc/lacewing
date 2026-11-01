import { test } from "node:test";
import assert from "node:assert/strict";
import { refusal } from "../../helpers.js";
import { createRemoteJWKSet } from "../../../src/jwks/remote.js";
import { generateKeyPair } from "../../../src/key/generate.js";
import { exportKeyJWK } from "../../../src/key/export.js";
import { resolveAlgorithm } from "../../../src/lib/algorithms.js";
import { SetAlg, type JwtHeader, type StaticJWK } from "../../../src/types.js";

const alice = await generateKeyPair("EdDSA", { extractable: true });
const bob = await generateKeyPair("EdDSA", { extractable: true });
const aliceJwk: StaticJWK = { ...(await exportKeyJWK(alice.publicKey)), kid: "alice" };
const bobJwk: StaticJWK = { ...(await exportKeyJWK(bob.publicKey)), kid: "bob" };

/** The options every remote JWKS must name; tests override what they exercise. */
const REQUIRED = { cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 5000 };
const URL_ = "https://auth.example.com/jwks";
/** A fixed instant for tests that drive the clock: 2026-01-01T00:00:00Z. */
const T0 = 1_767_225_600_000;
const ALLOWED = [resolveAlgorithm("EdDSA")];

function header(kid: string): JwtHeader {
	return { alg: SetAlg("EdDSA"), typ: "at+jwt", kid };
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
	assert.throws(() => createRemoteJWKSet("http://auth.example.com/jwks", REQUIRED), TypeError);
	assert.throws(() => createRemoteJWKSet("not a url", REQUIRED), TypeError);
});

test("fetches once and serves from cache within the TTL", async () => {
	const { fetch, calls } = scriptedFetch([() => jwksResponse([aliceJwk])]);
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cacheTtlSeconds: 300 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	await source.getVerificationKey(header("alice"), ALLOWED);
	await source.getVerificationKey(header("alice"), ALLOWED);
	assert.equal(calls(), 1);
});

test("honors Cache-Control max-age over the configured TTL", async () => {
	const { fetch, calls } = scriptedFetch([
		() => jwksResponse([aliceJwk], { "cache-control": "public, max-age=3600" }),
	]);
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cacheTtlSeconds: 0, cooldownSeconds: 1 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	await source.getVerificationKey(header("alice"), ALLOWED);
	assert.equal(calls(), 1);
});

test("refetches once on unknown kid (rotation), then fails closed", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: T0 });
	const { fetch, calls } = scriptedFetch([
		() => jwksResponse([aliceJwk]),
		() => jwksResponse([aliceJwk, bobJwk]),
	]);
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cooldownSeconds: 1 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	t.mock.timers.tick(1000);
	// "bob" appears after rotation: one refetch finds it.
	await assert.doesNotReject(source.getVerificationKey(header("bob"), ALLOWED));
	assert.equal(calls(), 2);
	// Still-unknown kids fail closed.
	await assert.rejects(source.getVerificationKey(header("carol"), ALLOWED), refusal("JWKS_NO_MATCHING_KEY"));
});

test("[LW-jwks.1] cooldown prevents unknown-kid fetch storms", async () => {
	const { fetch, calls } = scriptedFetch([() => jwksResponse([aliceJwk])]);
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cooldownSeconds: 60 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	for (let i = 0; i < 25; i++) {
		await assert.rejects(
			source.getVerificationKey(header(`attacker-${i}`), ALLOWED),
			refusal("JWKS_NO_MATCHING_KEY")
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
		const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cooldownSeconds: 1 });
		await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), refusal("JWKS_FETCH_FAILED"));
	}
});

test("an error from a caller-supplied fetch comes back as itself, not wrapped", async () => {
	const refused = new Error("ECONNREFUSED");
	const failingFetch = (async () => {
		throw refused;
	}) as unknown as typeof fetch;
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch: failingFetch, cooldownSeconds: 1 });
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), (error) => error === refused);
});

test("a failure of the global fetch is refused as JWKS_FETCH_FAILED, keeping the cause", async () => {
	const refused = new TypeError("fetch failed");
	const original = globalThis.fetch;
	globalThis.fetch = (async () => {
		throw refused;
	}) as unknown as typeof fetch;
	try {
		const source = createRemoteJWKSet(URL_, { ...REQUIRED, cooldownSeconds: 1 });
		await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), (error) => {
			refusal("JWKS_FETCH_FAILED")(error);
			assert.equal((error as Error).cause, refused);
			return true;
		});
	} finally {
		globalThis.fetch = original;
	}
});

test("stale keys keep serving when the endpoint goes down after a good fetch", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: T0 });
	const { fetch, calls } = scriptedFetch([
		() => jwksResponse([aliceJwk]),
		() => new Response("down", { status: 503 }),
	]);
	// TTL 0: every call past the cooldown is stale and wants a refresh.
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cacheTtlSeconds: 0, cooldownSeconds: 1 });
	await source.getVerificationKey(header("alice"), ALLOWED);
	t.mock.timers.tick(1000);
	await assert.doesNotReject(source.getVerificationKey(header("alice"), ALLOWED));
	assert.equal(calls(), 2, "the refresh was attempted and failed");
});

test("concurrent verifications share a single fetch", async () => {
	const { fetch, calls } = scriptedFetch([() => jwksResponse([aliceJwk])]);
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch });
	await Promise.all(
		Array.from({ length: 10 }, () => source.getVerificationKey(header("alice"), ALLOWED))
	);
	assert.equal(calls(), 1);
});

// --- bounded stale-serving, byte budget, symmetric keys (issue #14) -------

test("[LW-jwks.2] stale keys stop serving once the stale-while-error window closes", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: T0 });
	let fail = false;
	const down = new Error("endpoint down");
	const impl = (async () => {
		if (fail) throw down;
		return jwksResponse([aliceJwk]);
	}) as unknown as typeof fetch;
	// staleWhileErrorSeconds: 0 - an unreachable endpoint fails closed at once.
	const source = createRemoteJWKSet(URL_, {
		...REQUIRED,
		fetch: impl,
		cacheTtlSeconds: 0,
		cooldownSeconds: 1,
		staleWhileErrorSeconds: 0,
	});
	await source.getVerificationKey(header("alice"), ALLOWED);
	fail = true;
	t.mock.timers.tick(1000);
	// A key rotated out because it was compromised must not stay trusted for
	// as long as an attacker can keep the endpoint down. The fetch is the
	// caller's, so its own error is what surfaces.
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), (error) => error === down);
});

test("[LW-jwks.2] the stale window is also enforced while cooling down", async () => {
	let fail = false;
	const impl = (async () => {
		if (fail) throw new Error("endpoint down");
		return jwksResponse([aliceJwk]);
	}) as unknown as typeof fetch;
	const source = createRemoteJWKSet(URL_, {
		...REQUIRED,
		fetch: impl,
		cacheTtlSeconds: 0,
		cooldownSeconds: 3600, // long cooldown: the stale bound must still apply
		staleWhileErrorSeconds: 0,
	});
	await source.getVerificationKey(header("alice"), ALLOWED);
	fail = true;
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), refusal("JWKS_FETCH_FAILED"));
});

/** A source whose endpoint answers once with `cacheControl`, then is down for good. */
function oneGoodFetch(cacheControl: string | undefined, staleWhileErrorSeconds?: number): {
	source: ReturnType<typeof createRemoteJWKSet>;
	calls: () => number;
} {
	const headers: Record<string, string> = cacheControl === undefined ? {} : { "cache-control": cacheControl };
	const { fetch, calls } = scriptedFetch([
		() => jwksResponse([aliceJwk], headers),
		() => new Response("down", { status: 503 }),
	]);
	const options = { ...REQUIRED, fetch, staleWhileErrorSeconds };
	return { source: createRemoteJWKSet(URL_, options), calls };
}

// Found by the v2.0.1 adversarial review: the window was measured from the
// last good fetch, so a max-age as long as the window left no stale time.
test("[LW-jwks.2] the stale window opens when the cache lifetime ends, whatever max-age said", async (t) => {
	for (const maxAge of [60, 3600, 7200, 86400]) {
		t.mock.timers.enable({ apis: ["Date"], now: T0 });
		const { source, calls } = oneGoodFetch(`max-age=${maxAge}`);
		await source.getVerificationKey(header("alice"), ALLOWED);
		t.mock.timers.tick(maxAge * 1000 + 1000);
		await assert.doesNotReject(
			source.getVerificationKey(header("alice"), ALLOWED),
			`max-age=${maxAge} must still coast after the endpoint fails`
		);
		assert.equal(calls(), 2);
		t.mock.timers.reset();
	}
});

test("[LW-jwks.2] the stale window edges: open one ms before it closes, shut at the instant it closes", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: T0 });
	const { source } = oneGoodFetch(undefined, 600); // no Cache-Control: cacheTtlSeconds (300) applies
	await source.getVerificationKey(header("alice"), ALLOWED);
	t.mock.timers.tick((300 + 600) * 1000 - 1);
	await assert.doesNotReject(source.getVerificationKey(header("alice"), ALLOWED));
	t.mock.timers.tick(1);
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), refusal("JWKS_FETCH_FAILED"));
});

test("staleWhileErrorSeconds defaults to 3600 after the cache lifetime", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: T0 });
	const { source } = oneGoodFetch("max-age=60");
	await source.getVerificationKey(header("alice"), ALLOWED);
	t.mock.timers.tick((60 + 3600) * 1000 - 1);
	await assert.doesNotReject(source.getVerificationKey(header("alice"), ALLOWED));
	t.mock.timers.tick(1);
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), refusal("JWKS_FETCH_FAILED"));
});

test("staleWhileErrorSeconds is validated and capped at 86400", () => {
	for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY, 86401, "60"]) {
		assert.throws(
			() => createRemoteJWKSet(URL_, { ...REQUIRED, staleWhileErrorSeconds: bad as number }),
			TypeError,
			`accepted ${String(bad)}`
		);
	}
	assert.doesNotThrow(() => createRemoteJWKSet(URL_, { ...REQUIRED, staleWhileErrorSeconds: 0 }));
	assert.doesNotThrow(() => createRemoteJWKSet(URL_, { ...REQUIRED, staleWhileErrorSeconds: 86400 }));
});

test("cacheTtlSeconds, cooldownSeconds and timeoutMs are required and range-checked", () => {
	const cases: Array<[keyof typeof REQUIRED, unknown[], number[]]> = [
		["cacheTtlSeconds", [undefined, -1, Number.NaN, Number.POSITIVE_INFINITY, 86401, "300"], [0, 86400]],
		["cooldownSeconds", [undefined, 0, 0.5, -1, Number.NaN, 86401, "30"], [1, 86400]],
		["timeoutMs", [undefined, 0, -1, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 31, "5000"], [1, 2 ** 31 - 1]],
	];
	for (const [field, bad, good] of cases) {
		for (const value of bad) {
			assert.throws(
				() => createRemoteJWKSet(URL_, { ...REQUIRED, [field]: value } as never),
				(error: unknown) => error instanceof TypeError && error.message.includes(field),
				`${field} accepted ${String(value)}`
			);
		}
		for (const value of good) {
			assert.doesNotThrow(() => createRemoteJWKSet(URL_, { ...REQUIRED, [field]: value }), `${field} refused ${value}`);
		}
	}
	assert.throws(() => createRemoteJWKSet(URL_, undefined as never), TypeError);
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
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch: impl, cooldownSeconds: 1 });
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), refusal("JWKS_FETCH_FAILED"));
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
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch: impl, cooldownSeconds: 1 });
	await assert.rejects(source.getVerificationKey(header("alice"), ALLOWED), refusal("JWKS_FETCH_FAILED"));
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
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cooldownSeconds: 1 });
	const hs: JwtHeader = { alg: SetAlg("HS256"), typ: "at+jwt", kid: "shared" };
	await assert.rejects(source.getVerificationKey(hs, [resolveAlgorithm("HS256")]), refusal("JWKS_NO_MATCHING_KEY"));
});

test("[8725-3.1.2] a remote RSA key without alg is refused when the profile allows several RSA algorithms", async () => {
	const rsa = await generateKeyPair("PS256", { extractable: true });
	const { alg: _alg, ...unbound } = { ...(await exportKeyJWK(rsa.publicKey)), kid: "rsa" } as StaticJWK;
	const { fetch } = scriptedFetch([() => jwksResponse([unbound])]);
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, cooldownSeconds: 300 });
	const rsaHeader: JwtHeader = { alg: SetAlg("PS512"), typ: "at+jwt", kid: "rsa" };
	await assert.rejects(
		source.getVerificationKey(rsaHeader, [resolveAlgorithm("PS256"), resolveAlgorithm("PS512")]),
		refusal("JWKS_NO_MATCHING_KEY")
	);
	const resolved = await source.getVerificationKey(rsaHeader, [resolveAlgorithm("PS512")]);
	assert.equal(resolved.alg, "PS512");
});
