import { test } from "node:test";
import assert from "node:assert/strict";
import {
	SignJWT,
	jwtVerify,
	defineProfile,
	createRemoteJWKSet,
	generateKeyPair,
	generateSecret,
	exportKeyJWK,
	type LacewingEvent,
	type RevocationStore,
	type StaticJWK,
} from "../../../index.js";
import { resolveAlgorithm } from "../../../src/lib/algorithms.js";
import { SetAlg } from "../../../src/types.js";

const ISS = "https://auth.example.com";
const AUD = "https://api.example.com";
const URL_ = "https://auth.example.com/jwks";
const T0 = 1_767_225_600_000;
const REQUIRED = { cacheTtlSeconds: 300, cooldownSeconds: 30, timeoutMs: 5000 };

const brokenStore: RevocationStore = {
	isRevoked: async () => {
		throw new Error("redis down");
	},
};

function recorder(): { events: LacewingEvent[]; onEvent: (event: LacewingEvent) => void } {
	const events: LacewingEvent[] = [];
	return { events, onEvent: (event) => events.push(event) };
}

async function hmacSetup(
	extra: Record<string, unknown>
): Promise<{ token: string; profile: ReturnType<typeof defineProfile> }> {
	const secret = generateSecret("HS256");
	const token = await new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign(secret);
	const profile = defineProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: secret, maxTokenAge: "5m",
		...extra,
	});
	return { token, profile };
}

test("[LW-rev.4] a fail-open profile reports the store error it let through, with its cause", async () => {
	const { events, onEvent } = recorder();
	const { token, profile } = await hmacSetup({ revocation: brokenStore, unsafeFailOpenOnRevocationError: true, onEvent });
	await assert.doesNotReject(jwtVerify(token, profile));
	assert.equal(events.length, 1);
	const [event] = events;
	assert.equal(event?.type, "revocation-fail-open");
	assert.equal((event as { cause: Error }).cause.message, "redis down");
});

test("[LW-rev.4] a fail-closed profile throws and reports nothing", async () => {
	const { events, onEvent } = recorder();
	const { token, profile } = await hmacSetup({ revocation: brokenStore, onEvent });
	await assert.rejects(jwtVerify(token, profile), { name: "JWTError", code: "REVOCATION_CHECK_FAILED" });
	assert.equal(events.length, 0);
});

test("a listener that throws does not change the verification outcome", async () => {
	const { token, profile } = await hmacSetup({
		revocation: brokenStore,
		unsafeFailOpenOnRevocationError: true,
		onEvent: () => {
			throw new Error("logger broke");
		},
	});
	await assert.doesNotReject(jwtVerify(token, profile));
});

test("onEvent must be a function", () => {
	assert.throws(() => defineProfile({
		typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: generateSecret("HS256"), maxTokenAge: "5m",
		onEvent: "log" as never,
	}), TypeError);
	assert.throws(() => createRemoteJWKSet(URL_, { ...REQUIRED, onEvent: 1 as never }), TypeError);
});

const alice = await generateKeyPair("EdDSA", { extractable: true });
const aliceJwk: StaticJWK = { ...(await exportKeyJWK(alice.publicKey)), kid: "alice" };
const header = { alg: SetAlg("EdDSA"), typ: "at+jwt", kid: "alice" };
const ALLOWED = [resolveAlgorithm("EdDSA")];

function upThenDown(): { fetch: typeof fetch; calls: () => number } {
	let calls = 0;
	const impl = (async () => {
		calls += 1;
		if (calls === 1) {
			return new Response(JSON.stringify({ keys: [aliceJwk] }), { status: 200 });
		}
		return new Response("down", { status: 503 });
	}) as unknown as typeof fetch;
	return { fetch: impl, calls: () => calls };
}

test("[LW-jwks.2] stale serving is reported per verification, with how stale, and the failed fetch once", async () => {
	let clockMs = T0;
	const { events, onEvent } = recorder();
	const { fetch } = upThenDown();
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, onEvent, now: () => clockMs });
	await source.getVerificationKey(header, ALLOWED);
	assert.equal(events.length, 0, "a good fetch reports nothing");

	clockMs = T0 + (300 + 45) * 1000; // 45s past the cache lifetime, past the cooldown
	await source.getVerificationKey(header, ALLOWED);
	assert.deepEqual(events.map((e) => e.type), ["jwks-refresh-failed", "jwks-stale-serving"]);
	assert.equal((events[0] as { url: string }).url, URL_);
	assert.equal((events[1] as { staleForSeconds: number }).staleForSeconds, 45);

	clockMs += 1000; // inside the cooldown: no fetch, still stale
	await source.getVerificationKey(header, ALLOWED);
	assert.deepEqual(events.map((e) => e.type), ["jwks-refresh-failed", "jwks-stale-serving", "jwks-stale-serving"]);
});

test("concurrent verifications sharing one failed fetch report it once", async () => {
	let clockMs = T0;
	const { events, onEvent } = recorder();
	const { fetch, calls } = upThenDown();
	const source = createRemoteJWKSet(URL_, { ...REQUIRED, fetch, onEvent, now: () => clockMs });
	await source.getVerificationKey(header, ALLOWED);
	clockMs = T0 + 400 * 1000;
	await Promise.all(Array.from({ length: 5 }, () => source.getVerificationKey(header, ALLOWED)));
	assert.equal(calls(), 2);
	assert.equal(events.filter((e) => e.type === "jwks-refresh-failed").length, 1);
});

test("an inline { jwksUri } config reports through the profile's onEvent", async () => {
	const { events, onEvent } = recorder();
	const original = globalThis.fetch;
	globalThis.fetch = (async () => new Response("down", { status: 503 })) as unknown as typeof fetch;
	try {
		const profile = defineProfile({
			typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["EdDSA"], maxTokenAge: "5m", onEvent,
			keys: { jwksUri: URL_, ...REQUIRED },
		});
		const token = await new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m").sign(alice.privateKey);
		await assert.rejects(jwtVerify(token, profile), { name: "JWTError", code: "JWKS_FETCH_FAILED" });
		assert.deepEqual(events.map((e) => e.type), ["jwks-refresh-failed"]);
	} finally {
		globalThis.fetch = original;
	}
});
