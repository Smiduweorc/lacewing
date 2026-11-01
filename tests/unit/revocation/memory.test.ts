import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryRevocationStore } from "../../../src/revocation/memory.js";
import { buildRevocationContext } from "../../../src/revocation/store.js";
import { nowSeconds } from "../../helpers.js";

function context(jti: string): { jti: string; exp: number; iat: number } {
	return { jti, exp: nowSeconds() + 300, iat: nowSeconds() };
}

test("revoked jtis are reported revoked; others are not", async () => {
	const store = new MemoryRevocationStore();
	store.revoke("token-1", nowSeconds() + 300);
	assert.equal(await store.isRevoked(context("token-1")), true);
	assert.equal(await store.isRevoked(context("token-2")), false);
});

test("a token without a jti can never be revoked here", async () => {
	const store = new MemoryRevocationStore();
	assert.equal(await store.isRevoked({ exp: nowSeconds() + 60, iat: nowSeconds() }), false);
});

test("revocations expire with their token - no unbounded growth", async () => {
	const store = new MemoryRevocationStore();
	store.revoke("dead-token", nowSeconds() - 10);
	assert.equal(await store.isRevoked(context("dead-token")), false);
	assert.equal(store.size, 0);
});

test("expired entries are swept in bulk", async () => {
	const store = new MemoryRevocationStore();
	const past = nowSeconds() - 10;
	for (let i = 0; i < 300; i++) {
		store.revoke(`expired-${i}`, past);
	}
	// The periodic sweep fires within the op interval.
	assert.ok(store.size < 300);
});

test("revoke validates its inputs", () => {
	const store = new MemoryRevocationStore();
	assert.throws(() => store.revoke("", nowSeconds()), TypeError);
	assert.throws(() => store.revoke("x", Number.NaN), TypeError);
	store.revoke("y", new Date(Date.now() + 60_000));
});

test("isAnyRevoked maps over contexts", async () => {
	const store = new MemoryRevocationStore();
	store.revoke("a", nowSeconds() + 300);
	assert.deepEqual(await store.isAnyRevoked([context("a"), context("b")]), [true, false]);
});

test("buildRevocationContext extracts only the revocation-relevant slice", () => {
	const context_ = buildRevocationContext({
		jti: "j",
		sub: "s",
		sid: "session-1",
		exp: 100,
		iat: 50,
		email: "leak@example.com",
	});
	assert.deepEqual(context_, { jti: "j", sub: "s", sid: "session-1", exp: 100, iat: 50 });
});

// Found by the v2.0.1 adversarial review: the context carried sub and sid,
// and the reference store ignored both.
test("revokeSubject revokes every token the subject held, and none issued after", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: 1_767_225_600_000 });
	const store = new MemoryRevocationStore();
	const issuedBefore = { jti: "a", sub: "user-42", exp: nowSeconds() + 600, iat: nowSeconds() - 60 };
	const sameSecond = { jti: "b", sub: "user-42", exp: nowSeconds() + 600, iat: nowSeconds() };
	const otherUser = { jti: "c", sub: "user-7", exp: nowSeconds() + 600, iat: nowSeconds() - 60 };
	store.revokeSubject("user-42", nowSeconds() + 600);
	assert.equal(await store.isRevoked(issuedBefore), true);
	assert.equal(await store.isRevoked(sameSecond), true, "the revocation second fails closed");
	assert.equal(await store.isRevoked(otherUser), false);
	t.mock.timers.tick(1000);
	const issuedAfter = { jti: "d", sub: "user-42", exp: nowSeconds() + 600, iat: nowSeconds() };
	assert.equal(await store.isRevoked(issuedAfter), false, "a fresh login is not revoked");
});

test("revokeSession revokes by sid and leaves the subject's other sessions alone", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: 1_767_225_600_000 });
	const store = new MemoryRevocationStore();
	const iat = nowSeconds() - 60;
	store.revokeSession("session-1", nowSeconds() + 600);
	assert.equal(await store.isRevoked({ sub: "u", sid: "session-1", exp: iat + 600, iat }), true);
	assert.equal(await store.isRevoked({ sub: "u", sid: "session-2", exp: iat + 600, iat }), false);
	assert.equal(await store.isRevoked({ sub: "u", exp: iat + 600, iat }), false, "no sid, no session match");
});

test("a subject cut-off lives until its until, then evicts", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: 1_767_225_600_000 });
	const store = new MemoryRevocationStore();
	const iat = nowSeconds() - 60;
	store.revokeSubject("user-42", nowSeconds() + 600);
	t.mock.timers.tick(599_000);
	assert.equal(await store.isRevoked({ sub: "user-42", exp: iat + 7200, iat }), true, "one second before until");
	t.mock.timers.tick(1000);
	assert.equal(await store.isRevoked({ sub: "user-42", exp: iat + 7200, iat }), false, "at until it is gone");
	assert.equal(store.size, 0);
});

test("revoking a subject twice keeps the later cut-off and the longer until", async (t) => {
	t.mock.timers.enable({ apis: ["Date"], now: 1_767_225_600_000 });
	const store = new MemoryRevocationStore();
	store.revokeSubject("user-42", nowSeconds() + 3600);
	t.mock.timers.tick(10_000);
	const between = nowSeconds() - 5;
	store.revokeSubject("user-42", nowSeconds() + 60);
	assert.equal(await store.isRevoked({ sub: "user-42", exp: between + 600, iat: between }), true);
	t.mock.timers.tick(120_000);
	assert.equal(await store.isRevoked({ sub: "user-42", exp: between + 600, iat: between }), true, "the first until still holds");
});

test("revokeSubject and revokeSession validate their inputs", () => {
	const store = new MemoryRevocationStore();
	for (const method of ["revokeSubject", "revokeSession"] as const) {
		assert.throws(() => store[method]("", nowSeconds() + 60), TypeError);
		assert.throws(() => store[method](undefined as never, nowSeconds() + 60), TypeError);
		assert.throws(() => store[method]("x", Number.NaN), TypeError);
		assert.throws(() => store[method]("x", Number.POSITIVE_INFINITY), TypeError);
		assert.throws(() => store[method]("x", "soon" as never), TypeError);
		store[method]("x", new Date(Date.now() + 60_000));
	}
});

test("revoking a jti twice keeps the later expiry", async () => {
	const store = new MemoryRevocationStore();
	store.revoke("t", nowSeconds() + 600);
	store.revoke("t", nowSeconds() - 10);
	assert.equal(await store.isRevoked(context("t")), true);
});
