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
