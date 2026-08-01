import { test } from "node:test";
import assert from "node:assert/strict";
import {
	buildTokenCookie,
	clearTokenCookie,
	readTokenCookie,
	setTokenCookie,
} from "../../../src/http/cookies.js";

const TOKEN = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln";

test("[LW-http.1] every cookie carries HttpOnly, Secure and SameSite - always", () => {
	const variants = [
		buildTokenCookie(TOKEN),
		buildTokenCookie(TOKEN, { sameSite: "Strict" }),
		buildTokenCookie(TOKEN, { name: "session", path: "/app", maxAgeSeconds: 600, domain: "example.com" }),
	];
	for (const cookie of variants) {
		assert.match(cookie, /HttpOnly/);
		assert.match(cookie, /Secure/);
		assert.match(cookie, /SameSite=(Lax|Strict)/);
	}
});

test("[LW-http.1] weaker configurations are unrepresentable", () => {
	assert.throws(() => buildTokenCookie(TOKEN, { sameSite: "None" as never }), TypeError);
	// There is simply no httpOnly/secure option to turn off.
	assert.ok(!("httpOnly" in ({} as Parameters<typeof buildTokenCookie>[1] & object)));
});

test("defaults are the most locked-down: __Host- prefix, Path=/, SameSite=Lax", () => {
	const cookie = buildTokenCookie(TOKEN);
	assert.match(cookie, /^__Host-token=/);
	assert.match(cookie, /Path=\//);
	assert.match(cookie, /SameSite=Lax/);
});

test("__Host- constraints are enforced", () => {
	assert.throws(() => buildTokenCookie(TOKEN, { domain: "example.com" }), TypeError);
	assert.throws(() => buildTokenCookie(TOKEN, { path: "/api" }), TypeError);
});

test("tokens and metadata that could break the header are rejected", () => {
	assert.throws(() => buildTokenCookie("bad;token"), TypeError);
	assert.throws(() => buildTokenCookie("bad token"), TypeError);
	assert.throws(() => buildTokenCookie(""), TypeError);
	assert.throws(() => buildTokenCookie(TOKEN, { name: "bad name" }), TypeError);
	assert.throws(() => buildTokenCookie(TOKEN, { name: "n", path: "/a;b" }), TypeError);
	assert.throws(() => buildTokenCookie(TOKEN, { name: "n", domain: "evil.com;" }), TypeError);
	assert.throws(() => buildTokenCookie(TOKEN, { maxAgeSeconds: 1.5 }), TypeError);
});

test("setTokenCookie appends to response headers", () => {
	const headers = new Headers();
	setTokenCookie(headers, TOKEN);
	assert.match(headers.get("set-cookie") ?? "", /__Host-token=/);
});

test("clearTokenCookie expires the cookie", () => {
	const headers = new Headers();
	clearTokenCookie(headers);
	const cookie = headers.get("set-cookie") ?? "";
	assert.match(cookie, /__Host-token=;/);
	assert.match(cookie, /Max-Age=0/);
	assert.match(cookie, /HttpOnly/);
});

test("readTokenCookie round-trips from strings and Headers", () => {
	const headers = new Headers({ cookie: `a=1; __Host-token=${TOKEN}; b=2` });
	assert.equal(readTokenCookie(headers), TOKEN);
	assert.equal(readTokenCookie(`__Host-token=${TOKEN}`), TOKEN);
	assert.equal(readTokenCookie({ headers }), TOKEN);
});

test("readTokenCookie returns undefined for absent or malformed cookies", () => {
	assert.equal(readTokenCookie(new Headers()), undefined);
	assert.equal(readTokenCookie(null), undefined);
	assert.equal(readTokenCookie("othercookie=1"), undefined);
	assert.equal(readTokenCookie("__Host-token=bad token"), undefined);
	assert.equal(readTokenCookie(`x=${"a".repeat(20000)}`), undefined);
});

test("readTokenCookie throws on an unaccepted source instead of reading as absent", () => {
	// A Node/Express request: `headers` is a plain record, not `Headers`.
	// This used to return `undefined`, which is indistinguishable from a
	// request that genuinely carried no cookie.
	const expressReq = { headers: { cookie: `__Host-token=${TOKEN}` } };
	assert.throws(() => readTokenCookie(expressReq as never), TypeError);
	// The error has to say what to do about it, not just that it failed.
	assert.throws(
		() => readTokenCookie(expressReq as never),
		/new Headers\(req\.headers/,
		"the error should carry the fix"
	);
	for (const bad of [42, true, [], () => {}, Symbol("x")]) {
		assert.throws(() => readTokenCookie(bad as never), TypeError, `should reject: ${String(bad)}`);
	}
	// An explicit nothing is still a legitimate "no cookie", not a mistake.
	assert.equal(readTokenCookie(null), undefined);
	assert.equal(readTokenCookie(undefined), undefined);
});

test("readTokenCookie accepts a cross-realm Headers", () => {
	// A `Headers` from another realm (undici's own copy, a vm context, an
	// edge/node boundary) fails `instanceof` but is still a Headers.
	const foreign = { get: (name: string) => (name === "cookie" ? `__Host-token=${TOKEN}` : null) };
	assert.equal(readTokenCookie(foreign as never), TOKEN);
	assert.equal(readTokenCookie({ headers: foreign } as never), TOKEN);
});

test("readTokenCookie refuses a shadowed cookie rather than guessing", () => {
	// Servers disagree on whether the first or last duplicate wins; an
	// attacker who can set a same-named cookie relies on that disagreement.
	const shadowed = `__Host-token=${TOKEN}; __Host-token=attackervalue`;
	assert.equal(readTokenCookie(shadowed), undefined);
	assert.equal(readTokenCookie(`__Host-token=attackervalue; __Host-token=${TOKEN}`), undefined);
	// One occurrence is still fine, neighbours and all.
	assert.equal(readTokenCookie(`other=1; __Host-token=${TOKEN}; last=2`), TOKEN);
});
