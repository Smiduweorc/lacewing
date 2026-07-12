/**
 * LW-http.1/.2 - the paved road for transport. Token cookies always carry
 * `HttpOnly; Secure; SameSite` (weaker configurations are unrepresentable),
 * and the bearer parser is strict RFC 6750: one header, one scheme, one token.
 * (LW-http.3, the documentation requirement, is proved in `docs.test.ts`.)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTokenCookie, setTokenCookie, readTokenCookie, parseBearer, BearerParseFailed } from "../../index.js";

const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2ln";

test("[LW-http.1] every emitted cookie carries HttpOnly, Secure and SameSite", () => {
	for (const options of [{}, { sameSite: "Strict" as const }, { name: "session", maxAgeSeconds: 600 }]) {
		const cookie = buildTokenCookie(TOKEN, options);
		assert.ok(cookie.includes("HttpOnly"), cookie);
		assert.ok(cookie.includes("Secure"), cookie);
		assert.match(cookie, /SameSite=(Lax|Strict)/, cookie);
	}
});

test("[LW-http.1] the weakening knobs do not exist - SameSite=None and __Host- violations throw", () => {
	// There is no option to drop HttpOnly/Secure; the only SameSite values the
	// type (and the runtime) accept are Lax and Strict.
	assert.throws(() => buildTokenCookie(TOKEN, { sameSite: "None" as unknown as "Lax" }), TypeError);
	// __Host- prefix rules are enforced, so the locked-down default stays locked down.
	assert.throws(() => buildTokenCookie(TOKEN, { domain: "example.com" }), TypeError);
	assert.throws(() => buildTokenCookie(TOKEN, { path: "/api" }), TypeError);
});

test("[LW-http.1] the response helper round-trips through real Headers", () => {
	const headers = new Headers();
	setTokenCookie(headers, TOKEN);
	const setCookie = headers.get("set-cookie") as string;
	assert.ok(setCookie.includes("HttpOnly"));
	assert.equal(readTokenCookie(new Headers({ cookie: `__Host-token=${TOKEN}` })), TOKEN);
});

test("[LW-http.2] the bearer parser is strict: casing, whitespace and multi-token tricks all fail", () => {
	assert.equal(parseBearer(`Bearer ${TOKEN}`), TOKEN);
	for (const bad of [
		`bearer ${TOKEN}`, // wrong case
		`Bearer  ${TOKEN}`, // two spaces
		`Bearer ${TOKEN} ${TOKEN}`, // two tokens
		`Bearer ${TOKEN}, Bearer ${TOKEN}`, // joined duplicate headers
		`Basic ${TOKEN}`, // wrong scheme
		"Bearer", // no token
		"",
	]) {
		assert.throws(() => parseBearer(bad), BearerParseFailed, `should reject: ${bad.slice(0, 24)}`);
	}
});

test("[LW-http.2] there is no query-string token path at all", () => {
	// The parser only ever looks at the Authorization header. A URL carrying
	// ?access_token=... is not a thing Lacewing can be asked to read.
	assert.throws(() => parseBearer("?access_token=" + TOKEN), BearerParseFailed);
	assert.throws(() => parseBearer(null), BearerParseFailed);
	assert.throws(() => parseBearer(undefined), BearerParseFailed);
});
