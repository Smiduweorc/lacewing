/**
 * @security - cookie hardening sweep (LW-http.1). Whatever
 * legal combination of options a caller passes, the emitted Set-Cookie always
 * carries HttpOnly, Secure and a SameSite value; and every attempt to weaken
 * those throws rather than silently producing a soft cookie.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { buildTokenCookie } from "../../index.js";

const skip = process.env.LACEWING_SKIP_SECURITY === "1";
const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl";

test("@security every legal option combination still yields HttpOnly; Secure; SameSite", { skip }, () => {
	const options = fc.record(
		{
			name: fc.constantFrom("__Host-token", "session", "auth"),
			sameSite: fc.constantFrom("Lax" as const, "Strict" as const),
			maxAgeSeconds: fc.option(fc.integer({ min: 0, max: 1_000_000 }), { nil: undefined }),
		},
		{ requiredKeys: [] }
	);
	fc.assert(
		fc.property(options, (opts) => {
			// __Host- names forbid Domain and require Path=/, which are already the
			// defaults, so any of these combinations is legal.
			const cookie = buildTokenCookie(TOKEN, opts);
			assert.ok(cookie.includes("HttpOnly"), cookie);
			assert.ok(cookie.includes("Secure"), cookie);
			assert.match(cookie, /SameSite=(Lax|Strict)/);
		}),
		{ numRuns: 50 }
	);
});

test("@security weakening the cookie is unrepresentable", { skip }, () => {
	assert.throws(() => buildTokenCookie(TOKEN, { sameSite: "None" as unknown as "Lax" }), TypeError);
	assert.throws(() => buildTokenCookie(TOKEN, { domain: "example.com" }), TypeError); // __Host- forbids Domain
	assert.throws(() => buildTokenCookie(TOKEN, { path: "/scoped" }), TypeError); // __Host- requires Path=/
	assert.throws(() => buildTokenCookie("has spaces and \n newline"), TypeError); // junk value
});
