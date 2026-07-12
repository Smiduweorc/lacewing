/**
 * Docs-mechanism requirements: some obligations can only be
 * discharged by *telling the user something* - there is no runtime check that
 * can stop a developer putting a token in `localStorage` in their own app.
 *
 * "The docs say so" is still a claim, and claims get proofs. These tests read
 * the shipped README and assert the required warnings are actually present, so
 * a future edit that quietly deletes them fails the compliance gate.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const README = readFileSync(
	join(dirname(fileURLToPath(import.meta.url)), "..", "..", "README.md"),
	"utf8"
);
const readme = README.toLowerCase();

test("[LW-payload.3] the docs state that JWS payloads are readable plaintext", () => {
	// The claim must be made in terms a reader cannot miss: the payload is
	// encoded, not encrypted, and secrets must not go in it.
	assert.ok(
		readme.includes("plaintext"),
		"README must state that a JWS payload is plaintext"
	);
	assert.match(
		readme,
		/base64url-encoded \*\*plaintext\*\*|base64url-encoded plaintext/,
		"README must explain that the payload is base64url-encoded plaintext"
	);
	assert.ok(
		readme.includes("never put secrets in it") || readme.includes("do not put secrets in tokens"),
		"README must tell the reader not to put secrets in the payload"
	);
});

test("[LW-http.3] the docs warn against localStorage/sessionStorage and show the alternatives", () => {
	assert.ok(readme.includes("localstorage"), "README must name localStorage");
	assert.ok(readme.includes("sessionstorage"), "README must name sessionStorage");
	// The warning has to say *why*, and point somewhere better.
	assert.ok(readme.includes("xss"), "README must explain the XSS risk");
	assert.ok(readme.includes("httponly"), "README must offer the HttpOnly cookie alternative");
	assert.ok(
		readme.includes("in-memory") || readme.includes("memory bearer") || readme.includes("bearer token"),
		"README must offer the in-memory bearer alternative for services"
	);
});

test("the docs draw the line between revocation and replay protection", () => {
	// Design limitation made explicit: a valid, non-revoked token is replayable
	// until exp. The docs must say so and offer the mitigations.
	assert.ok(
		readme.includes("revocation is not replay protection"),
		"README must state that revocation is not replay protection"
	);
	assert.ok(
		readme.includes("replayed") && readme.includes("until `exp`"),
		"README must state the replay window is bounded only by exp"
	);
	assert.ok(readme.includes("jti-seen") || readme.includes("jti cache"), "README must show the jti-seen cache option");
});

test("the docs caveat A192* portability outside Node", () => {
	assert.ok(
		readme.includes("192-bit aes"),
		"README must name the 192-bit AES portability caveat"
	);
	assert.ok(
		readme.includes("webcrypto"),
		"README must explain it is a WebCrypto implementation gap"
	);
});

test("[LW-alg.1] the docs lead with asymmetric keys and caveat HMAC's shared-secret problem", () => {
	// The default in the examples is the asymmetric one.
	assert.ok(
		readme.includes("eddsa by default") || /generatekeypair\(\).*eddsa/s.test(readme),
		"README's key-generation example must default to EdDSA"
	);
	// And the HMAC section must lead with the distribution caveat: anyone who
	// can verify an HMAC token can also mint one.
	assert.ok(readme.includes("hmac"), "README must discuss HMAC");
	assert.ok(
		readme.includes("mint"),
		"README must warn that every HMAC verifier can also mint tokens"
	);
	assert.ok(
		readme.includes("asymmetric keys + jwks") || readme.includes("use asymmetric"),
		"README must point beyond-single-service users at asymmetric keys + JWKS"
	);
});
