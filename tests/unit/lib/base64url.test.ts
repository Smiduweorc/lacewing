import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeBase64url, encodeBase64url } from "../../../src/lib/base64url.js";
import { JWTInvalid } from "../../../src/util/errors.js";

test("round-trips arbitrary bytes", () => {
	const samples = [
		new Uint8Array([]),
		new Uint8Array([0]),
		new Uint8Array([255, 254, 253]),
		globalThis.crypto.getRandomValues(new Uint8Array(64)),
	];
	for (const bytes of samples) {
		assert.deepEqual(decodeBase64url(encodeBase64url(bytes)), bytes);
	}
});

test("encodes without padding or URL-unsafe characters", () => {
	const encoded = encodeBase64url(globalThis.crypto.getRandomValues(new Uint8Array(33)));
	assert.match(encoded, /^[A-Za-z0-9_-]+$/);
});

test("[strictness] rejects padding", () => {
	assert.throws(() => decodeBase64url("QQ=="), JWTInvalid);
	assert.throws(() => decodeBase64url("SGVsbG8="), JWTInvalid);
});

test("[strictness] rejects whitespace and standard-base64 characters", () => {
	for (const input of ["QUJ D", "QUJ\nD", " QUJD", "QUJD ", "a+b", "a/b", "a.b"]) {
		assert.throws(() => decodeBase64url(input), JWTInvalid);
	}
});

test("[strictness] rejects impossible lengths", () => {
	assert.throws(() => decodeBase64url("AAAAA"), JWTInvalid);
});

test("[strictness] rejects non-canonical trailing bits", () => {
	// "_w" and "_x" would both decode to [0xff] in a lenient decoder.
	assert.deepEqual(decodeBase64url("_w"), new Uint8Array([0xff]));
	assert.throws(() => decodeBase64url("_x"), JWTInvalid);
});
