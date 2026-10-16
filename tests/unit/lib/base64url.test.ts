import { test } from "node:test";
import assert from "node:assert/strict";
import { JWTError } from "../../../src/util/errors.js";
import { refusal } from "../../helpers.js";
import { Buffer } from "node:buffer";
import fc from "fast-check";
import { decodeBase64url, encodeBase64url } from "../../../src/lib/base64url.js";

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
	assert.throws(() => decodeBase64url("QQ=="), refusal("JWT_INVALID"));
	assert.throws(() => decodeBase64url("SGVsbG8="), refusal("JWT_INVALID"));
});

test("[strictness] rejects whitespace and standard-base64 characters", () => {
	for (const input of ["QUJ D", "QUJ\nD", " QUJD", "QUJD ", "a+b", "a/b", "a.b"]) {
		assert.throws(() => decodeBase64url(input), refusal("JWT_INVALID"));
	}
});

test("[strictness] rejects impossible lengths", () => {
	assert.throws(() => decodeBase64url("AAAAA"), refusal("JWT_INVALID"));
});

test("[strictness] rejects non-canonical trailing bits", () => {
	// "_w" and "_x" would both decode to [0xff] in a lenient decoder.
	assert.deepEqual(decodeBase64url("_w"), new Uint8Array([0xff]));
	assert.throws(() => decodeBase64url("_x"), refusal("JWT_INVALID"));
});

// The Buffer-backed decoder Lacewing shipped through 1.x, kept here as the
// reference the portable implementation must agree with on every input.
function bufferDecode(encoded: string): Uint8Array | "refused" {
	if (!/^[A-Za-z0-9_-]*$/.test(encoded) || encoded.length % 4 === 1) return "refused";
	const bytes = Buffer.from(encoded, "base64url");
	return bytes.toString("base64url") === encoded ? new Uint8Array(bytes) : "refused";
}

function portableDecode(encoded: string): Uint8Array | "refused" {
	try {
		return decodeBase64url(encoded);
	} catch (error) {
		assert.ok(error instanceof JWTError && error.code === "JWT_INVALID");
		return "refused";
	}
}

test("[property] encoding matches Buffer's base64url for any bytes", () => {
	fc.assert(
		fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
			assert.equal(encodeBase64url(bytes), Buffer.from(bytes).toString("base64url"));
		}),
		{ numRuns: 2000 }
	);
});

test("[property] any bytes round-trip to themselves", () => {
	fc.assert(
		fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
			assert.deepEqual(decodeBase64url(encodeBase64url(bytes)), bytes);
		}),
		{ numRuns: 2000 }
	);
});

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
// Mostly alphabet characters, so most strings get past the charset check and
// exercise the length and trailing-bit rules; the rest is what a lenient
// decoder forgives.
const nearlyBase64url = fc
	.array(
		fc.oneof(
			{ weight: 20, arbitrary: fc.constantFrom(...ALPHABET) },
			{ weight: 1, arbitrary: fc.constantFrom("=", "+", "/", " ", "\n", ".", "é", "\0") }
		),
		{ maxLength: 40 }
	)
	.map((chars) => chars.join(""));

test("[property] accepts and refuses exactly what the Buffer decoder did", () => {
	fc.assert(
		fc.property(fc.oneof(nearlyBase64url, fc.string({ maxLength: 40 })), (encoded) => {
			assert.deepEqual(portableDecode(encoded), bufferDecode(encoded));
		}),
		{ numRuns: 20000 }
	);
});

test("[strictness] every last character with stray low bits is refused", () => {
	for (const last of ALPHABET) {
		const index = ALPHABET.indexOf(last);
		assert.equal(portableDecode(`A${last}`) === "refused", (index & 0b1111) !== 0, `A${last}`);
		assert.equal(portableDecode(`AA${last}`) === "refused", (index & 0b11) !== 0, `AA${last}`);
	}
});

test("decodes the RFC 4648 §10 test vectors, unpadded", () => {
	const text = new TextDecoder();
	const vectors: Array<[string, string]> = [
		["", ""], ["Zg", "f"], ["Zm8", "fo"], ["Zm9v", "foo"],
		["Zm9vYg", "foob"], ["Zm9vYmE", "fooba"], ["Zm9vYmFy", "foobar"],
	];
	for (const [encoded, decoded] of vectors) {
		assert.equal(text.decode(decodeBase64url(encoded)), decoded);
		assert.equal(encodeBase64url(new TextEncoder().encode(decoded)), encoded);
	}
	assert.deepEqual(decodeBase64url("-_8"), new Uint8Array([0xfb, 0xff]));
});
