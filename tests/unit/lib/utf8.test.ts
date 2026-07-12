import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeUTF8, encodeUTF8 } from "../../../src/lib/utf8.js";
import { JWTInvalid } from "../../../src/util/errors.js";

test("round-trips ASCII, emoji and multi-byte text", () => {
	for (const text of ["hello", "héllo wörld", "👋🌍", "日本語", ""]) {
		assert.equal(decodeUTF8(encodeUTF8(text)), text);
	}
});

test("[8725-3.7.1] encoding rejects lone surrogates", () => {
	assert.throws(() => encodeUTF8("\uD800"), JWTInvalid);
	assert.throws(() => encodeUTF8("a\uDC00b"), JWTInvalid);
	// A proper surrogate pair is fine.
	assert.equal(decodeUTF8(encodeUTF8("👋")), "👋");
});

test("[8725-3.7.1] decoding rejects malformed sequences", () => {
	assert.throws(() => decodeUTF8(new Uint8Array([0xff])), JWTInvalid);
	assert.throws(() => decodeUTF8(new Uint8Array([0xc3])), JWTInvalid);
});

test("[8725-3.7.1] decoding rejects overlong encodings", () => {
	// 0xC0 0xAF is an overlong encoding of "/".
	assert.throws(() => decodeUTF8(new Uint8Array([0xc0, 0xaf])), JWTInvalid);
});

test("[8725-3.7.1] a BOM is preserved, not silently stripped", () => {
	const decoded = decodeUTF8(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
	assert.equal(decoded, "﻿{}");
	// ...which means JSON.parse downstream rejects BOM-prefixed documents.
	assert.throws(() => JSON.parse(decoded));
});
