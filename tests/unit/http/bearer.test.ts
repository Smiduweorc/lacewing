import { test } from "node:test";
import assert from "node:assert/strict";
import { parseBearer } from "../../../src/http/bearer.js";
import { BearerParseFailed } from "../../../src/util/errors.js";

const TOKEN = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln";

test("parses exactly one well-formed Bearer credential", () => {
	assert.equal(parseBearer(`Bearer ${TOKEN}`), TOKEN);
	// token68 padding is legal.
	assert.equal(parseBearer("Bearer abc123=="), "abc123==");
});

test("accepts Headers and Request-shaped sources", () => {
	const headers = new Headers({ authorization: `Bearer ${TOKEN}` });
	assert.equal(parseBearer(headers), TOKEN);
	assert.equal(parseBearer({ headers }), TOKEN);
});

test("[LW-http.2] scheme tricks are rejected", () => {
	const bad = [
		`bearer ${TOKEN}`,
		`BEARER ${TOKEN}`,
		`Basic ${TOKEN}`,
		`Bearer  ${TOKEN}`, // double space
		`Bearer ${TOKEN} `, // trailing space
		` Bearer ${TOKEN}`,
		`Bearer\t${TOKEN}`,
		"Bearer",
		"Bearer ",
	];
	for (const value of bad) {
		assert.throws(() => parseBearer(value), BearerParseFailed, `expected rejection: ${JSON.stringify(value)}`);
	}
});

test("[LW-http.2] multiple tokens are rejected", () => {
	assert.throws(() => parseBearer(`Bearer ${TOKEN} ${TOKEN}`), BearerParseFailed);
	// Duplicate Authorization headers arrive comma-joined via Headers.
	const headers = new Headers();
	headers.append("authorization", `Bearer ${TOKEN}`);
	headers.append("authorization", `Bearer ${TOKEN}`);
	assert.throws(() => parseBearer(headers), BearerParseFailed);
});

test("missing or oversized headers are rejected", () => {
	assert.throws(() => parseBearer(undefined), BearerParseFailed);
	assert.throws(() => parseBearer(null), BearerParseFailed);
	assert.throws(() => parseBearer(new Headers()), BearerParseFailed);
	assert.throws(() => parseBearer(""), BearerParseFailed);
	assert.throws(() => parseBearer(`Bearer ${"a".repeat(20000)}`), BearerParseFailed);
});

test("[LW-http.2] there is deliberately no query-string parsing", () => {
	// The API accepts headers only; a URL never parses.
	assert.throws(
		() => parseBearer(`https://api.example.com/?access_token=${TOKEN}`),
		BearerParseFailed
	);
});
