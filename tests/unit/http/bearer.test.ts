import { test } from "node:test";
import assert from "node:assert/strict";
import { refusal } from "../../helpers.js";
import { parseBearer } from "../../../src/http/bearer.js";

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
		assert.throws(() => parseBearer(value), refusal("BEARER_PARSE_FAILED"), `expected rejection: ${JSON.stringify(value)}`);
	}
});

test("[LW-http.2] multiple tokens are rejected", () => {
	assert.throws(() => parseBearer(`Bearer ${TOKEN} ${TOKEN}`), refusal("BEARER_PARSE_FAILED"));
	// Duplicate Authorization headers arrive comma-joined via Headers.
	const headers = new Headers();
	headers.append("authorization", `Bearer ${TOKEN}`);
	headers.append("authorization", `Bearer ${TOKEN}`);
	assert.throws(() => parseBearer(headers), refusal("BEARER_PARSE_FAILED"));
});

test("missing or oversized headers are rejected", () => {
	assert.throws(() => parseBearer(undefined), refusal("BEARER_PARSE_FAILED"));
	assert.throws(() => parseBearer(null), refusal("BEARER_PARSE_FAILED"));
	assert.throws(() => parseBearer(new Headers()), refusal("BEARER_PARSE_FAILED"));
	assert.throws(() => parseBearer(""), refusal("BEARER_PARSE_FAILED"));
	assert.throws(() => parseBearer(`Bearer ${"a".repeat(20000)}`), refusal("BEARER_PARSE_FAILED"));
});

test("an unaccepted source throws TypeError, not a misleading 'missing header'", () => {
	// Node/Express requests carry a plain `headers` record. Reporting that
	// as a BEARER_PARSE_FAILED "Missing Authorization header" error blamed the client
	// for a header that was in fact present.
	const expressReq = { headers: { authorization: `Bearer ${TOKEN}` } };
	assert.throws(() => parseBearer(expressReq as never), TypeError);
	assert.throws(() => parseBearer(expressReq as never), /new Headers\(req\.headers/);
	// A genuinely absent header is still the client-facing error.
	assert.throws(() => parseBearer(null), refusal("BEARER_PARSE_FAILED"));
});

test("a cross-realm Headers still parses", () => {
	const foreign = {
		get: (name: string) => (name === "authorization" ? `Bearer ${TOKEN}` : null),
	};
	assert.equal(parseBearer(foreign as never), TOKEN);
	assert.equal(parseBearer({ headers: foreign } as never), TOKEN);
});

test("[LW-http.2] there is deliberately no query-string parsing", () => {
	// The API accepts headers only; a URL never parses.
	assert.throws(
		() => parseBearer(`https://api.example.com/?access_token=${TOKEN}`),
		refusal("BEARER_PARSE_FAILED")
	);
});
