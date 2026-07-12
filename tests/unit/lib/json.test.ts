/**
 * Strict JSON object parsing: duplicate member names at any depth are a
 * parser differential (§3.7 strictness) and must be rejected. Rejection tests
 * outnumber acceptance tests, per the suite convention.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJsonObject, assertNoDuplicateKeys } from "../../../src/lib/json.js";
import { JWTInvalid } from "../../../src/util/errors.js";

test("accepts a well-formed object with unique keys", () => {
	const obj = parseJsonObject("{\"a\":1,\"b\":{\"c\":2},\"d\":[{\"e\":3},{\"e\":4}]}", "payload");
	assert.deepEqual(obj, { a: 1, b: { c: 2 }, d: [{ e: 3 }, { e: 4 }] });
});

test("the same key name in sibling objects is not a duplicate", () => {
	assert.doesNotThrow(() => assertNoDuplicateKeys("{\"x\":{\"k\":1},\"y\":{\"k\":2}}", "payload"));
});

test("rejects a duplicated top-level key", () => {
	assert.throws(() => parseJsonObject("{\"alg\":\"HS256\",\"alg\":\"none\"}", "header"), JWTInvalid);
});

test("rejects a duplicated key nested in an object", () => {
	assert.throws(() => parseJsonObject("{\"a\":{\"k\":1,\"k\":2}}", "payload"), JWTInvalid);
});

test("rejects a duplicated key inside an array element", () => {
	assert.throws(() => parseJsonObject("{\"a\":[{\"k\":1,\"k\":2}]}", "payload"), JWTInvalid);
});

test("treats an escaped key name as the same key", () => {
	// "a" decodes to "a".
	assert.throws(() => parseJsonObject("{\"a\":1,\"\\u0061\":2}", "payload"), JWTInvalid);
});

test("colons and braces inside string values do not confuse key tracking", () => {
	assert.doesNotThrow(() =>
		assertNoDuplicateKeys("{\"a\":\"{\\\"a\\\":1}\",\"b\":\"c:d\"}", "payload")
	);
});

test("a duplicate key whose value is itself a string is still caught", () => {
	assert.throws(() => parseJsonObject("{\"a\":\"x\",\"a\":\"y\"}", "payload"), JWTInvalid);
});

test("non-objects are rejected before the duplicate scan", () => {
	assert.throws(() => parseJsonObject("[1,2,3]", "payload"), JWTInvalid);
	assert.throws(() => parseJsonObject("\"a string\"", "payload"), JWTInvalid);
	assert.throws(() => parseJsonObject("not json", "payload"), JWTInvalid);
});
