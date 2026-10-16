/**
 * Strict JSON object parsing: duplicate member names at any depth are a
 * parser differential (§3.7 strictness) and must be rejected. Rejection tests
 * outnumber acceptance tests, per the suite convention.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { refusal } from "../../helpers.js";
import { parseJsonObject, assertNoDuplicateKeys } from "../../../src/lib/json.js";

test("accepts a well-formed object with unique keys", () => {
	const obj = parseJsonObject("{\"a\":1,\"b\":{\"c\":2},\"d\":[{\"e\":3},{\"e\":4}]}", "payload");
	assert.deepEqual(obj, { a: 1, b: { c: 2 }, d: [{ e: 3 }, { e: 4 }] });
});

test("the same key name in sibling objects is not a duplicate", () => {
	assert.doesNotThrow(() => assertNoDuplicateKeys("{\"x\":{\"k\":1},\"y\":{\"k\":2}}", "payload"));
});

test("rejects a duplicated top-level key", () => {
	assert.throws(() => parseJsonObject("{\"alg\":\"HS256\",\"alg\":\"none\"}", "header"), refusal("JWT_INVALID"));
});

test("rejects a duplicated key nested in an object", () => {
	assert.throws(() => parseJsonObject("{\"a\":{\"k\":1,\"k\":2}}", "payload"), refusal("JWT_INVALID"));
});

test("rejects a duplicated key inside an array element", () => {
	assert.throws(() => parseJsonObject("{\"a\":[{\"k\":1,\"k\":2}]}", "payload"), refusal("JWT_INVALID"));
});

test("treats an escaped key name as the same key", () => {
	// "a" decodes to "a".
	assert.throws(() => parseJsonObject("{\"a\":1,\"\\u0061\":2}", "payload"), refusal("JWT_INVALID"));
});

test("colons and braces inside string values do not confuse key tracking", () => {
	assert.doesNotThrow(() =>
		assertNoDuplicateKeys("{\"a\":\"{\\\"a\\\":1}\",\"b\":\"c:d\"}", "payload")
	);
});

test("a duplicate key whose value is itself a string is still caught", () => {
	assert.throws(() => parseJsonObject("{\"a\":\"x\",\"a\":\"y\"}", "payload"), refusal("JWT_INVALID"));
});

test("non-objects are rejected before the duplicate scan", () => {
	assert.throws(() => parseJsonObject("[1,2,3]", "payload"), refusal("JWT_INVALID"));
	assert.throws(() => parseJsonObject("\"a string\"", "payload"), refusal("JWT_INVALID"));
	assert.throws(() => parseJsonObject("not json", "payload"), refusal("JWT_INVALID"));
});

// Each of these is a path segment in a prototype-pollution gadget: a caller
// that deep-merges the payload writes through `__proto__` or
// `constructor.prototype` into Object.prototype.
for (const name of ["__proto__", "constructor", "prototype"]) {
	test(`rejects "${name}" as a top-level member name`, () => {
		assert.throws(() => parseJsonObject(`{"sub":"user-42","${name}":{"isAdmin":true}}`, "payload"), {
			name: "JWTError",
			code: "JWT_INVALID",
			message: `lacewing: Token payload contains the member name "${name}", which can pollute object prototypes`,
		});
	});

	test(`rejects "${name}" as a member name nested in an object`, () => {
		assert.throws(() => parseJsonObject(`{"a":{"b":{"${name}":1}}}`, "payload"), { code: "JWT_INVALID" });
	});

	test(`rejects "${name}" as a member name inside an array element`, () => {
		assert.throws(() => parseJsonObject(`{"a":[1,{"${name}":1}]}`, "header"), { code: "JWT_INVALID" });
	});

	test(`accepts "${name}" as a string value`, () => {
		assert.deepEqual(parseJsonObject(`{"a":"${name}","b":["${name}"]}`, "payload"), { a: name, b: [name] });
	});
}

test("rejects __proto__ spelled entirely with unicode escapes", () => {
	const escaped = "\\u005f\\u005f\\u0070\\u0072\\u006f\\u0074\\u006f\\u005f\\u005f";
	assert.throws(() => parseJsonObject(`{"${escaped}":{"isAdmin":true}}`, "payload"), {
		code: "JWT_INVALID",
		message: "lacewing: Token payload contains the member name \"__proto__\", which can pollute object prototypes",
	});
});

test("rejects __proto__ with a single escaped character", () => {
	assert.throws(() => parseJsonObject("{\"\\u005f_proto__\":{}}", "payload"), { code: "JWT_INVALID" });
	assert.throws(() => parseJsonObject("{\"__prot\\u006F__\":{}}", "payload"), { code: "JWT_INVALID" });
});

test("rejects constructor with an escaped first letter", () => {
	assert.throws(() => parseJsonObject("{\"a\":{\"\\u0063onstructor\":{\"prototype\":{}}}}", "payload"), { code: "JWT_INVALID" });
});

test("names that only contain or resemble a prototype key are accepted", () => {
	const text = "{\"__proto\":1,\"proto__\":2,\"_proto_\":3,\"__PROTO__\":4,\"Constructor\":5,\"prototypes\":6,\"x__proto__\":7}";
	assert.deepEqual(Object.keys(parseJsonObject(text, "payload")), ["__proto", "proto__", "_proto_", "__PROTO__", "Constructor", "prototypes", "x__proto__"]);
});
