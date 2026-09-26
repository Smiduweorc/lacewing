/**
 * `lacewing/extension` is a semver commitment, so its surface is pinned
 * here: adding a name to it is a decision, not a side effect of an export
 * line.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as extension from "../../src/extension.js";
import { AlgorithmNotAllowed, JWTInvalid } from "../../src/util/errors.js";

const { getAlgorithmProperties, parseDuration, parseJsonObject, readHeaderValue } = extension;

test("[LW-ext.1] the extension exports exactly the four read-only helpers", () => {
	assert.deepEqual(Object.keys(extension).sort(), [
		"getAlgorithmProperties",
		"parseDuration",
		"parseJsonObject",
		"readHeaderValue",
	]);
});

test("[LW-ext.1] nothing that changes the registry or header policy is reachable", () => {
	for (const name of ["registerLegacyAlgorithm", "validateHeader", "toValidAlg", "SetAlg"]) {
		assert.equal(name in extension, false, name);
	}
});

test("[LW-ext.1] a registry lookup is frozen and cannot weaken later imports", () => {
	const info = getAlgorithmProperties("PS256");
	assert.deepEqual({ ...info }, { name: "PS256", kty: "RSA", minKeyBits: 2048 });
	assert.throws(() => {
		(info as { minKeyBits: number }).minKeyBits = 512;
	}, TypeError);
	assert.equal(getAlgorithmProperties("PS256").minKeyBits, 2048);
});

test("a registry lookup of an absent algorithm throws AlgorithmNotAllowed without echoing it", () => {
	for (const alg of ["none", "RS256", "HS1", "", "ed25519", "EVIL<script>"]) {
		try {
			getAlgorithmProperties(alg);
			assert.fail(`${alg} should have been refused`);
		} catch (error) {
			assert.ok(error instanceof AlgorithmNotAllowed, alg);
			assert.equal(error.code, "ALGORITHM_NOT_ALLOWED");
			if (alg.length > 0) assert.ok(!error.message.includes(alg), alg);
		}
	}
});

test("parseDuration reads seconds and each unit suffix", () => {
	const cases: Array<[number | string, number]> = [
		[0, 0],
		[1, 1],
		[900, 900],
		["0s", 0],
		["30s", 30],
		["15m", 900],
		["1h", 3600],
		["7d", 604800],
		[" 5m ", 300],
		["999999999s", 999999999],
	];
	for (const [input, expected] of cases) {
		assert.equal(parseDuration(input), expected, String(input));
	}
});

test("parseDuration refuses anything that is not a whole, non-negative duration", () => {
	for (const input of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, -0.1]) {
		assert.throws(() => parseDuration(input), TypeError, String(input));
	}
	for (const input of ["", "5", "1w", "-1s", "1.5m", "5M", "5 m", "1000000000s", "m", "1h30m"]) {
		assert.throws(() => parseDuration(input), TypeError, input);
	}
});

test("parseDuration refuses a value of the wrong type with a TypeError that names the fix", () => {
	for (const input of [undefined, null, {}, [], true, 10n]) {
		assert.throws(
			() => parseDuration(input as unknown as string),
			(error: unknown) =>
				error instanceof TypeError && error.message.includes("number of seconds"),
			String(input)
		);
	}
});

test("readHeaderValue reads from Headers, a Request, or a raw string", () => {
	const headers = new Headers({ dpop: "proof", authorization: "DPoP token" });
	assert.equal(readHeaderValue(headers, "dpop", "reader"), "proof");
	assert.equal(readHeaderValue(headers, "DPoP", "reader"), "proof");
	const request = new Request("https://api.example.com/", { headers });
	assert.equal(readHeaderValue(request, "authorization", "reader"), "DPoP token");
	assert.equal(readHeaderValue("raw value", "anything", "reader"), "raw value");
});

test("readHeaderValue reports an absent header or an explicit nothing as undefined", () => {
	assert.equal(readHeaderValue(new Headers(), "dpop", "reader"), undefined);
	assert.equal(readHeaderValue(null, "dpop", "reader"), undefined);
	assert.equal(readHeaderValue(undefined, "dpop", "reader"), undefined);
});

test("readHeaderValue shows duplicate headers joined, so a caller can refuse them", () => {
	const headers = new Headers();
	headers.append("dpop", "a.b.c");
	headers.append("dpop", "d.e.f");
	assert.equal(readHeaderValue(headers, "dpop", "reader"), "a.b.c, d.e.f");
});

test("readHeaderValue throws a TypeError naming the calling helper for a Node-style request", () => {
	const nodeStyle = { headers: { dpop: "proof" } };
	assert.throws(
		() => readHeaderValue(nodeStyle as unknown as Headers, "dpop", "verifyThing"),
		(error: unknown) => error instanceof TypeError && error.message.startsWith("verifyThing()")
	);
});

test("parseJsonObject returns a plain object parsed from JSON text", () => {
	assert.deepEqual(parseJsonObject("{\"htm\":\"GET\",\"cnf\":{\"jkt\":\"x\"},\"list\":[1,{\"a\":2}]}", "payload"), {
		htm: "GET",
		cnf: { jkt: "x" },
		list: [1, { a: 2 }],
	});
});

test("parseJsonObject refuses a member name that appears twice, at any depth and in any spelling", () => {
	const cases = [
		"{\"alg\":\"ES256\",\"alg\":\"none\"}",
		"{\"jwk\":{\"kty\":\"EC\",\"kty\":\"RSA\"}}",
		"{\"a\":[{\"b\":1,\"b\":2}]}",
		"{\"htu\":\"x\",\"\\u0068tu\":\"y\"}",
	];
	for (const text of cases) {
		assert.throws(
			() => parseJsonObject(text, "header"),
			(error: unknown) =>
				error instanceof JWTInvalid && /duplicate JSON key/.test(error.message),
			text
		);
	}
});

test("parseJsonObject allows the same name in sibling objects and as a value", () => {
	assert.deepEqual(parseJsonObject("{\"a\":{\"k\":1},\"b\":{\"k\":2},\"c\":\"k\"}", "payload"), {
		a: { k: 1 },
		b: { k: 2 },
		c: "k",
	});
});

test("parseJsonObject refuses JSON that is not an object, and text that is not JSON", () => {
	for (const text of ["[]", "[{}]", "null", "1", "\"str\"", "true"]) {
		assert.throws(() => parseJsonObject(text, "header"), JWTInvalid, text);
	}
	for (const text of ["", "{", "{'a':1}", "{\"a\":1,}", "\uFEFF{}"]) {
		assert.throws(() => parseJsonObject(text, "header"), JWTInvalid, text);
	}
});
