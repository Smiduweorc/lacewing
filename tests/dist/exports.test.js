// Runs against dist/ after `npm run build`, importing by package name so the
// "exports" map in package.json is what resolves each path. A wrong path or a
// missing .js specifier fails here instead of in someone's install.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const manifest = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

test("every exports entry points at a built file and its declarations", () => {
	for (const [subpath, target] of Object.entries(manifest.exports)) {
		assert.ok(existsSync(join(ROOT, target.default)), `${subpath}: ${target.default}`);
		assert.ok(existsSync(join(ROOT, target.types)), `${subpath}: ${target.types}`);
	}
});

test("every exports entry imports by package name", async () => {
	for (const subpath of Object.keys(manifest.exports)) {
		const specifier = subpath === "." ? manifest.name : `${manifest.name}${subpath.slice(1)}`;
		await assert.doesNotReject(import(specifier), specifier);
	}
});

test("lacewing/extension exposes exactly its four helpers, working", async () => {
	const extension = await import("lacewing/extension");
	assert.deepEqual(Object.keys(extension).sort(), [
		"getAlgorithmProperties",
		"parseDuration",
		"parseJsonObject",
		"readHeaderValue",
	]);
	assert.deepEqual(extension.parseJsonObject("{\"a\":1}", "t"), { a: 1 });
	assert.throws(() => extension.parseJsonObject("{\"a\":1,\"a\":2}", "t"), { code: "JWT_INVALID" });
	assert.equal(extension.parseDuration("15m"), 900);
	assert.equal(extension.getAlgorithmProperties("Ed25519").crv, "Ed25519");
	assert.equal(Object.isFrozen(extension.getAlgorithmProperties("ES256")), true);
	assert.equal(extension.readHeaderValue(new globalThis.Headers({ dpop: "p" }), "dpop", "t"), "p");
});

test("the extension and the root share one registry, not two copies", async () => {
	const extension = await import("lacewing/extension");
	const { AlgorithmNotAllowed } = await import("lacewing");
	assert.throws(() => extension.getAlgorithmProperties("RS256"), AlgorithmNotAllowed);
	const { enableLegacyRS256 } = await import("lacewing/legacy/rs256");
	enableLegacyRS256();
	assert.equal(extension.getAlgorithmProperties("RS256").kty, "RSA");
});
