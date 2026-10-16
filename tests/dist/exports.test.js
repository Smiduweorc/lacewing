// Runs against dist/ after `npm run build`, importing by package name so the
// "exports" map in package.json is what resolves each path. A wrong path or a
// missing .js specifier fails here instead of in someone's install.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { env, execPath, platform } from "node:process";
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

// Descriptors are checked by identity, so every entry point must hand out the
// same objects. A build that duplicated lib/algorithms into two chunks would
// make LEGACY_RS256 from one entry a forgery to the other.
test("legacy descriptors from either legacy entry are the ones the root and extension accept", async () => {
	const extension = await import("lacewing/extension");
	const { LEGACY_RS256, LEGACY_RSA } = await import("lacewing/legacy/rsa");
	const rs256 = await import("lacewing/legacy/rs256");
	const { generateKeyPair, JWTError } = await import("lacewing");
	assert.equal(rs256.LEGACY_RS256, LEGACY_RS256);
	assert.equal(LEGACY_RSA[0], LEGACY_RS256);
	assert.equal(extension.getAlgorithmProperties("RS256", [rs256.LEGACY_RS256]), LEGACY_RS256);
	const pair = await generateKeyPair(rs256.LEGACY_RS256);
	assert.equal(pair.publicKey.algorithm, "RS256");
	assert.throws(() => extension.getAlgorithmProperties("RS256"), (error) => error instanceof JWTError && error.code === "ALGORITHM_NOT_ALLOWED");
});

// `"sideEffects": false` is a promise to bundlers that dropping an unused
// import changes nothing. A fresh process proves it: no new globals, no
// output, from loading every entry point.
test("importing every entry point adds no globals and prints nothing", () => {
	const specifiers = Object.keys(manifest.exports).map((subpath) =>
		subpath === "." ? manifest.name : `${manifest.name}${subpath.slice(1)}`
	);
	const script = [
		"const before = new Set(Object.getOwnPropertyNames(globalThis));",
		`for (const s of ${JSON.stringify(specifiers)}) await import(s);`,
		"const added = Object.getOwnPropertyNames(globalThis).filter((n) => !before.has(n));",
		"if (added.length > 0) { process.exitCode = 1; process.stderr.write(added.join(',')); }",
	].join("\n");
	const run = spawnSync(execPath, ["--input-type=module", "-e", script], {
		cwd: ROOT,
		encoding: "utf8",
	});
	assert.equal(run.status, 0, run.stderr);
	assert.equal(run.stdout, "");
	assert.equal(manifest.sideEffects, false);
});

test("the tarball holds dist/ and the documents, and no source or tests", () => {
	// On Windows npm is npm.cmd, which Node refuses to spawn without a shell.
	// Under `npm run` npm_execpath is npm's own JS entry, so run that instead.
	const args = ["pack", "--dry-run", "--json", "--ignore-scripts"];
	const npmCli = env.npm_execpath;
	const run = npmCli && /\.c?js$/.test(npmCli)
		? spawnSync(execPath, [npmCli, ...args], { cwd: ROOT, encoding: "utf8" })
		: spawnSync("npm", args, { cwd: ROOT, encoding: "utf8", shell: platform === "win32" });
	assert.equal(run.status, 0, run.error?.message ?? run.stderr);
	// npm 10 prints an array of packs, npm 11 an object keyed by package name.
	const packed = JSON.parse(run.stdout);
	const files = (Array.isArray(packed) ? packed[0] : packed[manifest.name]).files.map(
		(entry) => entry.path
	);
	for (const required of ["dist/index.js", "dist/types/index.d.ts", "README.md", "LICENSE", "NOTICE.md"]) {
		assert.ok(files.includes(required), required);
	}
	const outside = files.filter(
		(path) => !path.startsWith("dist/") && !/^[A-Z-]+\.md$|^LICENSE$|^package\.json$/.test(path)
	);
	assert.deepEqual(outside, []);
	assert.equal(files.some((path) => path.startsWith("dist/tests/")), false);
});
