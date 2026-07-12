/**
 * The compile-time half of LW-decode.1 (and the §3.1.2 key binding).
 *
 * "It won't compile" is a claim, and claims get proofs. This runs `tsc` over
 * `tests/types/fixtures/` - a directory of files that each contain exactly one
 * assignment the type system must reject - and asserts every one of them still
 * fails, with the error landing in the file we expect.
 *
 * Note the inversion: a *successful* compile is a FAILURE here. If someone
 * removes the `__brand` from `VerifiedJwt`, these fixtures start compiling and
 * this test goes red - which is the entire point.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const PROJECT = join(HERE, "tsconfig.json");

/** Each fixture, and the TypeScript error code it must still provoke. */
const FIXTURES: Array<{ file: string; code: string; why: string }> = [
	{
		file: "untrusted-to-verified.ts",
		code: "TS2322",
		why: "an UntrustedJwt must never be assignable to a VerifiedJwt",
	},
	{
		file: "forged-verified-jwt.ts",
		code: "TS2322",
		why: "a VerifiedJwt must not be constructible from a plain object",
	},
	{
		file: "key-algorithm-mismatch.ts",
		code: "TS2322",
		why: "a key bound to ES256 must not stand in for an HS256 key",
	},
	{
		file: "profile-requires-typ.ts",
		code: "TS2345",
		why: "a profile without a typ must not typecheck",
	},
	{
		file: "raw-key-cannot-sign.ts",
		code: "TS2345",
		why: "a bare CryptoKey must not be signable - keys come through importKey",
	},
];

const tsc = spawnSync(
	process.execPath,
	[join(ROOT, "node_modules", "typescript", "bin", "tsc"), "--noEmit", "-p", PROJECT],
	{ cwd: ROOT, encoding: "utf8" }
);
const output = `${tsc.stdout ?? ""}${tsc.stderr ?? ""}`;

test("[LW-decode.1] the negative type fixtures still fail to compile", () => {
	assert.notEqual(
		tsc.status,
		0,
		"tsc SUCCEEDED on the negative fixtures - a type-level guarantee has been lost:\n" + output
	);
});

for (const { file, code, why } of FIXTURES) {
	test(`[LW-decode.1] ${file} is rejected by tsc (${code}) - ${why}`, () => {
		// tsc prints "tests/types/fixtures/<file>(line,col): error TSxxxx: ..."
		const lines = output
			.split("\n")
			.filter((l) => l.includes(`fixtures/${file}`) || l.includes(`fixtures\\${file}`));
		assert.ok(lines.length > 0, `tsc reported no error for ${file}:\n${output}`);
		assert.ok(
			lines.some((l) => l.includes(code)),
			`expected ${code} in ${file}, got:\n${lines.join("\n")}`
		);
	});
}

test("[LW-decode.1] the fixtures are the *only* thing tsc complains about", () => {
	// Guards against the fixtures "passing" because the library itself no longer
	// compiles - which would make every assertion above vacuous.
	const errorLines = output.split("\n").filter((l) => /error TS\d+/.test(l));
	const strays = errorLines.filter((l) => !l.includes("fixtures/") && !l.includes("fixtures\\"));
	assert.deepEqual(strays, [], `tsc reported errors outside the fixtures:\n${strays.join("\n")}`);
});
