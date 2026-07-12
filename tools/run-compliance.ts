/**
 * Portable driver for the compliance gate: runs the test suite with the TAP
 * reporter, captures its output, then hands it to `compliance-gate.ts`. Kept
 * in Node (not a shell one-liner) so it behaves identically on the Windows CI
 * matrix leg. The suite's own pass/fail is preserved: if a test fails, the TAP
 * shows it and the gate reports the requirement as unproven.
 */

import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const TAP_PATH = join(ROOT, "compliance-tap.txt");
const GATE = join(HERE, "compliance-gate.ts");

const test = spawnSync(
	process.execPath,
	["--import", "tsx", "--test", "--test-reporter=tap", "tests/**/*.test.ts"],
	{ cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }
);

const tap = (test.stdout ?? "") + (test.stderr ?? "");
writeFileSync(TAP_PATH, tap);

const gate = spawnSync(process.execPath, ["--import", "tsx", GATE, TAP_PATH], {
	cwd: ROOT,
	encoding: "utf8",
	stdio: "inherit",
});

process.exit(gate.status ?? 1);
