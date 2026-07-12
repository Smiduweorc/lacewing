/**
 * Compliance gate.
 *
 * Cross-references the requirement inventory (`tests/compliance/requirements.json`)
 * against the test runner's TAP output and:
 *
 *   1. fails if any requirement id has zero *passing* tests,
 *   2. fails if a test references an id-shaped tag that is not in the
 *      inventory (a typo guard), and
 *   3. writes `compliance-report.md` - the traceability matrix with live
 *      pass/fail status - so "are we RFC 8725 compliant?" always has a
 *      current, generated answer.
 *
 * Usage:
 *   node --import tsx tools/compliance-gate.ts [tap-file]
 *   node --import tsx --test --test-reporter=tap "tests/**\/*.test.ts" | \
 *     node --import tsx tools/compliance-gate.ts
 *
 * With no argument it reads TAP from stdin; otherwise from the given file.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const REQUIREMENTS_PATH = join(HERE, "..", "tests", "compliance", "requirements.json");
const REPORT_PATH = join(HERE, "..", "compliance-report.md");

// A bracket token is a *requirement reference* only if it has this shape.
// Free-form tags like [strictness] or [@security] are ignored.
const REQ_ID = /^(?:8725-\d+(?:\.\d+)+|LW-[a-z]+\.\d+)$/;

interface Requirement {
	id: string;
	level: string;
	mechanism: string;
	summary: string;
}

interface Inventory {
	requirements: Requirement[];
}

interface TapResult {
	name: string;
	ok: boolean;
	skipped: boolean;
}

function parseTap(tap: string): TapResult[] {
	const results: TapResult[] = [];
	const line = /^\s*(not ok|ok)\s+\d+\s+-?\s*(.*)$/;
	for (const raw of tap.split("\n")) {
		const m = line.exec(raw);
		if (m === null) continue;
		let name = (m[2] ?? "").trim();
		// A trailing "# SKIP"/"# TODO" directive means the test did not run.
		const directive = /\s+#\s*(SKIP|TODO)\b/i.exec(name);
		const skipped = directive !== null;
		if (directive !== null) name = name.slice(0, directive.index).trim();
		results.push({ name, ok: m[1] === "ok", skipped });
	}
	return results;
}

function tagsIn(name: string): string[] {
	const tags: string[] = [];
	const bracket = /\[([^\]]+)\]/g;
	let m: RegExpExecArray | null;
	while ((m = bracket.exec(name)) !== null) {
		const token = m[1] as string;
		if (REQ_ID.test(token)) tags.push(token);
	}
	return tags;
}

function main(): void {
	const inventory = JSON.parse(readFileSync(REQUIREMENTS_PATH, "utf8")) as Inventory;
	const known = new Map(inventory.requirements.map((r) => [r.id, r]));

	const tapArg = process.argv[2];
	const tap =
		tapArg !== undefined ? readFileSync(tapArg, "utf8") : readFileSync(0, "utf8");
	const results = parseTap(tap);

	if (results.length === 0) {
		console.error(
			"compliance-gate: no TAP test lines found. Run the suite with " +
				"`--test-reporter=tap` and pipe it in (or pass a TAP file path)."
		);
		process.exit(2);
	}

	// id -> counts of passing / failing proofs.
	const passing = new Map<string, number>();
	const failing = new Map<string, number>();
	const unknownTags = new Map<string, number>(); // referenced but not in inventory

	for (const result of results) {
		for (const tag of tagsIn(result.name)) {
			if (!known.has(tag)) {
				unknownTags.set(tag, (unknownTags.get(tag) ?? 0) + 1);
				continue;
			}
			if (result.ok && !result.skipped) {
				passing.set(tag, (passing.get(tag) ?? 0) + 1);
			} else {
				failing.set(tag, (failing.get(tag) ?? 0) + 1);
			}
		}
	}

	const uncovered = inventory.requirements.filter((r) => (passing.get(r.id) ?? 0) === 0);

	writeReport(inventory, passing, failing, uncovered, unknownTags);

	let failed = false;
	if (uncovered.length > 0) {
		failed = true;
		console.error(`compliance-gate: ${uncovered.length} requirement(s) have no passing proof:`);
		for (const r of uncovered) {
			const f = failing.get(r.id) ?? 0;
			console.error(`  - ${r.id}${f > 0 ? ` (${f} failing test(s))` : " (no test)"}: ${r.summary}`);
		}
	}
	if (unknownTags.size > 0) {
		failed = true;
		console.error("compliance-gate: tests reference id-shaped tags not in the inventory (typo?):");
		for (const [tag, n] of unknownTags) {
			console.error(`  - ${tag} (${n} test(s))`);
		}
	}

	const total = inventory.requirements.length;
	const covered = total - uncovered.length;
	if (failed) {
		console.error(`compliance-gate: FAIL - ${covered}/${total} requirements proven.`);
		console.error(`compliance-gate: report written to ${REPORT_PATH}`);
		process.exit(1);
	}
	console.log(`compliance-gate: PASS - all ${total} requirements have at least one passing test.`);
	console.log(`compliance-gate: report written to ${REPORT_PATH}`);
}

function writeReport(
	inventory: Inventory,
	passing: Map<string, number>,
	failing: Map<string, number>,
	uncovered: Requirement[],
	unknownTags: Map<string, number>
): void {
	const total = inventory.requirements.length;
	const covered = total - uncovered.length;
	const now = new Date().toISOString();

	const lines: string[] = [];
	lines.push("# Compliance report");
	lines.push("");
	lines.push(`_Generated ${now} by \`tools/compliance-gate.ts\`. Do not edit by hand._`);
	lines.push("");
	lines.push(
		uncovered.length === 0 && unknownTags.size === 0
			? `**Status: PASS** - ${covered}/${total} requirements have a passing proof.`
			: `**Status: FAIL** - ${covered}/${total} requirements have a passing proof.`
	);
	lines.push("");
	lines.push("| ID | Level | Mechanism | Proofs | Status | Requirement |");
	lines.push("|---|---|---|---|---|---|");
	for (const r of inventory.requirements) {
		const pass = passing.get(r.id) ?? 0;
		const fail = failing.get(r.id) ?? 0;
		const proofs = fail > 0 ? `${pass} pass / ${fail} fail` : `${pass}`;
		const status = pass > 0 ? "pass" : "FAIL";
		lines.push(
			`| ${r.id} | ${r.level} | ${r.mechanism} | ${proofs} | ${status} | ${r.summary} |`
		);
	}
	lines.push("");
	if (unknownTags.size > 0) {
		lines.push("## Unknown requirement tags");
		lines.push("");
		lines.push("These id-shaped tags appear in test names but are not in the inventory:");
		lines.push("");
		for (const [tag, n] of unknownTags) lines.push(`- \`${tag}\` (${n} test(s))`);
		lines.push("");
	}
	writeFileSync(REPORT_PATH, lines.join("\n") + "\n");
}

main();
