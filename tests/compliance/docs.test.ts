/**
 * Docs-mechanism requirements: some obligations can only be
 * discharged by *telling the user something* - there is no runtime check that
 * can stop a developer putting a token in `localStorage` in their own app.
 *
 * "The docs say so" is still a claim, and claims get proofs. These tests read
 * the shipped README and guides and assert the required warnings are actually present, so
 * a future edit that quietly deletes them fails the compliance gate.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const README = readFileSync(join(ROOT, "README.md"), "utf8");
// The documentation that ships: the README and every guide it links. A
// warning moved from one to another still counts; a warning deleted does not.
const GUIDES = readdirSync(join(ROOT, "guides")).filter((name) => name.endsWith(".md")).sort();
const readme = [README, ...GUIDES.map((name) => readFileSync(join(ROOT, "guides", name), "utf8"))]
	.join("\n")
	.toLowerCase();

test("the README links every guide, so none of them is unreachable", () => {
	assert.ok(GUIDES.length > 0, "guides/ must not be empty");
	for (const name of GUIDES) {
		assert.ok(README.includes(`](./guides/${name})`), `README must link guides/${name}`);
	}
});

test("[LW-payload.3] the docs state that JWS payloads are readable plaintext", () => {
	// The claim must be made in terms a reader cannot miss: the payload is
	// encoded, not encrypted, and secrets must not go in it.
	assert.ok(
		readme.includes("plaintext"),
		"the docs must state that a JWS payload is plaintext"
	);
	assert.match(
		readme,
		/base64url-encoded \*\*plaintext\*\*|base64url-encoded plaintext/,
		"the docs must explain that the payload is base64url-encoded plaintext"
	);
	assert.ok(
		readme.includes("don't put secrets in a signed payload"),
		"the docs must tell the reader not to put secrets in the payload"
	);
});

test("[LW-http.3] the docs warn against localStorage/sessionStorage and show the alternatives", () => {
	assert.ok(readme.includes("localstorage"), "the docs must name localStorage");
	assert.ok(readme.includes("sessionstorage"), "the docs must name sessionStorage");
	// The warning has to say *why*, and point somewhere better.
	assert.ok(readme.includes("xss"), "the docs must explain the XSS risk");
	assert.ok(readme.includes("httponly"), "the docs must offer the HttpOnly cookie alternative");
	assert.ok(
		readme.includes("in-memory") || readme.includes("memory bearer") || readme.includes("bearer token"),
		"the docs must offer the in-memory bearer alternative for services"
	);
});

test("the docs draw the line between revocation and replay protection", () => {
	// Design limitation made explicit: a valid, non-revoked token is replayable
	// until exp. The docs must say so and offer the mitigations.
	assert.ok(
		readme.includes("revocation is not replay protection"),
		"the docs must state that revocation is not replay protection"
	);
	assert.ok(
		readme.includes("replayed") && readme.includes("until `exp`"),
		"the docs must state the replay window is bounded only by exp"
	);
	assert.ok(readme.includes("jti-seen") || readme.includes("jti cache"), "the docs must show the jti-seen cache option");
});

test("the docs caveat A192* portability outside Node", () => {
	assert.ok(
		readme.includes("192-bit aes"),
		"the docs must name the 192-bit AES portability caveat"
	);
	assert.ok(
		readme.includes("webcrypto"),
		"the docs must explain it is a WebCrypto implementation gap"
	);
});

test("[LW-alg.1] the docs lead with asymmetric keys and caveat HMAC's shared-secret problem", () => {
	// The default in the examples is the asymmetric one.
	assert.ok(
		readme.includes("eddsa by default") || /generatekeypair\(\).*eddsa/s.test(readme),
		"README's key-generation example must default to EdDSA"
	);
	// And the HMAC section must lead with the distribution caveat: anyone who
	// can verify an HMAC token can also mint one.
	assert.ok(readme.includes("hmac"), "the docs must discuss HMAC");
	assert.ok(
		readme.includes("mint"),
		"the docs must warn that every HMAC verifier can also mint tokens"
	);
	assert.ok(
		readme.includes("asymmetric keys + jwks") || readme.includes("use asymmetric"),
		"the docs must point beyond-single-service users at asymmetric keys + JWKS"
	);
});

test("the README points readers at the published security advisories", () => {
	assert.ok(README.includes("](./ADVISORIES.md)"), "README must link ADVISORIES.md");
	const advisories = readFileSync(
		join(dirname(fileURLToPath(import.meta.url)), "..", "..", "ADVISORIES.md"),
		"utf8"
	);
	for (const id of ["GHSA-x2q2-4jwp-wfgg", "GHSA-vwp5-4h2j-vhhq", "GHSA-gg54-pwrg-hjx7"]) {
		assert.ok(advisories.includes(`## ${id}:`), `ADVISORIES.md must document ${id}`);
	}
});

test("TypeDoc includes every markdown document in the repo", () => {
	const config = JSON.parse(readFileSync(join(ROOT, "typedoc.json"), "utf8")) as {
		readme: string;
		projectDocuments: string[];
	};
	const covered = (path: string): boolean =>
		config.projectDocuments.some((entry) =>
			entry.endsWith("/*.md") ? path.startsWith(entry.slice(0, -"*.md".length)) && !path.slice(entry.length - 4).includes("/") : entry === path
		);
	const documents = [
		...readdirSync(ROOT).filter((name) => name.endsWith(".md")),
		...GUIDES.map((name) => `guides/${name}`),
	];
	// Written by `npm run compliance` and gitignored: a fresh checkout has no
	// copy, so listing it would break `npm run docs`.
	const generated = new Set(["compliance-report.md"]);
	for (const path of documents) {
		if (path === config.readme || generated.has(path)) continue;
		assert.ok(covered(path), `typedoc.json projectDocuments must include ${path}`);
	}
});
