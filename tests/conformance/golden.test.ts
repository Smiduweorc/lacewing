/**
 * Static golden vectors - the implementation-agnostic
 * interop proof. Every fixture under `golden/*.json` is a checked-in, literal
 * token that Lacewing did not produce: the RFC 7515/7516/7519 worked examples
 * plus tokens built offline by non-jose tooling (the OpenSSL CLI and
 * pyca/cryptography). The suite asserts Lacewing verifies/decrypts the
 * policy-compliant ones and rejects the policy-violating ones with the exact
 * typed error.
 *
 * Each vector pins the clock (`clockAt`), so fixtures with fixed `iat`/`exp`
 * never rot. Like the attack corpus, this directory is append-only.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
	defineProfile,
	defineDecryptionProfile,
	jwtVerify,
	jwtDecrypt,
	importKey,
	importEncryptionKey,
	AlgorithmNotAllowed,
	JWTInvalid,
	JWTExpired,
	JWTClaimValidationFailed,
	MissingClaim,
	type StaticJWK,
} from "../../index.js";

const ERRORS: Record<string, abstract new (...args: never[]) => Error> = {
	AlgorithmNotAllowed,
	JWTInvalid,
	JWTExpired,
	JWTClaimValidationFailed,
	MissingClaim,
};

interface GoldenVector {
	name: string;
	source: string;
	description: string;
	format: "jws" | "jwe";
	/** Epoch seconds the test pins Date.now() to while validating. */
	clockAt: number;
	token: string;
	key: StaticJWK;
	keyAlg: string;
	profile: {
		typ: string;
		issuer: string;
		audience: string;
		algorithms?: string[];
		keyManagementAlgorithms?: string[];
		contentEncryptionAlgorithms?: string[];
		maxTokenAge: string;
	};
	relatedRequirements: string[];
	expect:
		| { outcome: "accept"; claims?: Record<string, unknown> }
		| { outcome: "reject"; error: keyof typeof ERRORS; code?: string };
}

const GOLDEN_DIR = join(dirname(fileURLToPath(import.meta.url)), "golden");
const files = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith(".json")).sort();

assert.ok(files.length > 0, "the golden-vector directory must not be empty");

for (const file of files) {
	const vector = JSON.parse(readFileSync(join(GOLDEN_DIR, file), "utf8")) as GoldenVector;
	const tags = vector.relatedRequirements.map((id) => `[${id}]`).join("");
	const verdict = vector.expect.outcome === "accept" ? "accepted" : `rejected with ${vector.expect.error}`;

	test(`${tags} golden/${file}: ${vector.name} - ${verdict}`, async (t) => {
		// Golden tokens carry fixed timestamps; pin the clock so they never rot.
		t.mock.timers.enable({ apis: ["Date"], now: vector.clockAt * 1000 });

		const base = {
			typ: vector.profile.typ,
			issuer: vector.profile.issuer,
			audience: vector.profile.audience,
			maxTokenAge: vector.profile.maxTokenAge,
		};

		const outcome =
			vector.format === "jws"
				? jwtVerify(
					vector.token,
					defineProfile({
						...base,
						algorithms: vector.profile.algorithms as string[],
						keys: await importKey(vector.key, vector.keyAlg),
					})
				)
				: jwtDecrypt(
					vector.token,
					defineDecryptionProfile({
						...base,
						keyManagementAlgorithms: vector.profile.keyManagementAlgorithms as string[],
						contentEncryptionAlgorithms: vector.profile.contentEncryptionAlgorithms as string[],
						key: await importEncryptionKey(vector.key, vector.keyAlg),
					})
				);

		if (vector.expect.outcome === "accept") {
			const { payload } = await outcome;
			for (const [claim, value] of Object.entries(vector.expect.claims ?? {})) {
				assert.deepEqual(payload[claim], value, `${file}: claim "${claim}"`);
			}
			return;
		}

		const { error, code } = vector.expect;
		const ErrorClass = ERRORS[error];
		assert.ok(ErrorClass, `${file}: unknown expected error "${error}"`);
		await assert.rejects(outcome, (thrown) => {
			assert.ok(thrown instanceof ErrorClass, `${file}: expected ${error}, got ${(thrown as Error)?.constructor?.name}`);
			if (code !== undefined) {
				assert.equal((thrown as { code?: string }).code, code, `${file}: wrong error code`);
			}
			return true;
		});
	});
}
