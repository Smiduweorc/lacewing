/**
 * Property: hygiene-scanner soundness (LW-payload).
 *
 * The claim is that the scanner has no order- or nesting-dependent blind spots
 * for the names it says it catches. So: a sensitive claim name buried at any
 * depth, in any position, is still caught; and a payload built only from safe
 * names is always accepted. This exercises the scanner directly - it is the
 * unit under test, not the public API.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { scanPayloadForSensitiveData } from "../../src/lib/payload_hygiene.js";
import { PayloadHygieneViolation } from "../../index.js";

const SENSITIVE = ["password", "secret", "apikey", "ssn", "creditcard", "cvv", "authorization"];

// Numeric-suffixed names are structurally incapable of containing a sensitive
// fragment, so a tree built from them must always pass.
const safeName = fc.integer({ min: 0, max: 100_000 }).map((n) => `f_${n}`);
const safeScalar = fc.oneof(
	fc.array(fc.constantFrom(..."abcdefghij".split("")), { maxLength: 10 }).map((a) => a.join("")),
	fc.integer(),
	fc.boolean()
);

const safeTree = fc.letrec((tie) => ({
	node: fc.oneof({ maxDepth: 4 }, safeScalar, fc.array(tie("node"), { maxLength: 3 }), fc.dictionary(safeName, tie("node"), { maxKeys: 4 })),
})).node;

test("[LW-payload.1] a payload built only from safe names is always accepted", () => {
	fc.assert(
		fc.property(fc.dictionary(safeName, safeTree, { minKeys: 1, maxKeys: 5 }), (payload) => {
			assert.doesNotThrow(() => scanPayloadForSensitiveData(payload));
		}),
		{ numRuns: 60 }
	);
});

test("[LW-payload.1] a sensitive name at any depth is caught - no nesting blind spot", () => {
	fc.assert(
		fc.property(fc.constantFrom(...SENSITIVE), fc.nat({ max: 4 }), safeTree, (word, depth, filler) => {
			// Wrap { <sensitive>: filler } inside `depth` layers of safe objects.
			let value: unknown = { [word]: filler };
			for (let i = 0; i < depth; i++) value = { [`wrap_${i}`]: value, sibling: filler };
			assert.throws(() => scanPayloadForSensitiveData({ data: value }), PayloadHygieneViolation);
		}),
		{ numRuns: 60 }
	);
});
