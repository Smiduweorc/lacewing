/**
 * Property: round-trip. For every algorithm and every
 * (safe) set of custom claims, sign->verify returns the same claim values.
 * This is the "it actually works" counterweight to a suite that is mostly
 * about saying no.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import {
	SignJWT,
	jwtVerify,
	defineProfile,
	generateKeyPair,
	generateSecret,
	type LacewingKey,
	type ExpectedJwtProfile,
} from "../../index.js";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

const eddsa = await generateKeyPair("EdDSA");
const es256 = await generateKeyPair("ES256");
const hmac = generateSecret("HS256");

function profileFor(alg: string, key: LacewingKey): ExpectedJwtProfile {
	return defineProfile({
		typ: "at+jwt",
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: [alg],
		keys: key,
		maxTokenAge: "15m",
	});
}

const cases: Array<{ alg: string; sign: LacewingKey; verify: LacewingKey }> = [
	{ alg: "EdDSA", sign: eddsa.privateKey, verify: eddsa.publicKey },
	{ alg: "ES256", sign: es256.privateKey, verify: es256.publicKey },
	{ alg: "HS256", sign: hmac, verify: hmac },
];

// Numeric-suffixed names can never spell a sensitive-name fragment, and short
// values can never look like a card/PEM/JWT - so the hygiene scanner never
// interferes with a legitimate round-trip.
const safeKey = fc.integer({ min: 0, max: 100_000 }).map((n) => `u_${n}`);
const safeValue = fc.oneof(
	fc.array(fc.constantFrom(..."abcdefghijklm".split("")), { maxLength: 12 }).map((a) => a.join("")),
	fc.integer({ min: -1_000_000, max: 1_000_000 }),
	fc.boolean()
);
const customClaims = fc.dictionary(safeKey, safeValue, { maxKeys: 6 });

for (const { alg, sign, verify } of cases) {
	test(`round-trip preserves custom claims under ${alg}`, async () => {
		const profile = profileFor(alg, verify);
		await fc.assert(
			fc.asyncProperty(customClaims, async (extra) => {
				let builder = new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).subject("user-42").expiresIn("5m");
				for (const [name, value] of Object.entries(extra)) builder = builder.claim(name, value);
				const token = await builder.sign(sign);
				const { payload, header } = await jwtVerify(token, profile);
				assert.equal(header.alg, alg);
				assert.equal(payload.iss, ISSUER);
				for (const [name, value] of Object.entries(extra)) {
					assert.deepEqual(payload[name], value, `claim ${name} survived`);
				}
			}),
			{ numRuns: 30 }
		);
	});
}
