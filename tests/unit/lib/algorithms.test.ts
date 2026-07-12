import { test } from "node:test";
import assert from "node:assert/strict";
import {
	getAlgorithmProperties,
	isValidAlgorithm,
	listAlgorithms,
	toValidAlg,
} from "../../../src/lib/algorithms.js";
import { AlgorithmNotAllowed } from "../../../src/util/errors.js";
import { SetAlg } from "../../../src/types.js";

const EXPECTED = [
	"EdDSA",
	"ES256",
	"ES384",
	"ES512",
	"PS256",
	"PS384",
	"PS512",
	"HS256",
	"HS384",
	"HS512",
];

test("[8725-3.2.1] the registry contains exactly the modern allowlist", () => {
	assert.deepEqual(listAlgorithms().sort(), [...EXPECTED].sort());
	for (const alg of EXPECTED) {
		assert.equal(isValidAlgorithm(alg), true);
		assert.equal(getAlgorithmProperties(alg).name, alg);
	}
});

test("[8725-3.2.2] 'none' is not representable in the registry", () => {
	for (const alg of ["none", "None", "NONE", "nOnE"]) {
		assert.equal(isValidAlgorithm(alg), false);
		assert.throws(() => getAlgorithmProperties(alg), AlgorithmNotAllowed);
		assert.throws(() => SetAlg(alg));
	}
});

test("[8725-3.2.3] RS256 and RSA1_5 are absent by default", () => {
	for (const alg of ["RS256", "RS384", "RS512", "RSA1_5"]) {
		assert.equal(isValidAlgorithm(alg), false);
		assert.throws(() => getAlgorithmProperties(alg), AlgorithmNotAllowed);
	}
});

test("algorithm lookup is case sensitive", () => {
	assert.equal(isValidAlgorithm("hs256"), false);
	assert.equal(isValidAlgorithm("eddsa"), false);
});

test("rejection messages never echo the attacker-supplied algorithm", () => {
	try {
		getAlgorithmProperties("EVIL<script>");
		assert.fail("should have thrown");
	} catch (error) {
		assert.ok(error instanceof AlgorithmNotAllowed);
		assert.ok(!error.message.includes("EVIL"));
	}
});

test("toValidAlg brands registry members and rejects the rest", () => {
	assert.equal(toValidAlg("EdDSA"), "EdDSA");
	assert.throws(() => toValidAlg("RS256"), AlgorithmNotAllowed);
	assert.throws(() => toValidAlg("none"), AlgorithmNotAllowed);
});

test("algorithm properties bind key types correctly", () => {
	assert.equal(getAlgorithmProperties("EdDSA").kty, "OKP");
	assert.equal(getAlgorithmProperties("ES256").crv, "P-256");
	assert.equal(getAlgorithmProperties("PS256").kty, "RSA");
	assert.equal(getAlgorithmProperties("HS384").minKeyBits, 384);
});
