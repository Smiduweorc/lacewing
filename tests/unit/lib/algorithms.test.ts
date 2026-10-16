import { test } from "node:test";
import assert from "node:assert/strict";
import { JWTError } from "../../../src/util/errors.js";
import { refusal } from "../../helpers.js";
import {
	findAlgorithm,
	getAlgorithmProperties,
	isKnownAlgorithmName,
	LEGACY_RS256,
	LEGACY_RS384,
	LEGACY_RS512,
	resolveAlgorithm,
	type AlgorithmInfo,
} from "../../../src/lib/algorithms.js";
import { SetAlg } from "../../../src/types.js";

const DEFAULTS: Array<[string, Omit<AlgorithmInfo, "name">]> = [
	["EdDSA", { kty: "OKP", crv: "Ed25519", minKeyBits: 256 }],
	["Ed25519", { kty: "OKP", crv: "Ed25519", minKeyBits: 256 }],
	["ES256", { kty: "EC", crv: "P-256", minKeyBits: 256 }],
	["ES384", { kty: "EC", crv: "P-384", minKeyBits: 384 }],
	["ES512", { kty: "EC", crv: "P-521", minKeyBits: 521 }],
	["PS256", { kty: "RSA", minKeyBits: 2048 }],
	["PS384", { kty: "RSA", minKeyBits: 2048 }],
	["PS512", { kty: "RSA", minKeyBits: 2048 }],
	["HS256", { kty: "oct", minKeyBits: 256 }],
	["HS384", { kty: "oct", minKeyBits: 384 }],
	["HS512", { kty: "oct", minKeyBits: 512 }],
];

test("[8725-3.2.1] every name in the default set resolves to its hand-checked properties", () => {
	for (const [name, properties] of DEFAULTS) {
		assert.deepEqual({ ...resolveAlgorithm(name) }, { name, ...properties }, name);
		assert.equal(getAlgorithmProperties(name), resolveAlgorithm(name), name);
	}
});

test("[8725-3.2.2] 'none' resolves nowhere, in any casing, and cannot be branded", () => {
	for (const alg of ["none", "None", "NONE", "nOnE"]) {
		assert.throws(() => resolveAlgorithm(alg), refusal("ALGORITHM_NOT_ALLOWED"));
		assert.throws(() => getAlgorithmProperties(alg), refusal("ALGORITHM_NOT_ALLOWED"));
		assert.throws(() => getAlgorithmProperties(alg, [LEGACY_RS256, LEGACY_RS384, LEGACY_RS512]), refusal("ALGORITHM_NOT_ALLOWED"));
		assert.throws(() => SetAlg(alg), refusal("ALGORITHM_NOT_ALLOWED"));
		assert.equal(isKnownAlgorithmName(alg), false);
	}
});

test("[8725-3.2.3] RS* and RSA1_5 are outside the default set as strings", () => {
	for (const alg of ["RS256", "RS384", "RS512", "RSA1_5"]) {
		assert.throws(() => resolveAlgorithm(alg), refusal("ALGORITHM_NOT_ALLOWED"));
		assert.throws(() => getAlgorithmProperties(alg), refusal("ALGORITHM_NOT_ALLOWED"));
	}
});

test("a legacy descriptor resolves only when the caller passes it", () => {
	assert.equal(resolveAlgorithm(LEGACY_RS256), LEGACY_RS256);
	assert.equal(getAlgorithmProperties("RS256", [LEGACY_RS256]), LEGACY_RS256);
	assert.deepEqual({ ...LEGACY_RS256 }, { name: "RS256", kty: "RSA", minKeyBits: 2048 });
	// Passing RS384 says nothing about RS256.
	assert.throws(() => getAlgorithmProperties("RS256", [LEGACY_RS384]), refusal("ALGORITHM_NOT_ALLOWED"));
	assert.equal(getAlgorithmProperties("RS512", [LEGACY_RS384, LEGACY_RS512]).name, "RS512");
});

test("a hand-built descriptor is refused, even one that copies a real one", () => {
	const forgeries: AlgorithmInfo[] = [
		{ name: "RS256", kty: "RSA", minKeyBits: 512 },
		{ ...LEGACY_RS256 },
		{ name: "none", kty: "oct", minKeyBits: 0 },
		{ name: "EdDSA", kty: "OKP", crv: "Ed25519", minKeyBits: 256 },
	];
	for (const forged of forgeries) {
		assert.throws(() => resolveAlgorithm(forged), refusal("ALGORITHM_NOT_ALLOWED"), forged.name);
		assert.throws(() => getAlgorithmProperties(forged.name, [forged]), refusal("ALGORITHM_NOT_ALLOWED"), forged.name);
		assert.throws(() => findAlgorithm(forged.name, [forged]), refusal("ALGORITHM_NOT_ALLOWED"), forged.name);
	}
});

test("findAlgorithm looks only inside the allowlist it is given", () => {
	const allowed = [resolveAlgorithm("ES256"), LEGACY_RS256];
	assert.equal(findAlgorithm("ES256", allowed).crv, "P-256");
	assert.equal(findAlgorithm("RS256", allowed), LEGACY_RS256);
	assert.throws(() => findAlgorithm("EdDSA", allowed), refusal("ALGORITHM_NOT_ALLOWED"));
	assert.throws(() => findAlgorithm("ES256", []), refusal("ALGORITHM_NOT_ALLOWED"));
});

test("isKnownAlgorithmName covers the default and legacy names and nothing else", () => {
	for (const [name] of DEFAULTS) assert.equal(isKnownAlgorithmName(name), true, name);
	for (const name of ["RS256", "RS384", "RS512"]) assert.equal(isKnownAlgorithmName(name), true, name);
	for (const name of ["RSA1_5", "HS1", "", "es256", "ed25519"]) assert.equal(isKnownAlgorithmName(name), false, name);
});

test("algorithm lookup is case sensitive", () => {
	for (const alg of ["hs256", "eddsa", "ed25519", "ps256"]) {
		assert.throws(() => resolveAlgorithm(alg), refusal("ALGORITHM_NOT_ALLOWED"), alg);
	}
});

test("rejection messages never echo the attacker-supplied algorithm", () => {
	for (const lookup of [() => getAlgorithmProperties("EVIL<script>"), () => findAlgorithm("EVIL<script>", [])]) {
		try {
			lookup();
			assert.fail("should have thrown");
		} catch (error) {
			assert.ok(error instanceof JWTError && error.code === "ALGORITHM_NOT_ALLOWED");
			assert.ok(!error.message.includes("EVIL"));
		}
	}
});

test("Ed25519 (RFC 9864) pairs with exactly the key EdDSA pairs with", () => {
	const eddsa = resolveAlgorithm("EdDSA");
	const ed25519 = resolveAlgorithm("Ed25519");
	assert.deepEqual({ ...ed25519, name: "EdDSA" }, { ...eddsa });
});

test("[LW-ext.1] descriptors, default and legacy, cannot be modified through a lookup", () => {
	for (const info of [...DEFAULTS.map(([name]) => resolveAlgorithm(name)), LEGACY_RS256, LEGACY_RS384, LEGACY_RS512]) {
		const bits = info.minKeyBits;
		assert.equal(Object.isFrozen(info), true, info.name);
		assert.throws(() => {
			(info as { minKeyBits: number }).minKeyBits = 0;
		}, TypeError);
		assert.equal(info.minKeyBits, bits);
	}
});
