/**
 * Attack-vector corpus - the append-only version.
 *
 * Every crafted malicious token lives as data under `vectors/*.json` with its
 * metadata (name, what it attacks, a CVE/writeup link, the requirement IDs it
 * relates to, and the exact typed error it must provoke). This loader is the
 * only code: it assembles each vector and asserts the public `jwtVerify` -
 * `parseBearer` for the header vectors, `jwtDecrypt` for the JWE vectors -
 * rejects it with the right error and machine-readable code.
 *
 * Adding a vector is adding a JSON file. Future CVE classes in any JWT library
 * become a new fixture here first (red), then a fix (green).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
	defineProfile,
	jwtVerify,
	parseBearer,
	importKey,
	generateKeyPair,
	defineDecryptionProfile,
	jwtDecrypt,
	importEncryptionKey,
	EncryptJWT,
	AlgorithmNotAllowed,
	JWTInvalid,
	JWTExpired,
	JWTClaimValidationFailed,
	MissingClaim,
	EntropyCheckFailed,
	JWTRevoked,
	KeyTypeMismatch,
	BearerParseFailed,
	PayloadHygieneViolation,
	type ExpectedJwtProfile,
} from "../../index.js";
import {
	b64uJson,
	craftHmacToken,
	craftHmacTokenRaw,
	craftUnsignedToken,
	nowSeconds,
	standardClaims,
} from "../helpers.js";

const ERRORS: Record<string, abstract new (...args: never[]) => Error> = {
	AlgorithmNotAllowed,
	JWTInvalid,
	JWTExpired,
	JWTClaimValidationFailed,
	MissingClaim,
	EntropyCheckFailed,
	JWTRevoked,
	KeyTypeMismatch,
	BearerParseFailed,
	PayloadHygieneViolation,
};

// A fixed, corpus-owned HS256 secret so HMAC vectors are reproducible from the
// JSON alone. 32 bytes, deliberately containing non-printable values so the
// password heuristic never trips on it.
const HMAC_SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff);
const OTHER_SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i * 53 + 7) & 0xff);

// The JWE corpus key: a fixed 32-byte `dir` key, reproducible like the HMAC
// secrets above. The decrypt profile allowlists exactly dir + A256GCM, so any
// other alg/enc in a vector's header exercises the allowlist rejection.
const DIR_SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i * 29 + 3) & 0xff);

const hmacKey = await importKey(HMAC_SECRET, "HS256");
const eddsa = await generateKeyPair("EdDSA", { extractable: true });
const es256 = await generateKeyPair("ES256", { extractable: true });
const dirKey = await importEncryptionKey(DIR_SECRET, "dir");

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

function profileFor(kind: string): ExpectedJwtProfile {
	const base = { issuer: ISSUER, audience: AUDIENCE, maxTokenAge: "15m" as const };
	switch (kind) {
	case "hmac":
		return defineProfile({ ...base, typ: "at+jwt", algorithms: ["HS256"], keys: hmacKey });
	case "eddsa":
		return defineProfile({ ...base, typ: "at+jwt", algorithms: ["EdDSA"], keys: eddsa.publicKey });
	case "es256":
		return defineProfile({ ...base, typ: "at+jwt", algorithms: ["ES256"], keys: es256.publicKey });
	default:
		throw new Error(`unknown profile kind: ${kind}`);
	}
}

const decryptionProfile = defineDecryptionProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	keyManagementAlgorithms: ["dir"],
	contentEncryptionAlgorithms: ["A256GCM"],
	key: dirKey,
	maxTokenAge: "15m",
});

interface Vector {
	name: string;
	description: string;
	attacks: string;
	reference?: string;
	relatedRequirements: string[];
	expectedError: keyof typeof ERRORS;
	expectedCode?: string;
	target?: "verify" | "bearer" | "decrypt";
	profile?: "hmac" | "eddsa" | "es256";
	recipe: Recipe;
}

type Recipe =
	| { kind: "literal"; token: string }
	| { kind: "bearer"; header: string }
	| { kind: "unsigned"; header: Record<string, unknown>; claims?: Record<string, unknown>; nowClaims?: Record<string, number>; signature?: string }
	| { kind: "hmac"; header: Record<string, unknown>; claims?: Record<string, unknown>; nowClaims?: Record<string, number>; secret?: "hmac" | "other"; alg?: string }
	| { kind: "hmacRaw"; headerJson: string; payloadJson: string; secret?: "hmac" | "other"; alg?: string }
	// A five-segment token with an attacker-chosen header; validation must
	// reject it before ever touching the (dummy) crypto segments.
	| { kind: "jweCrafted"; header: Record<string, unknown>; segments?: [string, string, string, string] }
	// A real encryption under the corpus dir key, optionally tampered with
	// after the fact.
	| { kind: "jweEncrypted"; enc?: string; claims?: Record<string, unknown>; tamper?: "ciphertext" | "tag" };

function buildPayload(claims?: Record<string, unknown>, nowClaims?: Record<string, number>): Record<string, unknown> {
	const payload = standardClaims(claims ?? {});
	if (nowClaims !== undefined) {
		const now = nowSeconds();
		for (const [claim, offset] of Object.entries(nowClaims)) {
			payload[claim] = now + offset;
		}
	}
	return payload;
}

function secretOf(ref?: "hmac" | "other"): Uint8Array {
	return ref === "other" ? OTHER_SECRET : HMAC_SECRET;
}

function flipByteInSegment(token: string, index: number): string {
	const parts = token.split(".");
	const bytes = Buffer.from(parts[index] as string, "base64url");
	bytes[0] = (bytes[0] as number) ^ 0xff;
	parts[index] = bytes.toString("base64url");
	return parts.join(".");
}

async function assembleToken(recipe: Recipe): Promise<string> {
	switch (recipe.kind) {
	case "literal":
		return recipe.token;
	case "bearer":
		return recipe.header;
	case "unsigned":
		return craftUnsignedToken(recipe.header, buildPayload(recipe.claims, recipe.nowClaims), recipe.signature ?? "");
	case "hmac":
		return craftHmacToken(recipe.header, buildPayload(recipe.claims, recipe.nowClaims), secretOf(recipe.secret), recipe.alg ?? "HS256");
	case "hmacRaw":
		return craftHmacTokenRaw(recipe.headerJson, recipe.payloadJson, secretOf(recipe.secret), recipe.alg ?? "HS256");
	case "jweCrafted":
		return [b64uJson(recipe.header), ...(recipe.segments ?? ["", "aXY", "Y3Q", "dGFn"])].join(".");
	case "jweEncrypted": {
		const builder = new EncryptJWT("at+jwt", { contentEncryption: recipe.enc ?? "A256GCM" })
			.issuer(ISSUER)
			.audience(AUDIENCE)
			.subject("user-42")
			.expiresIn("5m");
		for (const [name, value] of Object.entries(recipe.claims ?? {})) builder.claim(name, value);
		const token = await builder.encrypt(dirKey);
		if (recipe.tamper === "ciphertext") return flipByteInSegment(token, 3);
		if (recipe.tamper === "tag") return flipByteInSegment(token, 4);
		return token;
	}
	}
}

const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), "vectors");
const files = readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json")).sort();

assert.ok(files.length > 0, "the attack corpus must not be empty");

for (const file of files) {
	const vector = JSON.parse(readFileSync(join(VECTORS_DIR, file), "utf8")) as Vector;
	const tags = vector.relatedRequirements.map((id) => `[${id}]`).join("");

	test(`${tags} corpus/${file}: ${vector.name} - rejected with ${vector.expectedError}`, async () => {
		const ErrorClass = ERRORS[vector.expectedError];
		assert.ok(ErrorClass, `${file}: unknown expectedError "${vector.expectedError}"`);

		// The JSON cast is unchecked at runtime: a typo'd target must fail
		// loudly, not fall through to the verify path.
		const target: string = vector.target ?? "verify";
		assert.ok(["verify", "bearer", "decrypt"].includes(target), `${file}: unknown target "${target}"`);

		const token = await assembleToken(vector.recipe);

		const check = (error: unknown): true => {
			assert.ok(error instanceof ErrorClass, `${file}: expected ${vector.expectedError}, got ${(error as Error)?.constructor?.name}`);
			if (vector.expectedCode !== undefined) {
				assert.equal((error as { code?: string }).code, vector.expectedCode, `${file}: wrong error code`);
			}
			// Hygiene: a rejection message must never echo raw token content.
			for (const segment of token.split(".")) {
				if (segment.length >= 12) {
					assert.ok(!(error as Error).message.includes(segment), `${file}: error message leaked a token segment`);
				}
			}
			return true;
		};

		if (target === "bearer") {
			assert.throws(() => parseBearer(token), check);
			return;
		}
		if (target === "decrypt") {
			await assert.rejects(jwtDecrypt(token, decryptionProfile), check);
			return;
		}
		await assert.rejects(jwtVerify(token, profileFor(vector.profile ?? "hmac")), check);
	});
}
