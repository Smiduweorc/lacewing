import { test } from "node:test";
import assert from "node:assert/strict";
import * as root from "../../../index.js";
import { JWTError, type JWTErrorCode } from "../../../src/util/errors.js";

// Every code the union holds. `satisfies` keeps this list and the type in
// step: a code added to the union and not here fails to compile below.
const CODES = [
	"JWT_INVALID",
	"JWT_EXPIRED",
	"JWT_CLAIM_VALIDATION_FAILED",
	"MISSING_CLAIM",
	"ALGORITHM_NOT_ALLOWED",
	"KEY_IMPORT_FAILED",
	"KEY_TYPE_MISMATCH",
	"KEY_EXPORT_FAILED",
	"ENTROPY_CHECK_FAILED",
	"JWKS_FETCH_FAILED",
	"JWKS_NO_MATCHING_KEY",
	"JWT_REVOKED",
	"REVOCATION_CHECK_FAILED",
	"PAYLOAD_HYGIENE_VIOLATION",
	"MAX_LIFETIME_EXCEEDED",
	"BEARER_PARSE_FAILED",
] as const satisfies readonly JWTErrorCode[];
const everyCodeListed: Exclude<JWTErrorCode, (typeof CODES)[number]> extends never ? true : never = true;

const CLAIM_CODES = new Set(["JWT_CLAIM_VALIDATION_FAILED", "MISSING_CLAIM", "PAYLOAD_HYGIENE_VIOLATION"]);

function build(code: JWTErrorCode, message: string): JWTError {
	return CLAIM_CODES.has(code)
		? new JWTError(code as "MISSING_CLAIM", message, { claim: "sub" })
		: new JWTError(code as "JWT_INVALID", message);
}

test("every code builds one JWTError class, named JWTError, that is an Error", () => {
	assert.equal(everyCodeListed, true);
	for (const code of CODES) {
		const error = build(code, "message");
		assert.equal(error.code, code);
		assert.equal(error.name, "JWTError");
		assert.ok(error instanceof JWTError);
		assert.ok(error instanceof Error);
		assert.equal(Object.getPrototypeOf(error), JWTError.prototype, code);
	}
});

test("messages carry the lacewing prefix exactly once", () => {
	assert.equal(new JWTError("JWT_INVALID", "Token has an empty segment").message, "lacewing: Token has an empty segment");
	assert.equal(String(new JWTError("JWT_REVOKED", "Token has been revoked")), "JWTError: lacewing: Token has been revoked");
});

test("claim codes name the claim; the others carry no claim property", () => {
	const missing = new JWTError("MISSING_CLAIM", "Required claim \"exp\" is missing", { claim: "exp" });
	assert.equal(missing.claim, "exp");
	const hygiene = new JWTError("PAYLOAD_HYGIENE_VIOLATION", "no", { claim: "password" });
	assert.equal(hygiene.claim, "password");
	const invalid = new JWTError("JWT_INVALID", "bad");
	assert.equal(invalid.claim, undefined);
	assert.equal("claim" in invalid, false);
});

test("a cause is kept for operators, and absent when none was given", () => {
	const cause = new Error("underlying");
	assert.equal(new JWTError("JWKS_FETCH_FAILED", "fetch failed", { cause }).cause, cause);
	const claimed = new JWTError("JWT_CLAIM_VALIDATION_FAILED", "custom", { claim: "scope", cause });
	assert.equal(claimed.cause, cause);
	assert.equal("cause" in new JWTError("JWT_INVALID", "bad"), false);
});

test("the root export holds JWTError and none of the 1.x subclasses", () => {
	assert.equal(root.JWTError, JWTError);
	for (const removed of [
		"JWTInvalid", "JWTExpired", "JWTClaimValidationFailed", "MissingClaim", "AlgorithmNotAllowed",
		"KeyImportFailed", "KeyTypeMismatch", "KeyExportFailed", "EntropyCheckFailed", "JWKSFetchFailed",
		"JWKSNoMatchingKey", "JWTRevoked", "RevocationCheckFailed", "PayloadHygieneViolation",
		"MaxLifetimeExceeded", "BearerParseFailed",
	]) {
		assert.equal(removed in root, false, removed);
	}
});
