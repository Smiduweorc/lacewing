import { test } from "node:test";
import assert from "node:assert/strict";
import * as errors from "../../../src/util/errors.js";

const EXPECTED_CODES: Record<string, string> = {
	JWTInvalid: "JWT_INVALID",
	JWTExpired: "JWT_EXPIRED",
	MissingClaim: "MISSING_CLAIM",
	AlgorithmNotAllowed: "ALGORITHM_NOT_ALLOWED",
	KeyImportFailed: "KEY_IMPORT_FAILED",
	KeyExportFailed: "KEY_EXPORT_FAILED",
	KeyTypeMismatch: "KEY_TYPE_MISMATCH",
	EntropyCheckFailed: "ENTROPY_CHECK_FAILED",
	JWKSFetchFailed: "JWKS_FETCH_FAILED",
	JWKSNoMatchingKey: "JWKS_NO_MATCHING_KEY",
	JWTRevoked: "JWT_REVOKED",
	RevocationCheckFailed: "REVOCATION_CHECK_FAILED",
	MaxLifetimeExceeded: "MAX_LIFETIME_EXCEEDED",
	BearerParseFailed: "BEARER_PARSE_FAILED",
};

test("every error carries its machine-readable code and proper name", () => {
	for (const [name, code] of Object.entries(EXPECTED_CODES)) {
		const ErrorClass = errors[name as keyof typeof errors] as new (m: string) => errors.JWTError;
		const error = new ErrorClass("message");
		assert.equal(error.code, code, name);
		assert.equal(error.name, name);
		assert.ok(error instanceof errors.JWTError);
		assert.ok(error instanceof Error);
	}
});

test("claim-carrying errors expose the claim name", () => {
	const claimError = new errors.JWTClaimValidationFailed("aud", "mismatch");
	assert.equal(claimError.code, "JWT_CLAIM_VALIDATION_FAILED");
	assert.equal(claimError.claim, "aud");
	const hygiene = new errors.PayloadHygieneViolation("password", "no");
	assert.equal(hygiene.code, "PAYLOAD_HYGIENE_VIOLATION");
	assert.equal(hygiene.claim, "password");
	const missing = new errors.MissingClaim("exp");
	assert.equal(missing.claim, "exp");
});

test("errors carry an optional cause for operators", () => {
	const cause = new Error("underlying");
	const error = new errors.JWKSFetchFailed("fetch failed", { cause });
	assert.equal(error.cause, cause);
});
