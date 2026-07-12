import { test } from "node:test";
import assert from "node:assert/strict";
import { validateClaims } from "../../../src/lib/claims.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { generateSecret } from "../../../src/key/generate.js";
import {
	JWTClaimValidationFailed,
	JWTExpired,
	MissingClaim,
} from "../../../src/util/errors.js";
import { nowSeconds, standardClaims } from "../../helpers.js";

const key = generateSecret("HS256");

function makeProfile(overrides: Record<string, unknown> = {}): ReturnType<typeof defineProfile> {
	return defineProfile({
		typ: "at+jwt",
		issuer: "https://auth.example.com",
		audience: "https://api.example.com",
		algorithms: ["HS256"],
		keys: key,
		maxTokenAge: "15m",
		...overrides,
	});
}

test("a well-formed payload passes", async () => {
	await assert.doesNotReject(validateClaims(standardClaims(), makeProfile()));
});

test("[8725-3.8.1] wrong issuer is rejected", async () => {
	await assert.rejects(
		validateClaims(standardClaims({ iss: "https://evil.example.com" }), makeProfile()),
		JWTClaimValidationFailed
	);
});

test("[8725-3.8.1] missing issuer is rejected", async () => {
	const claims = standardClaims();
	delete claims.iss;
	await assert.rejects(validateClaims(claims, makeProfile()), MissingClaim);
});

test("[8725-3.9.1] wrong or missing audience is rejected", async () => {
	await assert.rejects(
		validateClaims(standardClaims({ aud: "https://other.example.com" }), makeProfile()),
		JWTClaimValidationFailed
	);
	const claims = standardClaims();
	delete claims.aud;
	await assert.rejects(validateClaims(claims, makeProfile()), MissingClaim);
});

test("[8725-3.9.1] audience arrays match when they include the expected value", async () => {
	await assert.doesNotReject(
		validateClaims(
			standardClaims({ aud: ["https://cdn.example.com", "https://api.example.com"] }),
			makeProfile()
		)
	);
	await assert.rejects(
		validateClaims(standardClaims({ aud: ["https://cdn.example.com"] }), makeProfile()),
		JWTClaimValidationFailed
	);
	// Non-string entries never match.
	await assert.rejects(
		validateClaims(standardClaims({ aud: [42] }), makeProfile()),
		JWTClaimValidationFailed
	);
});

test("expired tokens are rejected; skew is bounded", async () => {
	const now = nowSeconds();
	await assert.rejects(
		validateClaims(standardClaims({ iat: now - 60, exp: now - 30 }), makeProfile()),
		JWTExpired
	);
	// Inside the 5s default skew: still accepted.
	await assert.doesNotReject(
		validateClaims(standardClaims({ iat: now - 60, exp: now - 3 }), makeProfile())
	);
});

test("missing or non-numeric exp is rejected", async () => {
	const claims = standardClaims();
	delete claims.exp;
	await assert.rejects(validateClaims(claims, makeProfile()), MissingClaim);
	await assert.rejects(
		validateClaims(standardClaims({ exp: "soon" }), makeProfile()),
		JWTClaimValidationFailed
	);
});

test("iat in the future is rejected", async () => {
	await assert.rejects(
		validateClaims(standardClaims({ iat: nowSeconds() + 3600 }), makeProfile()),
		JWTClaimValidationFailed
	);
});

test("[LW-life.2] maxTokenAge is enforced independently of exp", async () => {
	const now = nowSeconds();
	// Token is 2h old but exp is still 10 years away.
	await assert.rejects(
		validateClaims(
			standardClaims({ iat: now - 7200, exp: now + 315_360_000 }),
			makeProfile({ maxTokenAge: "15m" })
		),
		JWTExpired
	);
});

test("future nbf is rejected", async () => {
	await assert.rejects(
		validateClaims(standardClaims({ nbf: nowSeconds() + 3600 }), makeProfile()),
		JWTClaimValidationFailed
	);
	await assert.doesNotReject(
		validateClaims(standardClaims({ nbf: nowSeconds() - 10 }), makeProfile())
	);
});

test("[8725-3.8.2] pinned subject must match", async () => {
	const profile = makeProfile({ subject: "user-42" });
	await assert.doesNotReject(validateClaims(standardClaims(), profile));
	await assert.rejects(
		validateClaims(standardClaims({ sub: "user-43" }), profile),
		JWTClaimValidationFailed
	);
	const claims = standardClaims();
	delete claims.sub;
	await assert.rejects(validateClaims(claims, profile), MissingClaim);
});

test("custom claim validators run and their failures are typed", async () => {
	const profile = makeProfile({
		claimValidators: {
			scope: (value: unknown) => {
				if (value !== "read") throw new Error("bad scope");
			},
		},
	});
	await assert.doesNotReject(validateClaims(standardClaims({ scope: "read" }), profile));
	await assert.rejects(
		validateClaims(standardClaims({ scope: "admin" }), profile),
		(error: unknown) =>
			error instanceof JWTClaimValidationFailed && error.claim === "scope"
	);
});

test("claim validation errors never echo untrusted values", async () => {
	const marker = "EVIL_VALUE_marker";
	try {
		await validateClaims(standardClaims({ iss: marker }), makeProfile());
		assert.fail("should have thrown");
	} catch (error) {
		assert.ok(error instanceof JWTClaimValidationFailed);
		assert.ok(!error.message.includes(marker));
	}
});

test("oversized string claims are rejected", async () => {
	await assert.rejects(
		validateClaims(standardClaims({ jti: "x".repeat(5000) }), makeProfile()),
		JWTClaimValidationFailed
	);
});
