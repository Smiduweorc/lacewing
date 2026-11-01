/**
 * LW-kind.1 (RFC 8725 §3.12 doing double duty) - the cookbook's access and
 * refresh profiles are *mutually exclusive*. This is a property, not an
 * anecdote: no matter what claims a token carries, the profile for one kind
 * must never accept the other kind's token.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { refusal } from "../helpers.js";
import fc from "fast-check";
import {
	accessTokenProfile,
	refreshTokenProfile,
	newAccessToken,
	newRefreshToken,
	jwtVerify,
	generateKeyPair,
	type LacewingKey,
	type SignJWT,
	MemoryRevocationStore,
} from "../../index.js";

const ISSUER = "https://auth.example.com";
const API = "https://api.example.com";

const { publicKey, privateKey } = await generateKeyPair("EdDSA");

// Deliberately the *same* issuer, audience, algorithm and key for both kinds,
// so the only thing standing between them is `typ`. If the profiles still
// refuse each other's tokens, the separation cannot be an accident of config.
const revocation = new MemoryRevocationStore();
const shared = { issuer: ISSUER, audience: API, algorithms: ["EdDSA"], keys: publicKey, revocation } as const;
const access = accessTokenProfile({ ...shared, maxTokenAge: "30d" });
const refresh = refreshTokenProfile({ ...shared, maxTokenAge: "30d" });

function sign(builder: SignJWT, subject: string, scope: string, key: LacewingKey): Promise<string> {
	return builder.issuer(ISSUER).audience(API).subject(subject).claim("scope", scope).expiresIn("10m").sign(key);
}

// Claim values that must not influence the outcome.
const subject = fc.string({ minLength: 1, maxLength: 64 }).filter((s) => s.trim().length > 0);
const scope = fc.string({ maxLength: 64 });

test("[LW-kind.1] no access token is ever accepted by the refresh profile", async () => {
	await fc.assert(
		fc.asyncProperty(subject, scope, async (sub, sc) => {
			const token = await sign(newAccessToken(), sub, sc, privateKey);
			// Its own profile takes it...
			const { header } = await jwtVerify(token, access);
			assert.equal(header.typ, "at+jwt");
			// ...and the other kind's profile does not, on typ alone.
			await assert.rejects(jwtVerify(token, refresh), refusal("JWT_CLAIM_VALIDATION_FAILED"));
		}),
		{ numRuns: 25 }
	);
});

test("[LW-kind.1] no refresh token is ever accepted by the access profile", async () => {
	await fc.assert(
		fc.asyncProperty(subject, scope, async (sub, sc) => {
			const token = await sign(newRefreshToken(), sub, sc, privateKey);
			const { header } = await jwtVerify(token, refresh);
			assert.equal(header.typ, "rt+jwt");
			await assert.rejects(jwtVerify(token, access), refusal("JWT_CLAIM_VALIDATION_FAILED"));
		}),
		{ numRuns: 25 }
	);
});

test("[LW-kind.1] the two profiles disagree on typ by construction, whatever else you configure", () => {
	assert.notEqual(access.typ, refresh.typ);
	// The typ is fixed by the factory: callers cannot accidentally align them.
	const misconfigured = accessTokenProfile({ ...shared, maxTokenAge: "30d", typ: "rt+jwt" } as never);
	assert.equal(misconfigured.typ, "at+jwt");
});

test("[LW-kind.1][LW-rev.2] a refresh profile needs a revocation store, or opts out by name", () => {
	const { revocation: _revocation, ...unrevocable } = shared;
	assert.throws(
		() => refreshTokenProfile(unrevocable as never),
		(error: unknown) => error instanceof TypeError && error.message.includes("unsafeNoRevocation")
	);
	assert.throws(() => refreshTokenProfile({ ...shared, unsafeNoRevocation: true } as never), TypeError);
	const optedOut = refreshTokenProfile({ ...unrevocable, unsafeNoRevocation: true });
	assert.equal(optedOut.revocation, undefined);
	assert.equal(refreshTokenProfile(shared).revocation, revocation);
});

test("[LW-kind.1] the cookbook defaults: access 10m and refresh 30d accepted age", () => {
	const { revocation: _revocation, ...base } = shared;
	assert.equal(accessTokenProfile(base).maxTokenAge, 600);
	assert.equal(refreshTokenProfile(shared).maxTokenAge, 30 * 86400);
});
