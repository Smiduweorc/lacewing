import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT } from "../../../src/jwt/sign.js";
import { jwtVerify } from "../../../src/jwt/verify.js";
import { defineProfile } from "../../../src/jwt/profile.js";
import { generateKeyPair, generateSecret } from "../../../src/key/generate.js";
import { MemoryRevocationStore } from "../../../src/revocation/memory.js";
import {
	AlgorithmNotAllowed,
	JWTClaimValidationFailed,
	JWTInvalid,
	JWTRevoked,
	MissingClaim,
	RevocationCheckFailed,
} from "../../../src/util/errors.js";
import type { ProfileOptions, TokenRevocationContext } from "../../../index.js";
import { craftHmacToken, standardClaims } from "../../helpers.js";

const { publicKey, privateKey } = await generateKeyPair("EdDSA");
const secret = generateSecret("HS256");

function makeProfile(overrides: Partial<ProfileOptions> = {}): ReturnType<typeof defineProfile> {
	return defineProfile({
		typ: "at+jwt",
		issuer: "https://auth.example.com",
		audience: "https://api.example.com",
		algorithms: ["EdDSA"],
		keys: publicKey,
		maxTokenAge: "15m",
		...overrides,
	});
}

function signToken(typ = "at+jwt"): Promise<string> {
	return new SignJWT(typ)
		.issuer("https://auth.example.com")
		.audience("https://api.example.com")
		.subject("user-42")
		.expiresIn("10m")
		.sign(privateKey);
}

test("round-trip: sign -> verify yields the verified payload (EdDSA)", async () => {
	const verified = await jwtVerify(await signToken(), makeProfile());
	assert.equal(verified.payload.iss, "https://auth.example.com");
	assert.equal(verified.payload.sub, "user-42");
	assert.equal(verified.header.alg, "EdDSA");
});

test("round-trip works for HMAC profiles too", async () => {
	const token = await new SignJWT("at+jwt")
		.issuer("https://auth.example.com")
		.audience("https://api.example.com")
		.expiresIn("5m")
		.sign(secret);
	const profile = makeProfile({ algorithms: ["HS256"], keys: secret });
	const verified = await jwtVerify(token, profile);
	assert.equal(verified.header.alg, "HS256");
});

test("[8725-3.3.1] tampered tokens are rejected with a typed error", async () => {
	const token = await signToken();
	const [header, payload, signature] = token.split(".") as [string, string, string];
	// Flip a character in each segment in turn.
	const flip = (s: string): string =>
		(s[0] === "A" ? "B" : "A") + s.slice(1);
	await assert.rejects(jwtVerify(`${header}.${flip(payload)}.${signature}`, makeProfile()), JWTInvalid);
	await assert.rejects(jwtVerify(`${header}.${payload}.${flip(signature)}`, makeProfile()), JWTInvalid);
	await assert.rejects(jwtVerify(`${header}.${payload}.${signature.slice(0, -8)}`, makeProfile()), JWTInvalid);
});

test("garbage input never crashes - always a typed JWTInvalid", async () => {
	const garbage = [
		"",
		".",
		"..",
		"a.b",
		"a.b.c.d",
		"ey.ey.",
		"🤡.🤡.🤡",
		"a".repeat(100_000),
		`${"a".repeat(20000)}.b.c`,
	];
	for (const input of garbage) {
		await assert.rejects(jwtVerify(input, makeProfile()), JWTInvalid);
	}
	await assert.rejects(jwtVerify(null as never, makeProfile()), JWTInvalid);
});

test("[8725-3.1.1] the profile allowlist decides, not the token header", async () => {
	// A perfectly valid HS256 token is rejected by an EdDSA-only profile.
	const token = craftHmacToken(
		{ alg: "HS256", typ: "at+jwt" },
		standardClaims(),
		secret.key as Uint8Array
	);
	await assert.rejects(jwtVerify(token, makeProfile()), AlgorithmNotAllowed);
});

test("[8725-3.12.1] profiles with different typ are mutually exclusive", async () => {
	const accessProfile = makeProfile({ typ: "at+jwt" });
	const refreshProfile = makeProfile({ typ: "rt+jwt" });
	const accessToken = await signToken("at+jwt");
	const refreshToken = await signToken("rt+jwt");
	await assert.doesNotReject(jwtVerify(accessToken, accessProfile));
	await assert.doesNotReject(jwtVerify(refreshToken, refreshProfile));
	await assert.rejects(jwtVerify(refreshToken, accessProfile), JWTClaimValidationFailed);
	await assert.rejects(jwtVerify(accessToken, refreshProfile), JWTClaimValidationFailed);
});

test("[8725-3.11.2] typ comparison tolerates the application/ media-type prefix", async () => {
	const profile = makeProfile({ typ: "application/at+jwt" });
	await assert.doesNotReject(jwtVerify(await signToken("at+jwt"), profile));
});

test("[LW-rev.2] revoked tokens are rejected after signature and claims pass", async () => {
	const store = new MemoryRevocationStore();
	const profile = makeProfile({ revocation: store });
	const token = await signToken();
	const verified = await jwtVerify(token, profile);
	store.revoke(verified.payload.jti as string, verified.payload.exp);
	await assert.rejects(jwtVerify(token, profile), JWTRevoked);
	// Other tokens are unaffected.
	await assert.doesNotReject(jwtVerify(await signToken(), profile));
});

test("[LW-rev.3] the store is never consulted for forged tokens", async () => {
	const calls: TokenRevocationContext[] = [];
	const spyStore = {
		async isRevoked(context: TokenRevocationContext): Promise<boolean> {
			calls.push(context);
			return false;
		},
	};
	const profile = makeProfile({ revocation: spyStore });
	const token = await signToken();
	const [h, p, s] = token.split(".") as [string, string, string];
	await assert.rejects(jwtVerify(`${h}.${p}.${s.slice(0, -8)}AAAAAAAA`, profile), JWTInvalid);
	assert.equal(calls.length, 0, "revocation store must not see unauthenticated input");
	await jwtVerify(token, profile);
	assert.equal(calls.length, 1);
});

test("[LW-rev.4] store errors fail closed, unless the ugly flag is set", async () => {
	const failingStore = {
		async isRevoked(): Promise<boolean> {
			throw new Error("redis is down");
		},
	};
	const token = await signToken();
	await assert.rejects(
		jwtVerify(token, makeProfile({ revocation: failingStore })),
		RevocationCheckFailed
	);
	await assert.doesNotReject(
		jwtVerify(
			token,
			makeProfile({ revocation: failingStore, unsafeFailOpenOnRevocationError: true })
		)
	);
});

test("[LW-rev] a revocation profile requires tokens to carry a jti", async () => {
	const store = new MemoryRevocationStore();
	const hsProfile = makeProfile({
		algorithms: ["HS256"],
		keys: secret,
		revocation: store,
	});
	const token = craftHmacToken(
		{ alg: "HS256", typ: "at+jwt" },
		(() => {
			const claims = standardClaims();
			delete claims.jti;
			return claims;
		})(),
		secret.key as Uint8Array
	);
	await assert.rejects(jwtVerify(token, hsProfile), MissingClaim);
});

test("custom claim validators run through the verify path", async () => {
	const profile = makeProfile({
		claimValidators: {
			scope: (value) => {
				if (value !== "read") throw new Error("nope");
			},
		},
	});
	const good = await new SignJWT("at+jwt")
		.issuer("https://auth.example.com")
		.audience("https://api.example.com")
		.claim("scope", "read")
		.expiresIn("5m")
		.sign(privateKey);
	await assert.doesNotReject(jwtVerify(good, profile));
	await assert.rejects(jwtVerify(await signToken(), profile), JWTClaimValidationFailed);
});
