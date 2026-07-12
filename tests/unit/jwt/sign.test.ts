import { test } from "node:test";
import assert from "node:assert/strict";
import { SignJWT } from "../../../src/jwt/sign.js";
import { generateKeyPair, generateSecret } from "../../../src/key/generate.js";
import { unsafeDecode } from "../../../src/util/unsafe-decode.js";
import {
	KeyTypeMismatch,
	MaxLifetimeExceeded,
	MissingClaim,
	PayloadHygieneViolation,
} from "../../../src/util/errors.js";
import { nowSeconds } from "../../helpers.js";

const { publicKey, privateKey } = await generateKeyPair("EdDSA");

function builder(): SignJWT {
	return new SignJWT("at+jwt")
		.issuer("https://auth.example.com")
		.audience("https://api.example.com")
		.expiresIn("10m");
}

test("[8725-3.11.1] a signed token carries the explicit typ and required claims", async () => {
	const token = await builder().subject("user-42").claim("scope", "read").sign(privateKey);
	const { header, payload } = unsafeDecode(token);
	assert.equal(header.typ, "at+jwt");
	assert.equal(header.alg, "EdDSA");
	assert.equal(payload.iss, "https://auth.example.com");
	assert.equal(payload.aud, "https://api.example.com");
	assert.equal(payload.sub, "user-42");
	assert.equal(payload.scope, "read");
	assert.ok(Math.abs((payload.iat as number) - nowSeconds()) <= 2);
	assert.equal(payload.exp, (payload.iat as number) + 600);
});

test("[LW-rev.1] every token gets a unique jti by default", async () => {
	const first = unsafeDecode(await builder().sign(privateKey));
	const second = unsafeDecode(await builder().sign(privateKey));
	assert.equal(typeof first.payload.jti, "string");
	assert.notEqual(first.payload.jti, second.payload.jti);
});

test("typ is mandatory at construction", () => {
	// @ts-expect-error - typ is a required constructor argument
	assert.throws(() => new SignJWT(), TypeError);
	assert.throws(() => new SignJWT(""), TypeError);
});

test("[8725-3.8/3.9] sign() refuses tokens without iss, aud or exp", async () => {
	await assert.rejects(
		new SignJWT("at+jwt").audience("a").expiresIn(60).sign(privateKey),
		(e: unknown) => e instanceof MissingClaim && e.claim === "iss"
	);
	await assert.rejects(
		new SignJWT("at+jwt").issuer("i").expiresIn(60).sign(privateKey),
		(e: unknown) => e instanceof MissingClaim && e.claim === "aud"
	);
	await assert.rejects(
		new SignJWT("at+jwt").issuer("i").audience("a").sign(privateKey),
		(e: unknown) => e instanceof MissingClaim && e.claim === "exp"
	);
});

test("waivers are explicit, per-field and grep-loud", async () => {
	const token = await new SignJWT("magic-link")
		.audience("https://api.example.com")
		.expiresIn("5m")
		.unsafeAllowMissingIssuer()
		.sign(privateKey);
	const { payload } = unsafeDecode(token);
	assert.equal(payload.iss, undefined);
	// The other requirements still hold.
	await assert.rejects(
		new SignJWT("magic-link").unsafeAllowMissingIssuer().expiresIn("5m").sign(privateKey),
		MissingClaim
	);
});

test("[LW-life.1] lifetimes beyond the cap are rejected at sign time", async () => {
	await assert.rejects(
		builder().expiresIn("2h").sign(privateKey),
		MaxLifetimeExceeded
	);
	// A 10-year token requires a deliberate, visible maxLifetime.
	await assert.rejects(
		builder().expiresIn(315_360_000).sign(privateKey),
		MaxLifetimeExceeded
	);
	const token = await new SignJWT("rt+jwt", { maxLifetime: "30d" })
		.issuer("i")
		.audience("a")
		.expiresIn("7d")
		.sign(privateKey);
	assert.equal(typeof token, "string");
});

test("registered claims cannot be smuggled through .claim()", () => {
	for (const name of ["iss", "aud", "exp", "iat", "jti", "nbf", "sub"]) {
		assert.throws(() => builder().claim(name, "x"), TypeError);
	}
});

test("[LW-payload.1] the hygiene scanner runs at sign time", async () => {
	await assert.rejects(
		builder().claim("password", "hunter2").sign(privateKey),
		PayloadHygieneViolation
	);
});

test("[LW-payload.1] hygiene false positives are waived per claim, loudly", async () => {
	const token = await builder()
		.claim("passwordHint", "favorite color")
		.unsafeAllowClaim("passwordHint")
		.sign(privateKey);
	assert.equal(unsafeDecode(token).payload.passwordHint, "favorite color");
});

test("signing requires a Lacewing key that can sign", async () => {
	await assert.rejects(
		builder().sign({} as never),
		TypeError
	);
	await assert.rejects(builder().sign(publicKey), KeyTypeMismatch);
});

test("HMAC signing works with generated secrets", async () => {
	const secret = generateSecret("HS256");
	const token = await builder().sign(secret);
	assert.equal(unsafeDecode(token).header.alg, "HS256");
});

test("notBefore and jwtId are honored", async () => {
	const token = await builder().notBefore("1m").jwtId("custom-jti").sign(privateKey);
	const { payload } = unsafeDecode(token);
	assert.equal(payload.jti, "custom-jti");
	assert.equal(payload.nbf, (payload.iat as number) + 60);
});
