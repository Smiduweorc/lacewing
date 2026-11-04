/**
 * Found in the second v3 audit: SignJWT and EncryptJWT produced tokens that
 * Lacewing's own jwtVerify and jwtDecrypt then refused. A signer that emits
 * what its verifier rejects hands the caller a token that fails only once it
 * is in use, so each of these now fails at sign or encrypt time instead.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
	SignJWT,
	EncryptJWT,
	jwtVerify,
	defineProfile,
	generateDirectKey,
	importKey,
} from "../../../index.js";

const ISS = "https://auth.example.com";
const AUD = "https://api.example.com";
const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
const secret = await importKey(raw, "HS256");
const dir = generateDirectKey("A256GCM");
const profile = defineProfile({ typ: "at+jwt", issuer: ISS, audience: AUD, algorithms: ["HS256"], keys: secret, maxTokenAge: "5m" });

const signer = (): SignJWT => new SignJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m");
const encrypter = (): EncryptJWT => new EncryptJWT("at+jwt").issuer(ISS).audience(AUD).expiresIn("5m");

test("a __proto__, constructor or prototype member is refused at sign and encrypt time, at any depth", async () => {
	for (const [name, value] of [
		["__proto__", { isAdmin: true }],
		["meta", JSON.parse("{\"constructor\":{\"prototype\":{}}}")],
		["list", [JSON.parse("{\"__proto__\":1}")]],
	] as const) {
		await assert.rejects(signer().claim(name, value).sign(secret), TypeError, name);
		await assert.rejects(encrypter().claim(name, value).encrypt(dir), TypeError, name);
	}
});

test("iss, sub and jti longer than the 1024 verification accepts are refused at sign time; 1024 exactly signs and verifies", async () => {
	const at = "x".repeat(1024);
	const over = "x".repeat(1025);
	await assert.rejects(signer().subject(over).sign(secret), TypeError);
	await assert.rejects(signer().jwtId(over).sign(secret), TypeError);
	await assert.rejects(new SignJWT("at+jwt").issuer(over).audience(AUD).expiresIn("5m").sign(secret), TypeError);
	await assert.rejects(encrypter().subject(over).encrypt(dir), TypeError);
	await assert.doesNotReject(jwtVerify(await signer().subject(at).sign(secret), profile));
});

test("a token over the 16384 characters verification accepts is refused at sign and encrypt time", async () => {
	await assert.rejects(signer().claim("blob", "a".repeat(20_000)).sign(secret), (error: unknown) => {
		assert.ok(error instanceof TypeError);
		assert.match(error.message, /16384/);
		return true;
	});
	await assert.rejects(encrypter().claim("blob", "a".repeat(20_000)).encrypt(dir), TypeError);
});

test("the token-length boundary: the largest token that signs verifies, and the next size up is refused", async () => {
	// Grow a claim until the token is as close to the 16384 cap as signing allows.
	const base = (await signer().jwtId("j").claim("blob", "").sign(secret)).length;
	const build = (extra: number): Promise<string> => signer().jwtId("j").claim("blob", "a".repeat(extra)).sign(secret);
	// base64url grows by 4 characters per 3 bytes, so step until we straddle the cap.
	let extra = Math.floor(((16384 - base) * 3) / 4) - 3;
	let token = await build(extra);
	while (token.length < 16384) {
		extra += 1;
		try {
			token = await build(extra);
		} catch {
			break;
		}
	}
	// base64url moves in steps of up to 4 characters, so the largest token that signs sits within 4 of the cap.
	assert.ok(token.length <= 16384 && token.length > 16380, `landed at ${token.length}`);
	await assert.doesNotReject(jwtVerify(token, profile));
	await assert.rejects(build(extra + 3), TypeError);
});

test("jwtVerify still refuses an over-long token built by someone else", async () => {
	const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
	const now = Math.floor(Date.now() / 1000);
	const input = `${b64({ alg: "HS256", typ: "at+jwt" })}.${b64({ iss: ISS, aud: AUD, iat: now, exp: now + 60, blob: "a".repeat(20_000) })}`;
	const token = `${input}.${createHmac("sha256", raw).update(input).digest("base64url")}`;
	await assert.rejects(jwtVerify(token, profile), { name: "JWTError", code: "JWT_INVALID" });
});
