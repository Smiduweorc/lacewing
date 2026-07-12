/**
 * RFC 8725 §3.6 - do not compress before encryption (no `zip`); §3.7 - use
 * UTF-8 and strict, canonical encodings. Parser-differential seeds (non-UTF-8,
 * duplicate JSON keys) reject the token.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { jwtVerify, JWTInvalid } from "../../index.js";
import { b64u, b64uJson, craftHmacToken, craftHmacTokenRaw, standardClaims } from "../helpers.js";
import { createHmac } from "node:crypto";
import { AUDIENCE, ISSUER, hmac, hmacProfile } from "./_shared.js";

const now = Math.floor(Date.now() / 1000);
const validPayloadJson = JSON.stringify({ iss: ISSUER, aud: AUDIENCE, sub: "user-42", jti: "j1", iat: now, exp: now + 300 });

test("[8725-3.6.1] a zip (compression) header is rejected - no decompression bombs", async () => {
	const token = craftHmacToken({ alg: "HS256", typ: "at+jwt", zip: "DEF" }, standardClaims(), hmac.key as Uint8Array);
	await assert.rejects(jwtVerify(token, hmacProfile()), JWTInvalid);
});

test("[8725-3.7.1] a non-UTF-8 payload is rejected even with a valid signature", async () => {
	const header = b64uJson({ alg: "HS256", typ: "at+jwt" });
	const payload = b64u(new Uint8Array([0xff, 0xfe, 0x7b, 0x7d]));
	const mac = createHmac("sha256", hmac.key as Uint8Array).update(`${header}.${payload}`).digest();
	await assert.rejects(jwtVerify(`${header}.${payload}.${b64u(mac)}`, hmacProfile()), JWTInvalid);
});

test("[8725-3.7.1] duplicate JSON keys in the payload are a parser differential and are rejected", async () => {
	// Two `aud` members: JSON.parse would keep the last; Lacewing refuses.
	const dupPayload = `{"iss":"${ISSUER}","aud":"${AUDIENCE}","aud":"https://evil.example.com","sub":"user-42","jti":"j1","iat":${now},"exp":${now + 300}}`;
	const token = craftHmacTokenRaw(JSON.stringify({ alg: "HS256", typ: "at+jwt" }), dupPayload, hmac.key as Uint8Array);
	await assert.rejects(jwtVerify(token, hmacProfile()), JWTInvalid);
});

test("[8725-3.7.1] duplicate JSON keys in the header are rejected before any key lookup", async () => {
	const dupHeader = "{\"alg\":\"HS256\",\"alg\":\"none\",\"typ\":\"at+jwt\"}";
	const token = craftHmacTokenRaw(dupHeader, validPayloadJson, hmac.key as Uint8Array);
	await assert.rejects(jwtVerify(token, hmacProfile()), JWTInvalid);
});
