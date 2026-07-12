/**
 * NEGATIVE FIXTURE - this file MUST NOT compile (RFC 8725 §3.1.2).
 *
 * Sign and verify never accept a bare `CryptoKey`: every key must come through
 * `importKey`/`generateKeyPair`, which is what binds it to one algorithm. If a
 * raw CryptoKey could be signed with, the alg-key binding would be bypassable.
 */

import { SignJWT } from "../../../index.js";

declare const rawKey: CryptoKey;

// ERROR: CryptoKey is not a LacewingKey.
export const signed = new SignJWT("at+jwt")
	.issuer("https://auth.example.com")
	.audience("https://api.example.com")
	.expiresIn("5m")
	.sign(rawKey);
