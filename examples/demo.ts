/**
 * Lacewing end-to-end demo - run with `npm run demo`.
 *
 * Walks through the library's headline guarantees against live keys:
 * every "rejected" line below is a real thrown error, not a mock. If any
 * expectation fails the script exits non-zero, so this doubles as a smoke
 * test of the README's claims.
 */

import {
	defineProfile,
	jwtVerify,
	SignJWT,
	generateKeyPair,
	importKey,
	unsafeDecode,
	parseBearer,
	MemoryRevocationStore,
	accessTokenProfile,
	refreshTokenProfile,
	newRefreshToken,
	EncryptJWT,
	jwtDecrypt,
	defineDecryptionProfile,
	generateDirectKey,
	JWTError,
} from "../index.js";

const ISSUER = "https://auth.example.com";
const AUDIENCE = "https://api.example.com";

let failures = 0;

function ok(label: string): void {
	console.log(`  ok: ${label}`);
}

async function rejected(label: string, run: () => Promise<unknown>): Promise<void> {
	try {
		await run();
		failures += 1;
		console.log(`  FAIL: ${label} was accepted, expected a rejection`);
	} catch (error) {
		const name = error instanceof JWTError ? `${error.constructor.name} (${error.code})` : String(error);
		console.log(`  ok: ${label} -> ${name}`);
	}
}

console.log("\n1. Sign + verify (EdDSA, the default)");
const { publicKey, privateKey } = await generateKeyPair("EdDSA");
const revocation = new MemoryRevocationStore();
const profile = defineProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	algorithms: ["EdDSA"],
	keys: publicKey,
	maxTokenAge: "15m",
	revocation,
});

const token = await new SignJWT("at+jwt")
	.issuer(ISSUER)
	.audience(AUDIENCE)
	.subject("user-42")
	.claim("scope", "read")
	.expiresIn("10m")
	.sign(privateKey);

const verified = await jwtVerify(token, profile);
ok(`signed and verified: sub=${String(verified.payload.sub)}, jti auto-assigned (${String(verified.payload.jti).slice(0, 8)}...)`);

console.log("\n2. The classics are unrepresentable or rejected");
const [header] = token.split(".");
const noneToken = `${Buffer.from(JSON.stringify({ alg: "none", typ: "at+jwt" })).toString("base64url")}.${token.split(".")[1]}.`;
await rejected("alg 'none' token", () => jwtVerify(noneToken, profile));
await rejected("tampered signature", () => jwtVerify(`${header}.${token.split(".")[1]}.${"A".repeat(86)}`, profile));

const wrongAudience = await new SignJWT("at+jwt")
	.issuer(ISSUER)
	.audience("https://evil.example.com")
	.expiresIn("10m")
	.sign(privateKey);
await rejected("wrong audience", () => jwtVerify(wrongAudience, profile));

console.log("\n3. Payload hygiene at sign time");
await rejected("payload containing a 'password' claim", () =>
	new SignJWT("at+jwt").issuer(ISSUER).audience(AUDIENCE).expiresIn("5m").claim("password", "hunter2").sign(privateKey)
);

console.log("\n4. Weak HMAC secrets never import");
await rejected("importKey('my-secret-password-123')", () => importKey("my-secret-password-123", "HS256"));

console.log("\n5. Revocation is built-in");
revocation.revoke(String(verified.payload.jti), verified.payload.exp);
await rejected("the token from step 1, after revoke(jti)", () => jwtVerify(token, profile));

console.log("\n6. Access vs refresh (typ does the work)");
const apiProfile = accessTokenProfile({ issuer: ISSUER, audience: AUDIENCE, algorithms: ["EdDSA"], keys: publicKey });
const authProfile = refreshTokenProfile({ issuer: ISSUER, audience: ISSUER + "/token", algorithms: ["EdDSA"], keys: publicKey });
const refreshToken = await newRefreshToken()
	.issuer(ISSUER)
	.audience(ISSUER + "/token")
	.subject("user-42")
	.expiresIn("30d")
	.sign(privateKey);
const refreshVerified = await jwtVerify(refreshToken, authProfile);
ok(`refresh token accepted by the auth profile (typ rt+jwt, sub=${String(refreshVerified.payload.sub)})`);
await rejected("refresh token presented to the API profile", () => jwtVerify(refreshToken, apiProfile));

console.log("\n7. unsafeDecode is loud and type-branded");
const untrusted = unsafeDecode(token);
ok(`unsafeDecode works on the revoked token: alg=${untrusted.header.alg} - but its type is UntrustedJwt, unusable where VerifiedJwt is required`);

console.log("\n8. Encrypted JWTs (JWE), same profile discipline");
const dirKey = await generateDirectKey("A256GCM");
const jwe = await new EncryptJWT("at+jwt", { contentEncryption: "A256GCM" })
	.issuer(ISSUER)
	.audience(AUDIENCE)
	.subject("user-42")
	.expiresIn("5m")
	.encrypt(dirKey);
const decrypted = await jwtDecrypt(jwe, defineDecryptionProfile({
	typ: "at+jwt",
	issuer: ISSUER,
	audience: AUDIENCE,
	key: dirKey,
	keyManagementAlgorithms: ["dir"],
	contentEncryptionAlgorithms: ["A256GCM"],
	maxTokenAge: "15m",
}));
ok(`encrypted, then decrypted: sub=${String(decrypted.payload.sub)} (5 segments, AEAD-protected)`);
await rejected("the JWE handed to jwtVerify (format confusion)", () => jwtVerify(jwe, profile));

console.log("\n9. Strict Authorization: Bearer parsing");
ok(`parseBearer extracts exactly one token: ${parseBearer(`Bearer ${jwe}`).slice(0, 16)}...`);
await rejected("two tokens in one header", async () => parseBearer(`Bearer ${jwe} ${jwe}`));

if (failures > 0) {
	console.error(`\n${failures} expectation(s) failed`);
	process.exit(1);
}
console.log("\nAll demonstrations behaved as documented.\n");
