/**
 * Shared fixtures for the compliance suite. Everything here goes through the
 * *public* API (index.ts) - compliance is a property of what callers can
 * reach, not of internals.
 */

import {
	defineProfile,
	generateKeyPair,
	generateSecret,
	SignJWT,
	type ExpectedJwtProfile,
	type LacewingKey,
	type ProfileOptions,
} from "../../index.js";

export const ISSUER = "https://auth.example.com";
export const AUDIENCE = "https://api.example.com";

export const eddsa = await generateKeyPair("EdDSA", { extractable: true });
export const es256 = await generateKeyPair("ES256", { extractable: true });
export const hmac = generateSecret("HS256");

/** A profile that trusts a single EdDSA public key. */
export function eddsaProfile(overrides: Partial<ProfileOptions> = {}): ExpectedJwtProfile {
	return defineProfile({
		typ: "at+jwt",
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["EdDSA"],
		keys: eddsa.publicKey,
		maxTokenAge: "15m",
		...overrides,
	});
}

/** A profile that trusts a single HS256 secret. */
export function hmacProfile(overrides: Partial<ProfileOptions> = {}): ExpectedJwtProfile {
	return defineProfile({
		typ: "at+jwt",
		issuer: ISSUER,
		audience: AUDIENCE,
		algorithms: ["HS256"],
		keys: hmac,
		maxTokenAge: "15m",
		...overrides,
	});
}

/** Sign a standard, policy-satisfying access token with the given key. */
export function signValid(
	key: LacewingKey,
	build: (b: SignJWT) => SignJWT = (b) => b
): Promise<string> {
	return build(
		new SignJWT("at+jwt")
			.issuer(ISSUER)
			.audience(AUDIENCE)
			.subject("user-42")
			.expiresIn("5m")
	).sign(key);
}
