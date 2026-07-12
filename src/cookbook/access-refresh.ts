/**
 * Cookbook: access tokens vs refresh tokens (LW-kind.1).
 *
 * The single most common token-confusion bug is letting a refresh token buy
 * access to an API (or letting a stolen access token mint new sessions). RFC
 * 8725 §3.12 says the validation rules for different kinds of JWT must be
 * mutually exclusive; Lacewing makes that concrete by shipping the two
 * profiles rather than leaving them as an exercise.
 *
 * The separation is enforced on three axes at once:
 *
 *  | | access | refresh |
 *  |---|---|---|
 *  | `typ` | `at+jwt` | `rt+jwt` |
 *  | audience | the API | the auth server's token endpoint |
 *  | lifetime | minutes (default 10m) | days (default 30d) |
 *  | key source | usually a public JWKS | usually a private, server-only key |
 *  | revocation | optional | **strongly recommended** |
 *
 * `typ` alone is load-bearing: even with identical keys, claims and audience,
 * each profile refuses the other's tokens. The rest is defense in depth.
 *
 * @example
 * ```ts
 * import { accessTokenProfile, refreshTokenProfile, newAccessToken } from "lacewing";
 *
 * const api = accessTokenProfile({
 *   issuer: "https://auth.example.com",
 *   audience: "https://api.example.com",
 *   algorithms: ["EdDSA"],
 *   keys: { jwksUri: "https://auth.example.com/jwks" },
 * });
 *
 * const token = await newAccessToken()
 *   .issuer("https://auth.example.com")
 *   .audience("https://api.example.com")
 *   .subject("user-42")
 *   .expiresIn("10m")
 *   .sign(privateKey);
 * ```
 */

import { defineProfile, type ProfileOptions } from "../jwt/profile.js";
import { SignJWT } from "../jwt/sign.js";
import type { ExpectedJwtProfile } from "../types.js";

/** The `typ` of an OAuth 2.0 JWT access token (RFC 9068). */
export const ACCESS_TOKEN_TYP = "at+jwt";
/** The `typ` Lacewing uses for refresh tokens - anything but the access `typ`. */
export const REFRESH_TOKEN_TYP = "rt+jwt";

const DEFAULT_ACCESS_MAX_AGE = "10m";
const DEFAULT_REFRESH_MAX_AGE = "30d";

/**
 * Everything a cookbook profile needs except the `typ`, which is fixed by the
 * factory. `maxTokenAge` becomes optional here - each kind has a sane default.
 */
export type TokenProfileOptions = Omit<ProfileOptions, "typ" | "maxTokenAge"> & {
	/** Defaults to 10m for access tokens, 30d for refresh tokens. */
	maxTokenAge?: number | string;
};

/**
 * An access-token profile: short-lived, audience-scoped to your API, and
 * pinned to `typ: "at+jwt"`. Verifies tokens presented by clients.
 */
export function accessTokenProfile(options: TokenProfileOptions): ExpectedJwtProfile {
	return defineProfile({
		...options,
		maxTokenAge: options.maxTokenAge ?? DEFAULT_ACCESS_MAX_AGE,
		typ: ACCESS_TOKEN_TYP,
	});
}

/**
 * A refresh-token profile: long-lived, audience-scoped to the *auth server*
 * (never the API), and pinned to `typ: "rt+jwt"`. Pass a `revocation` store -
 * a long-lived token you cannot revoke is a long-lived incident.
 */
export function refreshTokenProfile(options: TokenProfileOptions): ExpectedJwtProfile {
	return defineProfile({
		...options,
		maxTokenAge: options.maxTokenAge ?? DEFAULT_REFRESH_MAX_AGE,
		typ: REFRESH_TOKEN_TYP,
	});
}

/** A {@link SignJWT} builder pre-set to the access-token `typ` and a 1h cap. */
export function newAccessToken(): SignJWT {
	return new SignJWT(ACCESS_TOKEN_TYP, { maxLifetime: "1h" });
}

/**
 * A {@link SignJWT} builder pre-set to the refresh-token `typ`. The cap is
 * raised to 90d because that is the point of a refresh token - but the
 * lifetime you actually pass to `.expiresIn()` should be as short as your UX
 * tolerates, and the token should be revocable.
 */
export function newRefreshToken(): SignJWT {
	return new SignJWT(REFRESH_TOKEN_TYP, { maxLifetime: "90d" });
}
