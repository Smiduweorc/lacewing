/**
 * The one and only verification path (RFC 8725 §3.3).
 *
 * Order of operations, fail-fast, all-or-nothing:
 *   1. structural parse (length cap, strict base64url, strict UTF-8)
 *   2. header validation (allowlist, typ, kid hygiene, forbidden params)
 *   3. key resolution from the profile's key source
 *   4. signature verification
 *   5. claims validation
 *   6. custom claim validators
 *   7. revocation check - last, so unauthenticated input can never
 *      drive store lookups (LW-rev.3)
 *
 * There is no partial result and no decoded-but-unverified escape hatch
 * here; that lives, loudly branded, in `util/unsafe-decode.ts`.
 */

import { compactVerify } from "jose";
import {
	AlgorithmNotAllowed,
	JWTInvalid,
	JWTRevoked,
	MissingClaim,
	RevocationCheckFailed,
} from "../util/errors.js";
import { decodeBase64url } from "../lib/base64url.js";
import { decodeUTF8 } from "../lib/utf8.js";
import { parseJsonObject } from "../lib/json.js";
import { validateHeader } from "../lib/headers.js";
import { validateClaims } from "../lib/claims.js";
import { buildRevocationContext } from "../revocation/store.js";
import {
	isLacewingKey,
	type ExpectedJwtProfile,
	type JwtHeader,
	type JwtPayLoad,
	type ResolvedVerificationKey,
	type VerifiedJwt,
} from "../types.js";

// Bounded before any parsing so garbage can't allocate unboundedly.
const MAX_TOKEN_LENGTH = 16384;

function parseSegmentJson(bytes: Uint8Array, what: string): Record<string, unknown> {
	return parseJsonObject(decodeUTF8(bytes), what);
}

async function resolveKey(
	profile: ExpectedJwtProfile,
	header: JwtHeader
): Promise<ResolvedVerificationKey> {
	if (isLacewingKey(profile.keys)) {
		if ((profile.keys.algorithm as string) !== (header.alg as string)) {
			throw new AlgorithmNotAllowed(
				"Token algorithm does not match the profile's key"
			);
		}
		return { alg: header.alg, key: profile.keys.key };
	}
	return profile.keys.getVerificationKey(header, profile.alg);
}

/**
 * Verify a token against a profile. The returned {@link VerifiedJwt} is
 * the only way to obtain one - there is no backdoor.
 *
 * On any failure it throws a typed error ({@link JWTExpired},
 * {@link AlgorithmNotAllowed}, {@link JWTClaimValidationFailed}, ...) and yields
 * no partial result. There is no `decode()` and no `ignoreExpiration`.
 *
 * @example
 * ```ts
 * const profile = defineProfile({
 *   typ: "at+jwt",
 *   issuer: "https://auth.example.com",
 *   audience: "https://api.example.com",
 *   algorithms: ["EdDSA"],
 *   keys: createRemoteJWKSet("https://auth.example.com/jwks"),
 *   maxTokenAge: "10m",
 * });
 *
 * const { payload } = await jwtVerify(token, profile); // every check passed
 * ```
 */
export async function jwtVerify(
	token: string,
	profile: ExpectedJwtProfile
): Promise<VerifiedJwt> {
	if (typeof token !== "string" || token.length === 0) {
		throw new JWTInvalid("Token must be a non-empty string");
	}
	if (token.length > MAX_TOKEN_LENGTH) {
		throw new JWTInvalid("Token exceeds the maximum length");
	}
	const segments = token.split(".");
	if (segments.length !== 3) {
		throw new JWTInvalid("Token must have exactly three segments");
	}
	const [rawHeader, rawPayload, rawSignature] = segments as [string, string, string];
	if (rawHeader === "" || rawPayload === "" || rawSignature === "") {
		throw new JWTInvalid("Token has an empty segment");
	}

	// Strict decoding is authoritative: Lacewing's canonical base64url and
	// fatal UTF-8 run before jose ever sees the token, closing parser
	// differentials (§3.7 and the strictness attack vectors).
	const header = validateHeader(parseSegmentJson(decodeBase64url(rawHeader), "header"), profile);
	const payloadBytes = decodeBase64url(rawPayload);
	decodeBase64url(rawSignature);

	const resolved = await resolveKey(profile, header);
	try {
		await compactVerify(token, resolved.key as Parameters<typeof compactVerify>[1], {
			algorithms: [header.alg as string],
		});
	} catch (cause) {
		throw new JWTInvalid("Token signature verification failed", { cause });
	}

	const payload = parseSegmentJson(payloadBytes, "payload");
	await validateClaims(payload, profile);

	// Revocation last (LW-rev.3): only signed, claims-valid tokens ever
	// reach the store, so forged input can't probe or flood it.
	if (profile.revocation !== undefined) {
		if (typeof payload.jti !== "string") {
			throw new MissingClaim(
				"jti",
				"This profile has a revocation store but the token carries no jti"
			);
		}
		let revoked: boolean;
		try {
			revoked = await profile.revocation.isRevoked(buildRevocationContext(payload));
		} catch (cause) {
			if (profile.unsafeFailOpenOnRevocationError === true) {
				revoked = false;
			} else {
				throw new RevocationCheckFailed(
					"Revocation store errored - failing closed (LW-rev.4)",
					{ cause }
				);
			}
		}
		if (revoked) {
			throw new JWTRevoked("Token has been revoked");
		}
	}

	return { header, payload: payload as JwtPayLoad } as VerifiedJwt;
}
