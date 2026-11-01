/**
 * Revocation contract.
 *
 * A {@link RevocationStore} answers "has this token been revoked?" and is
 * consulted by `jwtVerify` *only after* signature and claims checks pass
 * (LW-rev.3), so unauthenticated input can never drive store lookups.
 * Store errors fail closed (LW-rev.4).
 *
 * The interface is shaped for async backends (Redis, a database): see
 * `MemoryRevocationStore` for the reference implementation and the
 * eviction contract - a revocation only needs to outlive its token.
 */

import { JWTError } from "../util/errors.js";
import { emit } from "../util/events.js";
import type { JwtPayLoad, TokenPolicy, TokenRevocationContext } from "../types.js";

export type { RevocationStore, TokenRevocationContext } from "../types.js";

/** Extract the revocation-relevant slice of a verified payload. */
export function buildRevocationContext(
	payload: Record<string, unknown>
): TokenRevocationContext {
	const { jti, sub, sid, exp, iat } = payload as JwtPayLoad & { sid?: unknown };
	const context: TokenRevocationContext = { exp, iat };
	if (typeof jti === "string") context.jti = jti;
	if (typeof sub === "string") context.sub = sub;
	if (typeof sid === "string") context.sid = sid;
	return context;
}

/**
 * The revocation step of `jwtVerify` and `jwtDecrypt`, run only after the
 * signature (or AEAD) and every claim check passed (LW-rev.3). A store that
 * throws fails closed (LW-rev.4) unless the profile set
 * `unsafeFailOpenOnRevocationError`, in which case the error is reported as a
 * `revocation-fail-open` event rather than lost.
 */
export async function assertNotRevoked(payload: Record<string, unknown>, policy: TokenPolicy): Promise<void> {
	if (policy.revocation === undefined) return;
	if (typeof payload.jti !== "string") {
		throw new JWTError(
			"MISSING_CLAIM",
			"This profile has a revocation store but the token carries no jti",
			{ claim: "jti" }
		);
	}
	let revoked: boolean;
	try {
		revoked = await policy.revocation.isRevoked(buildRevocationContext(payload));
	} catch (cause) {
		if (policy.unsafeFailOpenOnRevocationError !== true) {
			throw new JWTError(
				"REVOCATION_CHECK_FAILED",
				"Revocation store errored - failing closed (LW-rev.4)",
				{ cause }
			);
		}
		emit(policy.onEvent, { type: "revocation-fail-open", cause });
		revoked = false;
	}
	if (revoked) {
		throw new JWTError("JWT_REVOKED", "Token has been revoked");
	}
}
