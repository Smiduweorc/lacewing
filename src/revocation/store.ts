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

import type { JwtPayLoad, TokenRevocationContext } from "../types.js";

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
