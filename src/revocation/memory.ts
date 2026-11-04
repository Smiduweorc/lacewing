/**
 * In-memory {@link RevocationStore}.
 *
 * Revokes one token by `jti`, or every token a subject (`sub`) or session
 * (`sid`) holds at the moment of revocation. Entries evict once the moment
 * passes after which no token they cover can still be valid: a revocation
 * only needs to outlive the tokens it revokes.
 *
 * One process only: twenty replicas are twenty stores, and a revocation made
 * on one is invisible to the others. Fleets implement {@link RevocationStore}
 * over shared state (a Redis key with `PX` set to the remaining lifetime, a
 * database row with an expiry column).
 */

import { nowSeconds, requireClock, type Clock } from "../util/clock.js";
import type { RevocationStore, TokenRevocationContext } from "../types.js";

const SWEEP_INTERVAL_OPS = 256;

/** A subject or session cut-off: tokens issued at or before `revokedAt` are revoked. */
interface CutOff {
	revokedAt: number;
	until: number;
}

function toSeconds(value: number | Date, field: string): number {
	const seconds = value instanceof Date ? Math.ceil(value.getTime() / 1000) : value;
	if (typeof seconds !== "number" || !Number.isFinite(seconds)) {
		throw new TypeError(`${field} must be unix seconds or a Date`);
	}
	return seconds;
}

function requireId(value: unknown, method: string, claim: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new TypeError(`${method}() requires the token's ${claim}`);
	}
	return value;
}

export interface MemoryRevocationStoreOptions {
	/** Clock in milliseconds, default `Date.now`. Give it the profile's clock. */
	now?: Clock;
}

export class MemoryRevocationStore implements RevocationStore {
	readonly #now: Clock;
	/** jti -> token expiry (unix seconds). */
	readonly #tokens = new Map<string, number>();
	readonly #subjects = new Map<string, CutOff>();
	readonly #sessions = new Map<string, CutOff>();
	#opsSinceSweep = 0;

	constructor(options: MemoryRevocationStoreOptions = {}) {
		this.#now = requireClock(options.now, "MemoryRevocationStore");
	}

	/**
	 * Revoke one token by its `jti`. `expiresAt` is the token's `exp` (unix
	 * seconds or Date); the entry is dropped after that moment.
	 */
	revoke(jti: string, expiresAt: number | Date): void {
		requireId(jti, "revoke", "jti");
		const exp = toSeconds(expiresAt, "revoke() expiresAt");
		this.#tokens.set(jti, Math.max(exp, this.#tokens.get(jti) ?? exp));
		this.#maybeSweep();
	}

	/**
	 * Revoke every token for `sub` issued up to now (`iat` at or before this
	 * second), e.g. on "log out everywhere" or a password change. A token issued
	 * later in the same second is revoked too: telling them apart needs a
	 * finer clock than `iat` has, so it fails closed.
	 *
	 * `until` is the latest moment any covered token can still verify: now
	 * plus your longest `maxTokenAge` for this subject's tokens. Shorter, and a
	 * token outlives its revocation.
	 */
	revokeSubject(sub: string, until: number | Date): void {
		this.#cutOff(this.#subjects, requireId(sub, "revokeSubject", "sub"), until, "revokeSubject() until");
	}

	/** Revoke every token for session `sid` issued up to now. `until` as for {@link revokeSubject}. */
	revokeSession(sid: string, until: number | Date): void {
		this.#cutOff(this.#sessions, requireId(sid, "revokeSession", "sid"), until, "revokeSession() until");
	}

	async isRevoked(context: TokenRevocationContext): Promise<boolean> {
		this.#maybeSweep();
		const now = this.#nowSeconds();
		if (context.jti !== undefined) {
			const exp = this.#tokens.get(context.jti);
			if (exp !== undefined && exp <= now) {
				this.#tokens.delete(context.jti);
			} else if (exp !== undefined) {
				return true;
			}
		}
		return (
			this.#coveredBy(this.#subjects, context.sub, context.iat, now) ||
			this.#coveredBy(this.#sessions, context.sid, context.iat, now)
		);
	}

	/** Number of live revocations of all three kinds (expired entries may linger until a sweep). */
	get size(): number {
		return this.#tokens.size + this.#subjects.size + this.#sessions.size;
	}

	#cutOff(map: Map<string, CutOff>, id: string, until: number | Date, field: string): void {
		const untilSeconds = toSeconds(until, field);
		const previous = map.get(id);
		map.set(id, {
			revokedAt: this.#nowSeconds(),
			until: Math.max(untilSeconds, previous?.until ?? untilSeconds),
		});
		this.#maybeSweep();
	}

	#coveredBy(map: Map<string, CutOff>, id: string | undefined, iat: number, now: number): boolean {
		if (id === undefined) {
			return false;
		}
		const cutOff = map.get(id);
		if (cutOff === undefined) {
			return false;
		}
		if (cutOff.until <= now) {
			map.delete(id);
			return false;
		}
		return iat <= cutOff.revokedAt;
	}

	#nowSeconds(): number {
		return nowSeconds(this.#now);
	}

	#maybeSweep(): void {
		if (++this.#opsSinceSweep < SWEEP_INTERVAL_OPS) {
			return;
		}
		this.#opsSinceSweep = 0;
		const now = this.#nowSeconds();
		for (const [jti, exp] of this.#tokens) {
			if (exp <= now) this.#tokens.delete(jti);
		}
		for (const map of [this.#subjects, this.#sessions]) {
			for (const [id, cutOff] of map) {
				if (cutOff.until <= now) map.delete(id);
			}
		}
	}
}
