/**
 * In-memory {@link RevocationStore}.
 *
 * Entries evict once the revoked token's `exp` passes: a revocation only
 * needs to outlive the token it revokes. Suitable for single-process
 * deployments and tests; multi-instance services want a shared backend
 * (Redis/DB) implementing the same interface.
 */

import type { RevocationStore, TokenRevocationContext } from "../types.js";

const SWEEP_INTERVAL_OPS = 256;

export class MemoryRevocationStore implements RevocationStore {
	/** jti -> token expiry (unix seconds). */
	readonly #revoked = new Map<string, number>();
	#opsSinceSweep = 0;

	/**
	 * Revoke a token by its `jti`. `expiresAt` is the token's `exp`
	 * (unix seconds or Date) - the entry is dropped after that moment.
	 */
	revoke(jti: string, expiresAt: number | Date): void {
		if (typeof jti !== "string" || jti.length === 0) {
			throw new TypeError("revoke() requires the token's jti");
		}
		const expSeconds =
			expiresAt instanceof Date ? Math.ceil(expiresAt.getTime() / 1000) : expiresAt;
		if (!Number.isFinite(expSeconds)) {
			throw new TypeError("revoke() requires the token's expiry");
		}
		this.#revoked.set(jti, expSeconds);
		this.#maybeSweep();
	}

	async isRevoked(context: TokenRevocationContext): Promise<boolean> {
		this.#maybeSweep();
		if (context.jti === undefined) {
			return false;
		}
		const exp = this.#revoked.get(context.jti);
		if (exp === undefined) {
			return false;
		}
		if (exp <= this.#nowSeconds()) {
			this.#revoked.delete(context.jti);
			return false;
		}
		return true;
	}

	async isAnyRevoked(contexts: TokenRevocationContext[]): Promise<boolean[]> {
		return Promise.all(contexts.map((context) => this.isRevoked(context)));
	}

	/** Number of live revocations (expired entries may linger until a sweep). */
	get size(): number {
		return this.#revoked.size;
	}

	#nowSeconds(): number {
		return Math.floor(Date.now() / 1000);
	}

	#maybeSweep(): void {
		if (++this.#opsSinceSweep < SWEEP_INTERVAL_OPS) {
			return;
		}
		this.#opsSinceSweep = 0;
		const now = this.#nowSeconds();
		for (const [jti, exp] of this.#revoked) {
			if (exp <= now) {
				this.#revoked.delete(jti);
			}
		}
	}
}
