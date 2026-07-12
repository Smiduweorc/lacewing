/**
 * Remote JWK Sets with caching and rotation.
 *
 * - HTTPS-only URLs; redirects are never followed
 * - caches with a configurable TTL and honors `Cache-Control: max-age`
 * - cooldown between refetches (no attacker-driven fetch storms)
 * - refetches once on unknown `kid` (key rotation), then fails closed
 * - response size is capped; entries outside the registry are dropped
 */

import { JWKSFetchFailed, JWKSNoMatchingKey } from "../util/errors.js";
import { resolveFromJwks, validateJwksShape } from "./local.js";
import type {
	JwtHeader,
	KeySource,
	ResolvedVerificationKey,
	StaticJWK,
} from "../types.js";

const DEFAULT_CACHE_TTL_SECONDS = 300;
const DEFAULT_COOLDOWN_SECONDS = 30;
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_CACHE_TTL_SECONDS = 86400;
const MAX_RESPONSE_BYTES = 1_048_576;

export interface RemoteJWKSetOptions {
	/** Cache lifetime when the response has no usable Cache-Control (default 300s). */
	cacheTtlSeconds?: number;
	/** Minimum interval between fetch attempts (default 30s). */
	cooldownSeconds?: number;
	/** Fetch timeout (default 5000ms). */
	timeoutMs?: number;
	/** Fetch implementation override - intended for tests. */
	fetch?: typeof fetch;
}

function cacheTtlFrom(response: Response, fallbackSeconds: number): number {
	const cacheControl = response.headers.get("cache-control");
	const match = cacheControl === null ? null : /max-age\s*=\s*(\d{1,8})/.exec(cacheControl);
	const ttl = match === null ? fallbackSeconds : Number(match[1]);
	return Math.min(Math.max(ttl, 0), MAX_CACHE_TTL_SECONDS);
}

/** Create a {@link KeySource} that fetches and caches a remote JWKS. */
export function createRemoteJWKSet(
	url: URL | string,
	options: RemoteJWKSetOptions = {}
): KeySource {
	const jwksUrl = new URL(url);
	if (jwksUrl.protocol !== "https:") {
		throw new TypeError("JWKS URLs must use https");
	}
	const fetchImpl = options.fetch ?? fetch;
	const fallbackTtl = options.cacheTtlSeconds ?? DEFAULT_CACHE_TTL_SECONDS;
	const cooldownMs = (options.cooldownSeconds ?? DEFAULT_COOLDOWN_SECONDS) * 1000;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	let cachedKeys: StaticJWK[] | undefined;
	let expiresAtMs = 0;
	let lastAttemptMs = 0;
	let inflight: Promise<void> | undefined;

	async function fetchJwks(): Promise<void> {
		lastAttemptMs = Date.now();
		let response: Response;
		try {
			response = await fetchImpl(jwksUrl, {
				redirect: "error",
				headers: { accept: "application/jwk-set+json, application/json" },
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch (cause) {
			throw new JWKSFetchFailed("JWKS endpoint could not be reached", { cause });
		}
		if (!response.ok) {
			throw new JWKSFetchFailed(`JWKS endpoint responded with status ${response.status}`);
		}
		const body = await response.text();
		if (body.length > MAX_RESPONSE_BYTES) {
			throw new JWKSFetchFailed("JWKS response exceeds the size cap");
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(body);
		} catch (cause) {
			throw new JWKSFetchFailed("JWKS response is not valid JSON", { cause });
		}
		let keys: StaticJWK[];
		try {
			keys = validateJwksShape(parsed);
		} catch (cause) {
			throw new JWKSFetchFailed("JWKS response is not a valid key set", { cause });
		}
		cachedKeys = keys;
		expiresAtMs = Date.now() + cacheTtlFrom(response, fallbackTtl) * 1000;
	}

	function refresh(): Promise<void> {
		// Concurrent verifications share one fetch.
		inflight ??= fetchJwks().finally(() => {
			inflight = undefined;
		});
		return inflight;
	}

	async function ensureFresh(): Promise<void> {
		const now = Date.now();
		if (cachedKeys !== undefined && now < expiresAtMs) {
			return;
		}
		if (now - lastAttemptMs < cooldownMs && inflight === undefined) {
			// In cooldown: serve stale keys if we have them, else fail.
			if (cachedKeys !== undefined) return;
			throw new JWKSFetchFailed("JWKS fetch is cooling down after a recent failure");
		}
		try {
			await refresh();
		} catch (error) {
			// Stale-while-error: an unreachable endpoint must not take down
			// verification while we still hold previously good keys.
			if (cachedKeys === undefined) throw error;
		}
	}

	return {
		async getVerificationKey(header: JwtHeader): Promise<ResolvedVerificationKey> {
			await ensureFresh();
			try {
				return await resolveFromJwks(cachedKeys as StaticJWK[], header);
			} catch (error) {
				// Unknown kid may mean the signer rotated keys: refetch once
				// (respecting the cooldown), then fail closed.
				const canRetry =
					error instanceof JWKSNoMatchingKey &&
					Date.now() - lastAttemptMs >= cooldownMs;
				if (!canRetry) throw error;
				await refresh();
				return resolveFromJwks(cachedKeys as StaticJWK[], header);
			}
		},
	};
}
