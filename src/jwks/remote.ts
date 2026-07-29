/**
 * Remote JWK Sets with caching and rotation.
 *
 * - HTTPS-only URLs; redirects are never followed
 * - caches with a configurable TTL and honors `Cache-Control: max-age`
 * - cooldown between refetches (no attacker-driven fetch storms)
 * - refetches once on unknown `kid` (key rotation), then fails closed
 * - stale keys keep serving a *bounded* while after the endpoint starts
 *   failing, then verification fails closed (LW-jwks.2)
 * - the response byte budget is enforced while reading, not after
 * - symmetric (`oct`) entries are refused: a JWKS endpoint is public
 * - entries outside the registry are dropped
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
const DEFAULT_STALE_WHILE_ERROR_SECONDS = 3600;
const MAX_CACHE_TTL_SECONDS = 86400;
const MAX_RESPONSE_BYTES = 1_048_576;

export interface RemoteJWKSetOptions {
	/** Cache lifetime when the response has no usable Cache-Control (default 300s). */
	cacheTtlSeconds?: number;
	/** Minimum interval between fetch attempts (default 30s). */
	cooldownSeconds?: number;
	/** Fetch timeout (default 5000ms). */
	timeoutMs?: number;
	/**
	 * How long previously-good keys may keep serving once the endpoint starts
	 * failing (default 3600s). Bounded on purpose: a key rotated out *because
	 * it was compromised* must not stay trusted for as long as an attacker can
	 * keep the endpoint unreachable. `0` disables stale serving entirely.
	 */
	staleWhileErrorSeconds?: number;
	/** Fetch implementation override - intended for tests. */
	fetch?: typeof fetch;
}

function cacheTtlFrom(response: Response, fallbackSeconds: number): number {
	const cacheControl = response.headers.get("cache-control");
	const match = cacheControl === null ? null : /max-age\s*=\s*(\d{1,8})/.exec(cacheControl);
	const ttl = match === null ? fallbackSeconds : Number(match[1]);
	return Math.min(Math.max(ttl, 0), MAX_CACHE_TTL_SECONDS);
}

function nonNegativeSeconds(value: number | undefined, fallback: number, field: string): number {
	if (value === undefined) return fallback;
	if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
		throw new TypeError(`JWKS ${field} must be a non-negative number of seconds`);
	}
	return value;
}

/**
 * Read a response body under a hard byte budget. The cap is checked against
 * `Content-Length` up front and again on every chunk, so an oversized body is
 * abandoned mid-flight instead of being buffered in full and measured
 * afterwards.
 */
async function readCappedText(response: Response, maxBytes: number): Promise<string> {
	const declared = response.headers.get("content-length");
	if (declared !== null) {
		const length = Number(declared);
		if (Number.isFinite(length) && length > maxBytes) {
			throw new JWKSFetchFailed("JWKS response exceeds the size cap");
		}
	}
	const body = response.body;
	if (body === null || body === undefined) {
		return "";
	}
	const reader = body.getReader();
	const decoder = new TextDecoder();
	let received = 0;
	let text = "";
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			received += value.byteLength;
			if (received > maxBytes) {
				throw new JWKSFetchFailed("JWKS response exceeds the size cap");
			}
			text += decoder.decode(value, { stream: true });
		}
	} finally {
		// Abandons the transfer when we bailed out early; a no-op once drained.
		await reader.cancel().catch(() => undefined);
	}
	return text + decoder.decode();
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
	const staleWhileErrorMs =
		nonNegativeSeconds(
			options.staleWhileErrorSeconds,
			DEFAULT_STALE_WHILE_ERROR_SECONDS,
			"staleWhileErrorSeconds"
		) * 1000;

	let cachedKeys: StaticJWK[] | undefined;
	let expiresAtMs = 0;
	let lastAttemptMs = 0;
	let lastSuccessMs = 0;
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
		const body = await readCappedText(response, MAX_RESPONSE_BYTES);
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
		lastSuccessMs = Date.now();
		expiresAtMs = lastSuccessMs + cacheTtlFrom(response, fallbackTtl) * 1000;
	}

	function refresh(): Promise<void> {
		// Concurrent verifications share one fetch.
		inflight ??= fetchJwks().finally(() => {
			inflight = undefined;
		});
		return inflight;
	}

	/**
	 * May we still serve the last good keys, given how long ago they were good?
	 * Strict `<` so that `staleWhileErrorSeconds: 0` disables stale serving
	 * outright rather than granting the millisecond the keys were fetched in.
	 */
	function staleServable(): boolean {
		return cachedKeys !== undefined && Date.now() - lastSuccessMs < staleWhileErrorMs;
	}

	async function ensureFresh(): Promise<void> {
		const now = Date.now();
		if (cachedKeys !== undefined && now < expiresAtMs) {
			return;
		}
		if (now - lastAttemptMs < cooldownMs && inflight === undefined) {
			// In cooldown: serve stale keys if they are still inside the
			// stale-while-error window, otherwise fail closed.
			if (staleServable()) return;
			throw new JWKSFetchFailed(
				cachedKeys === undefined
					? "JWKS fetch is cooling down after a recent failure"
					: "JWKS keys are stale beyond the stale-while-error window"
			);
		}
		try {
			await refresh();
		} catch (error) {
			// Stale-while-error: an unreachable endpoint must not take down
			// verification immediately - but only for a bounded window, so
			// rotated-out keys cannot stay trusted indefinitely (LW-jwks.2).
			if (!staleServable()) throw error;
		}
	}

	return {
		async getVerificationKey(header: JwtHeader): Promise<ResolvedVerificationKey> {
			await ensureFresh();
			try {
				return await resolveFromJwks(cachedKeys as StaticJWK[], header, {
					allowSymmetric: false,
				});
			} catch (error) {
				// Unknown kid may mean the signer rotated keys: refetch once
				// (respecting the cooldown), then fail closed.
				const canRetry =
					error instanceof JWKSNoMatchingKey &&
					Date.now() - lastAttemptMs >= cooldownMs;
				if (!canRetry) throw error;
				await refresh();
				return resolveFromJwks(cachedKeys as StaticJWK[], header, {
					allowSymmetric: false,
				});
			}
		},
	};
}
