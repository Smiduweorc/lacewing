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
 * - entries for algorithms Lacewing has no descriptor for are dropped
 */

import { JWTError } from "../util/errors.js";
import { resolveFromJwks, validateJwksShape } from "./local.js";
import { vouchForKeySource } from "./trusted.js";
import type { AlgorithmInfo } from "../lib/algorithms.js";
import type { JwtHeader, KeySource, ResolvedVerificationKey, StaticJWK } from "../types.js";

const DEFAULT_STALE_WHILE_ERROR_SECONDS = 3600;
const MAX_CACHE_TTL_SECONDS = 86400;
const MAX_COOLDOWN_SECONDS = 86400;
const MAX_STALE_WHILE_ERROR_SECONDS = 86400;
const MAX_RESPONSE_BYTES = 1_048_576;

export interface RemoteJWKSetOptions {
	/**
	 * How long fetched keys are trusted when the response sends no
	 * `Cache-Control: max-age`, in seconds, 0 to 86400. This is how long a key
	 * your issuer removed from the set stays trusted here: pick it from how
	 * fast you need a rotation to take effect, not from how often you want to
	 * fetch. A `max-age` on the response wins, capped at 86400.
	 */
	cacheTtlSeconds: number;
	/**
	 * Minimum gap between fetch attempts, in seconds, 1 to 86400. A token with
	 * an unknown `kid` triggers a refetch, so this is how often a stranger can
	 * make you call your issuer. Shorter than your issuer's rotation overlap,
	 * or a freshly rotated key is refused until the cooldown ends.
	 */
	cooldownSeconds: number;
	/**
	 * How long one fetch may take before it is abandoned, in milliseconds.
	 * Verification waits this long on a cold or rotating cache, so it is
	 * part of your request latency budget.
	 */
	timeoutMs: number;
	/**
	 * How long the last good keys keep serving after their cache lifetime
	 * ends while the endpoint is failing, in seconds (default 3600, at most
	 * 86400). Bounded on purpose: a key rotated out *because it was
	 * compromised* must not stay trusted for as long as an attacker can keep
	 * the endpoint unreachable. `0` disables stale serving entirely.
	 */
	staleWhileErrorSeconds?: number;
	/**
	 * Fetch implementation to use instead of the global `fetch`. Whatever it
	 * throws reaches the caller unchanged, so a failure in your own transport
	 * stays distinguishable from a Lacewing refusal; only a failure of the
	 * global `fetch` becomes a `JWKS_FETCH_FAILED` error.
	 */
	fetch?: typeof fetch;
}

function cacheTtlFrom(response: Response, fallbackSeconds: number): number {
	const cacheControl = response.headers.get("cache-control");
	const match = cacheControl === null ? null : /max-age\s*=\s*(\d{1,8})/.exec(cacheControl);
	const ttl = match === null ? fallbackSeconds : Number(match[1]);
	return Math.min(Math.max(ttl, 0), MAX_CACHE_TTL_SECONDS);
}

function numberInRange(value: unknown, min: number, max: number, field: string, unit: string): number {
	if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max) {
		throw new TypeError(`JWKS ${field} is required: a number of ${unit} from ${min} to ${max}`);
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
			throw new JWTError("JWKS_FETCH_FAILED", "JWKS response exceeds the size cap");
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
				throw new JWTError("JWKS_FETCH_FAILED", "JWKS response exceeds the size cap");
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
	options: RemoteJWKSetOptions
): KeySource {
	const jwksUrl = new URL(url);
	if (jwksUrl.protocol !== "https:") {
		throw new TypeError("JWKS URLs must use https");
	}
	if (typeof options !== "object" || options === null) {
		throw new TypeError("createRemoteJWKSet needs cacheTtlSeconds, cooldownSeconds and timeoutMs");
	}
	const callerFetch = options.fetch;
	const fallbackTtl = numberInRange(options.cacheTtlSeconds, 0, MAX_CACHE_TTL_SECONDS, "cacheTtlSeconds", "seconds");
	const cooldownMs =
		numberInRange(options.cooldownSeconds, 1, MAX_COOLDOWN_SECONDS, "cooldownSeconds", "seconds") * 1000;
	const timeoutMs = numberInRange(options.timeoutMs, 1, 2 ** 31 - 1, "timeoutMs", "milliseconds");
	const staleWhileErrorMs =
		numberInRange(
			options.staleWhileErrorSeconds ?? DEFAULT_STALE_WHILE_ERROR_SECONDS,
			0,
			MAX_STALE_WHILE_ERROR_SECONDS,
			"staleWhileErrorSeconds",
			"seconds"
		) * 1000;

	let cachedKeys: StaticJWK[] | undefined;
	let expiresAtMs = 0;
	let lastAttemptMs = 0;
	let inflight: Promise<void> | undefined;

	async function fetchJwks(): Promise<void> {
		lastAttemptMs = Date.now();
		const init: RequestInit = {
			redirect: "error",
			headers: { accept: "application/jwk-set+json, application/json" },
			signal: AbortSignal.timeout(timeoutMs),
		};
		let response: Response;
		if (callerFetch !== undefined) {
			response = await callerFetch(jwksUrl, init);
		} else {
			try {
				response = await fetch(jwksUrl, init);
			} catch (cause) {
				throw new JWTError(
					"JWKS_FETCH_FAILED",
					"JWKS endpoint could not be reached",
					{ cause }
				);
			}
		}
		if (!response.ok) {
			throw new JWTError(
				"JWKS_FETCH_FAILED",
				`JWKS endpoint responded with status ${response.status}`
			);
		}
		const body = await readCappedText(response, MAX_RESPONSE_BYTES);
		let parsed: unknown;
		try {
			parsed = JSON.parse(body);
		} catch (cause) {
			throw new JWTError("JWKS_FETCH_FAILED", "JWKS response is not valid JSON", { cause });
		}
		let keys: StaticJWK[];
		try {
			keys = validateJwksShape(parsed);
		} catch (cause) {
			throw new JWTError(
				"JWKS_FETCH_FAILED",
				"JWKS response is not a valid key set",
				{ cause }
			);
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

	/**
	 * May we still serve the last good keys? The window opens when their cache
	 * lifetime ends, not when they were fetched: measured from the fetch, a
	 * `max-age` as long as the window left no stale time at all. Strict `<` so
	 * that `staleWhileErrorSeconds: 0` disables stale serving outright.
	 */
	function staleServable(): boolean {
		return cachedKeys !== undefined && Date.now() - expiresAtMs < staleWhileErrorMs;
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
			throw new JWTError(
				"JWKS_FETCH_FAILED",
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

	return vouchForKeySource({
		async getVerificationKey(
			header: JwtHeader,
			allowedAlgorithms: readonly AlgorithmInfo[]
		): Promise<ResolvedVerificationKey> {
			await ensureFresh();
			try {
				return await resolveFromJwks(cachedKeys as StaticJWK[], header, allowedAlgorithms, {
					allowSymmetric: false,
				});
			} catch (error) {
				// Unknown kid may mean the signer rotated keys: refetch once
				// (respecting the cooldown), then fail closed.
				const canRetry =
					error instanceof JWTError &&
					error.code === "JWKS_NO_MATCHING_KEY" &&
					Date.now() - lastAttemptMs >= cooldownMs;
				if (!canRetry) throw error;
				await refresh();
				return resolveFromJwks(cachedKeys as StaticJWK[], header, allowedAlgorithms, {
					allowSymmetric: false,
				});
			}
		},
	});
}
