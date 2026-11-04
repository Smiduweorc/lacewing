/**
 * The part of a profile that verification (`defineProfile`) and decryption
 * (`defineDecryptionProfile`) share: who issued the token, who it is for,
 * how old it may be, which extra checks run, and how revocation behaves.
 * Both factories validate it here, once, so the two cannot drift apart on a
 * cap or an `unsafe*` flag.
 */

import { parseDuration } from "../lib/duration.js";
import { requireClock, type Clock } from "../util/clock.js";
import { requireOnEvent, type OnEvent } from "../util/events.js";
import { toSeconds, type RevocationStore, type TokenPolicy, type ValidateClaim } from "../types.js";

const DEFAULT_CLOCK_SKEW_SECONDS = 5;
const MAX_CLOCK_SKEW_SECONDS = 30;
const UNSAFE_MAX_CLOCK_SKEW_SECONDS = 120;
const MAX_TOKEN_AGE_SECONDS = 30 * 24 * 60 * 60;

export interface PolicyOptions {
	/** Expected token type, e.g. `"at+jwt"` (§3.11). */
	typ: string;
	/** The one issuer this profile trusts (§3.8). */
	issuer: string;
	/** The audience value that must appear in the token (§3.9). */
	audience: string;
	/**
	 * Maximum accepted token age (`now - iat`), independent of `exp`, up to
	 * 30 days. How long a token you issued may keep working here.
	 */
	maxTokenAge: number | string;
	/** Ugly on purpose: allow `maxTokenAge` above 30 days. */
	unsafeAllowLongTokenAge?: boolean;
	/**
	 * Optional cap on the token's *declared* lifetime (`exp - iat`). Where
	 * `maxTokenAge` bounds how long a token stays usable, this refuses a token
	 * whose issuer claimed an implausible span at all - a misissuance signal.
	 */
	maxTokenLifetime?: number | string;
	/** Allowed clock skew, default 5s, capped at 30s (120s with `unsafeAllowLargeClockSkew`). */
	maxClockSkew?: number | string;
	/** Ugly on purpose: allow `maxClockSkew` above 30s, up to 120s. */
	unsafeAllowLargeClockSkew?: boolean;
	/** Optional revocation store - its absence is a visible choice. */
	revocation?: RevocationStore;
	/**
	 * Ugly on purpose: extra per-claim predicates, run after all standard
	 * checks. Arbitrary code in the accept path - you own its correctness.
	 */
	unsafeClaimValidators?: Record<string, ValidateClaim>;
	/** Pin the expected `sub` (§3.8.2). */
	subject?: string;
	/** Ugly on purpose: accept tokens when the revocation store errors (LW-rev.4). */
	unsafeFailOpenOnRevocationError?: boolean;
	/** Receives what Lacewing reports instead of logging; see `LacewingEvent`. */
	onEvent?: OnEvent;
	/** Clock in milliseconds, default `Date.now`. */
	now?: Clock;
}

function requireNonEmptyString(value: unknown, field: string, label: string): string {
	if (typeof value !== "string" || value.length === 0) {
		throw new TypeError(`${label} "${field}" must be a non-empty string`);
	}
	return value;
}

/** Validate the shared options; `label` names the factory in error messages. */
export function buildPolicy(options: PolicyOptions, label: string): TokenPolicy {
	const typ = requireNonEmptyString(options.typ, "typ", label);
	const iss = requireNonEmptyString(options.issuer, "issuer", label);
	const aud = requireNonEmptyString(options.audience, "audience", label);

	const maxTokenAge = parseDuration(options.maxTokenAge);
	if (maxTokenAge < 1) {
		throw new TypeError(`${label} maxTokenAge must be at least one second`);
	}
	if (maxTokenAge > MAX_TOKEN_AGE_SECONDS && options.unsafeAllowLongTokenAge !== true) {
		throw new TypeError(
			`${label} maxTokenAge is capped at 30 days - set unsafeAllowLongTokenAge to go beyond`
		);
	}
	const maxClockSkew = parseDuration(options.maxClockSkew ?? DEFAULT_CLOCK_SKEW_SECONDS);
	const skewCap =
		options.unsafeAllowLargeClockSkew === true ? UNSAFE_MAX_CLOCK_SKEW_SECONDS : MAX_CLOCK_SKEW_SECONDS;
	if (maxClockSkew > skewCap) {
		throw new TypeError(
			skewCap === MAX_CLOCK_SKEW_SECONDS
				? `${label} maxClockSkew is capped at ${MAX_CLOCK_SKEW_SECONDS} seconds - set unsafeAllowLargeClockSkew to allow up to ${UNSAFE_MAX_CLOCK_SKEW_SECONDS}`
				: `${label} maxClockSkew is capped at ${UNSAFE_MAX_CLOCK_SKEW_SECONDS} seconds`
		);
	}
	const maxTokenLifetime =
		options.maxTokenLifetime === undefined ? undefined : parseDuration(options.maxTokenLifetime);
	if (maxTokenLifetime !== undefined && maxTokenLifetime < 1) {
		throw new TypeError(`${label} maxTokenLifetime must be at least one second`);
	}

	if (options.revocation !== undefined && typeof options.revocation.isRevoked !== "function") {
		throw new TypeError(`${label} revocation store must implement isRevoked()`);
	}
	if (options.unsafeClaimValidators !== undefined) {
		for (const [claim, validator] of Object.entries(options.unsafeClaimValidators)) {
			if (typeof validator !== "function") {
				throw new TypeError(`Claim validator for "${claim}" must be a function`);
			}
		}
	}
	if (options.subject !== undefined) {
		requireNonEmptyString(options.subject, "subject", label);
	}
	const onEvent = requireOnEvent(options.onEvent, label);

	const policy: TokenPolicy = {
		typ,
		iss,
		aud,
		maxTokenAge: toSeconds(maxTokenAge),
		maxClockSkew: toSeconds(maxClockSkew),
		now: requireClock(options.now, label),
	};
	if (maxTokenLifetime !== undefined) policy.maxTokenLifetime = toSeconds(maxTokenLifetime);
	if (options.revocation !== undefined) policy.revocation = options.revocation;
	if (options.unsafeClaimValidators !== undefined) {
		policy.claimValidators = { ...options.unsafeClaimValidators };
	}
	if (options.subject !== undefined) policy.subject = options.subject;
	if (options.unsafeFailOpenOnRevocationError === true) {
		policy.unsafeFailOpenOnRevocationError = true;
	}
	if (onEvent !== undefined) policy.onEvent = onEvent;
	return policy;
}
