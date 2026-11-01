/**
 * What Lacewing reports instead of logging. A library does not own the
 * terminal: things a caller should know about but that are not refusals
 * (stale keys serving through an outage, a revocation store error that a
 * fail-open profile let through) arrive here as plain values, and the caller
 * decides whether they become logs, metrics or nothing.
 */

/**
 * | `type` | When |
 * | --- | --- |
 * | `jwks-refresh-failed` | A remote JWKS fetch failed; `cause` is what it threw. |
 * | `jwks-stale-serving` | A verification used keys past their cache lifetime because the endpoint is failing. |
 * | `revocation-fail-open` | The revocation store threw and `unsafeFailOpenOnRevocationError` accepted the token anyway. |
 */
export type LacewingEvent =
	| { type: "jwks-refresh-failed"; url: string; cause: unknown }
	| { type: "jwks-stale-serving"; url: string; staleForSeconds: number }
	| { type: "revocation-fail-open"; cause: unknown };

/** Receives {@link LacewingEvent}s. Whatever it throws is ignored. */
export type OnEvent = (event: LacewingEvent) => void;

export function requireOnEvent(value: unknown, owner: string): OnEvent | undefined {
	if (value !== undefined && typeof value !== "function") {
		throw new TypeError(`${owner} onEvent must be a function`);
	}
	return value as OnEvent | undefined;
}

export function emit(onEvent: OnEvent | undefined, event: LacewingEvent): void {
	if (onEvent === undefined) return;
	try {
		onEvent(event);
	} catch {
		// A listener is the caller's reporting, not part of verification: a
		// broken logger must not turn a valid token into a refused one.
	}
}
