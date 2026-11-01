/**
 * The swappable clock. Every time Lacewing reads comes from a `now` option
 * (milliseconds, like `Date.now`), so tests and callers drive time instead of
 * patching globals. The default is `Date.now`, read at call time so a mocked
 * global still applies.
 */

export type Clock = () => number;

const systemClock: Clock = () => Date.now();

export function requireClock(value: unknown, owner: string): Clock {
	if (value === undefined) return systemClock;
	if (typeof value !== "function") {
		throw new TypeError(`${owner} now must be a function returning milliseconds`);
	}
	const clock = value as () => unknown;
	// Every comparison with NaN is false, so a clock returning NaN would make
	// every token unexpired. Checked on each read, not once: a clock can break
	// after construction.
	return () => {
		const ms = clock();
		if (typeof ms !== "number" || !Number.isFinite(ms)) {
			throw new TypeError(`${owner} now returned ${String(ms)}, not a finite number of milliseconds`);
		}
		return ms;
	};
}

/** Whole unix seconds, as `iat`, `exp` and `nbf` count them. */
export function nowSeconds(clock: Clock): number {
	return Math.floor(clock() / 1000);
}
