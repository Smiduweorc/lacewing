/**
 * Human-friendly duration parsing: public APIs accept `900` (seconds) or
 * `"15m"`; everything internal works in branded {@link DurationSeconds}.
 */

import { toSeconds, type DurationSeconds } from "../types.js";

const DURATION = /^(\d{1,9})(s|m|h|d)$/;

const MULTIPLIER: Record<string, number> = {
	s: 1,
	m: 60,
	h: 3600,
	d: 86400,
};

export function parseDuration(value: number | string): DurationSeconds {
	if (typeof value === "number") {
		return toSeconds(value);
	}
	const match = DURATION.exec(value.trim());
	if (match === null) {
		throw new TypeError(
			`Invalid duration "${value}" - use seconds or "30s" / "15m" / "1h" / "7d"`
		);
	}
	const [, amount, unit] = match;
	return toSeconds(Number(amount) * (MULTIPLIER[unit as string] as number));
}
