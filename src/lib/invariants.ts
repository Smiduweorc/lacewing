/** Internal assertion helpers. */

/** Throw if `condition` is false. For states that must be impossible. */
export function invariant(condition: unknown, message: string): asserts condition {
	if (!condition) {
		throw new Error(`Invariant violation: ${message}`);
	}
}

/** Exhaustiveness check for switch statements. */
export function assertNever(value: never): never {
	throw new Error(`Unexpected value: ${String(value)}`);
}
