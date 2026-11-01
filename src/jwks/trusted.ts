/**
 * Provenance for key sources. `defineProfile` accepts only key sources built
 * by this library, or ones explicitly waved through with the grep-loud
 * `unsafeCustomKeySource()` - a hand-rolled `getVerificationKey` decides which
 * key verifies a token, so it should never be anonymous code.
 */

import type { KeySource } from "../types.js";

const vouched = new WeakSet<KeySource>();

/** Internal: mark a key source as built (or explicitly accepted) by Lacewing. */
export function vouchForKeySource<T extends KeySource>(source: T): T {
	vouched.add(source);
	return source;
}

export function isVouchedKeySource(source: KeySource): boolean {
	return vouched.has(source);
}

/**
 * Ugly on purpose: accept a custom {@link KeySource}. Its `getVerificationKey`
 * is the issuer-to-key binding (RFC 8725 §3.8); you own its correctness.
 */
export function unsafeCustomKeySource<T extends KeySource>(source: T): T {
	if (typeof source?.getVerificationKey !== "function") {
		throw new TypeError("unsafeCustomKeySource() needs an object with getVerificationKey()");
	}
	return vouchForKeySource(source);
}
