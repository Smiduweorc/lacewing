/**
 * Provenance for key sources. `defineProfile` accepts only key sources built
 * by this library, or ones explicitly waved through with the grep-loud
 * `unsafeCustomKeySource()` - a hand-rolled `getVerificationKey` decides which
 * key verifies a token, so it should never be anonymous code.
 */

import { mintedKind } from "../lib/minted.js";
import type { KeySource } from "../types.js";

const vouched = mintedKind<KeySource>();

/** Internal: wrap a key source Lacewing built (or was explicitly told to accept). */
export function vouchForKeySource(source: KeySource): KeySource {
	return vouched.mint({ getVerificationKey: source.getVerificationKey.bind(source) });
}

export function isVouchedKeySource(source: unknown): source is KeySource {
	return vouched.is(source);
}

/**
 * Ugly on purpose: accept a custom {@link KeySource}. Its `getVerificationKey`
 * is the issuer-to-key binding (RFC 8725 §3.8); you own its correctness.
 * Returns a wrapper; pass that, not the original, as `keys`.
 */
export function unsafeCustomKeySource(source: KeySource): KeySource {
	if (typeof source?.getVerificationKey !== "function") {
		throw new TypeError("unsafeCustomKeySource() needs an object with getVerificationKey()");
	}
	return vouchForKeySource(source);
}
