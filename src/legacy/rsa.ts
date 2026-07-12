/**
 * LEGACY INTEROP - explicit opt-in only.
 *
 * The `RS*` family (RSASSA-PKCS1-v1_5) is not in Lacewing's default registry:
 * PKCS#1 v1.5 signatures are the deprecated ancestor of RSA-PSS and only
 * belong in systems that must interoperate with issuers that cannot emit
 * `PS256`/`EdDSA`. Each `enable...` call is the grep-loud marker code review
 * looks for; prefer `PS256`/`EdDSA` everywhere you control both sides.
 *
 * `none` can never enter through this door - `registerLegacyAlgorithm` refuses
 * it - and neither can any algorithm not on this curated legacy list.
 */

import { registerLegacyAlgorithm } from "../lib/algorithms.js";

const RSA_MIN_KEY_BITS = 2048;

/** Register legacy `RS256`. After this, importKey/profiles/JWKS accept it. */
export function enableLegacyRS256(): void {
	registerLegacyAlgorithm({ name: "RS256", kty: "RSA", minKeyBits: RSA_MIN_KEY_BITS });
}

/** Register legacy `RS384`. Prefer `PS384`/`EdDSA` where you control both sides. */
export function enableLegacyRS384(): void {
	registerLegacyAlgorithm({ name: "RS384", kty: "RSA", minKeyBits: RSA_MIN_KEY_BITS });
}

/** Register legacy `RS512`. Prefer `PS512`/`EdDSA` where you control both sides. */
export function enableLegacyRS512(): void {
	registerLegacyAlgorithm({ name: "RS512", kty: "RSA", minKeyBits: RSA_MIN_KEY_BITS });
}

/**
 * Register the whole legacy `RS256`/`RS384`/`RS512` family at once, for
 * interop with an issuer that may rotate across hash sizes. Still an explicit,
 * grep-loud opt-in - do not call it "just in case".
 */
export function enableLegacyRSA(): void {
	enableLegacyRS256();
	enableLegacyRS384();
	enableLegacyRS512();
}
