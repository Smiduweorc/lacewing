/**
 * LEGACY INTEROP - explicit opt-in only.
 *
 * The `RS*` family (RSASSA-PKCS1-v1_5) is not in Lacewing's default set:
 * PKCS#1 v1.5 signatures are the deprecated ancestor of RSA-PSS and only
 * belong in systems that must interoperate with issuers that cannot emit
 * `PS256`/`EdDSA`. Prefer those everywhere you control both sides.
 *
 * Importing this module changes nothing. Each descriptor works only where
 * you pass it, which is the line code review greps for:
 *
 * ```ts
 * import { LEGACY_RS256 } from "lacewing/legacy/rsa";
 * const key = await importKey(pem, LEGACY_RS256);
 * const profile = defineProfile({ ..., algorithms: [LEGACY_RS256], keys: key });
 * ```
 *
 * A profile that does not list it keeps refusing `RS256`, in the same
 * process, whatever any other profile or package opted into. `none` has no
 * descriptor and never will.
 */

import { LEGACY_RS256, LEGACY_RS384, LEGACY_RS512 } from "../lib/algorithms.js";

export { LEGACY_RS256, LEGACY_RS384, LEGACY_RS512 };

/**
 * All three, for an issuer that may rotate across hash sizes. Still an
 * explicit opt-in: list it only where such an issuer is trusted.
 */
export const LEGACY_RSA = Object.freeze([LEGACY_RS256, LEGACY_RS384, LEGACY_RS512] as const);
