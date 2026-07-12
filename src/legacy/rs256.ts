/**
 * LEGACY INTEROP - explicit opt-in only.
 *
 * `RS256` (RSASSA-PKCS1-v1_5) is not in Lacewing's default registry. This
 * module is kept for backwards compatibility and re-exports the RS256 opt-in
 * from {@link module:legacy/rsa}, where the rest of the `RS*` family lives.
 * Calling {@link enableLegacyRS256} is the grep-loud marker code review looks
 * for; prefer `PS256`/`EdDSA` everywhere you control both sides.
 */

export { enableLegacyRS256 } from "./rsa.js";
