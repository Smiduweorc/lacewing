/**
 * LEGACY INTEROP - explicit opt-in only.
 *
 * The `RS256` descriptor on its own, for callers that only ever need that one.
 * Everything in {@link module:legacy/rsa} applies: importing this changes
 * nothing, and `RS256` is accepted only where `LEGACY_RS256` is passed.
 */

export { LEGACY_RS256 } from "./rsa.js";
