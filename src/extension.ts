/**
 * `lacewing/extension`: the policy Lacewing already enforces, for packages
 * that build on it and must not drift from it.
 *
 * Covered by semver like the root export. Everything here is read-only:
 * registry entries are frozen, and nothing that adds to the registry
 * (`registerLegacyAlgorithm`) or weakens a check is reachable from this
 * path. Header validation (`validateHeader`) is deliberately absent too:
 * it refuses an embedded `jwk`, which is right for a token and wrong for
 * any format that carries its own key, so each format owns its header
 * rules.
 */

export { getAlgorithmProperties, type AlgorithmInfo } from "./lib/algorithms.js";
export { parseDuration } from "./lib/duration.js";
export { readHeaderValue, type HeaderSource } from "./http/source.js";
