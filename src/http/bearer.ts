/**
 * Strict `Authorization: Bearer` parsing (RFC 6750 §2.1, LW-http.2).
 *
 * Deliberately unsupported: tokens in query strings (they leak through
 * logs and the Referer header), multiple tokens, alternate casings and
 * whitespace tricks. One header, one scheme, one token.
 */

import { BearerParseFailed } from "../util/errors.js";

// RFC 6750 credentials: exact-case scheme, a single SP, one token68.
const BEARER = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/;
const MAX_HEADER_LENGTH = 16384;

/**
 * Extract the bearer token from an `Authorization` header. Accepts a
 * `Headers` object, anything with a `.headers` (e.g. `Request`), or the
 * raw header value. Throws {@link BearerParseFailed} on anything that
 * isn't exactly one well-formed `Bearer <token>`.
 *
 * Note: when multiple `Authorization` headers were sent, `Headers`
 * joins them with `", "` - which this parser rejects, by design.
 */
export function parseBearer(
	source: Headers | { headers: Headers } | string | null | undefined
): string {
	let value: string | null | undefined;
	if (typeof source === "string") {
		value = source;
	} else if (source instanceof Headers) {
		value = source.get("authorization");
	} else if (typeof source === "object" && source !== null && source.headers instanceof Headers) {
		value = source.headers.get("authorization");
	}
	if (typeof value !== "string" || value.length === 0) {
		throw new BearerParseFailed("Missing Authorization header");
	}
	if (value.length > MAX_HEADER_LENGTH) {
		throw new BearerParseFailed("Authorization header exceeds the maximum length");
	}
	const match = BEARER.exec(value);
	if (match === null) {
		throw new BearerParseFailed(
			"Authorization header failed strict Bearer parsing (expected exactly \"Bearer <token>\")"
		);
	}
	return match[1] as string;
}
