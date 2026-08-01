/**
 * Header-source narrowing shared by the cookie and bearer readers.
 *
 * The contract is deliberately narrow: WHATWG `Headers` (or anything
 * carrying them, e.g. `Request`) or the raw header string. Node's
 * `IncomingMessage.headers` is a plain record, not `Headers`, and is
 * *not* accepted - callers on Express/Fastify/Koa convert once at the
 * edge rather than making every reader here carry a second shape.
 *
 * What matters is that an unrecognized shape throws instead of reading
 * as "header absent". A helper that silently returns nothing for an
 * argument it never understood is one people route around, and the
 * hand-rolled replacement has none of the ambiguity refusals below.
 */

/** Anything the readers accept. `null`/`undefined` mean "header absent". */
export type HeaderSource = Headers | { headers: Headers } | string | null | undefined;

// Duck-typed rather than `instanceof`: a `Headers` from another realm
// (undici's own copy, a vm context, an edge/node boundary) is still a
// `Headers`, and `instanceof` would reject it. This widens nothing -
// a plain Node header record has no `.get` and still fails.
function isHeadersLike(value: unknown): value is Headers {
	return (
		typeof value === "object" && value !== null && typeof (value as Headers).get === "function"
	);
}

/**
 * Read one header from an accepted source. Returns `undefined` when the
 * header is absent; throws {@link TypeError} when `source` is a shape
 * this library does not accept.
 *
 * @param helper - calling helper's name, used in the error message.
 */
export function readHeaderValue(
	source: HeaderSource,
	header: string,
	helper: string
): string | undefined {
	// An explicit nothing - including the `null` that `Headers.get` itself
	// returns - is a legitimate "no such header", not a caller mistake.
	if (source === null || source === undefined) return undefined;
	if (typeof source === "string") return source;
	if (isHeadersLike(source)) {
		const value = source.get(header);
		return typeof value === "string" ? value : undefined;
	}
	if (typeof source === "object" && isHeadersLike((source as { headers?: unknown }).headers)) {
		const value = (source as { headers: Headers }).headers.get(header);
		return typeof value === "string" ? value : undefined;
	}
	throw new TypeError(
		`${helper}() expects a Headers, an object with a .headers (e.g. Request), a raw ` +
			"header string, or null/undefined. Node-style requests (Express, Fastify, Koa) " +
			"expose a plain object instead - convert it first: " +
			"new Headers(req.headers as Record<string, string>)"
	);
}
