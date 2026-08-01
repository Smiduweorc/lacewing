/**
 * Cookie transport helpers (LW-http.1).
 *
 * The paved road for browser token storage: `HttpOnly; Secure; SameSite`
 * are always emitted and cannot be configured away - weaker cookies are
 * unrepresentable. `localStorage`/`sessionStorage` are script-readable
 * and therefore one XSS away from token theft; don't put tokens there.
 *
 * Framework-agnostic: works on WHATWG `Headers` (and anything exposing
 * them, e.g. `Request`/`Response`).
 */

import { readHeaderValue, type HeaderSource } from "./source.js";

// RFC 6265 cookie-name token; value charset covers compact JWTs.
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~A-Za-z0-9]+$/;
const COOKIE_VALUE = /^[A-Za-z0-9._~+/=-]*$/;

const DEFAULT_COOKIE_NAME = "__Host-token";

export interface TokenCookieOptions {
	/** Cookie name (default `__Host-token`, the most locked-down prefix). */
	name?: string;
	/** `None` is not an option - cross-site token cookies are how CSRF happens. */
	sameSite?: "Strict" | "Lax";
	/** Default `/` (mandatory for `__Host-` names). */
	path?: string;
	/** Cookie lifetime; omit for a session cookie. */
	maxAgeSeconds?: number;
	/** Not allowed with `__Host-` names. */
	domain?: string;
}

/** Build a hardened `Set-Cookie` value. Prefer {@link setTokenCookie}. */
export function buildTokenCookie(token: string, options: TokenCookieOptions = {}): string {
	if (typeof token !== "string" || !COOKIE_VALUE.test(token) || token.length === 0) {
		throw new TypeError("Token contains characters that cannot be stored in a cookie");
	}
	const name = options.name ?? DEFAULT_COOKIE_NAME;
	if (!COOKIE_NAME.test(name)) {
		throw new TypeError("Invalid cookie name");
	}
	const sameSite = options.sameSite ?? "Lax";
	if (sameSite !== "Lax" && sameSite !== "Strict") {
		throw new TypeError("SameSite must be \"Lax\" or \"Strict\" - \"None\" is not supported");
	}
	const path = options.path ?? "/";
	if (path.includes(";") || !path.startsWith("/")) {
		throw new TypeError("Invalid cookie path");
	}
	if (name.startsWith("__Host-")) {
		if (options.domain !== undefined) {
			throw new TypeError("__Host- cookies must not set a Domain");
		}
		if (path !== "/") {
			throw new TypeError("__Host- cookies require Path=/");
		}
	}
	const parts = [`${name}=${token}`, `Path=${path}`];
	if (options.domain !== undefined) {
		if (!/^[A-Za-z0-9.-]+$/.test(options.domain)) {
			throw new TypeError("Invalid cookie domain");
		}
		parts.push(`Domain=${options.domain}`);
	}
	if (options.maxAgeSeconds !== undefined) {
		if (!Number.isInteger(options.maxAgeSeconds) || options.maxAgeSeconds < 0) {
			throw new TypeError("maxAgeSeconds must be a non-negative integer");
		}
		parts.push(`Max-Age=${options.maxAgeSeconds}`);
	}
	// Non-negotiable (LW-http.1). There is no option to remove these.
	parts.push("HttpOnly", "Secure", `SameSite=${sameSite}`);
	return parts.join("; ");
}

/** Append a hardened token cookie to a response's headers. */
export function setTokenCookie(
	headers: Headers,
	token: string,
	options: TokenCookieOptions = {}
): void {
	headers.append("Set-Cookie", buildTokenCookie(token, options));
}

/** Expire a previously set token cookie. */
export function clearTokenCookie(
	headers: Headers,
	options: Pick<TokenCookieOptions, "name" | "path" | "domain"> = {}
): void {
	headers.append(
		"Set-Cookie",
		buildTokenCookie("x", { ...options, maxAgeSeconds: 0 }).replace(/^([^=]+)=x;/, "$1=;")
	);
}

/**
 * Read a token cookie from a request. Accepts a `Headers` object,
 * anything with a `.headers` (e.g. `Request`), or the raw `Cookie`
 * header string. Returns `undefined` when absent or malformed.
 *
 * Throws {@link TypeError} on a shape it does not accept - notably a
 * Node/Express request, whose `headers` is a plain record. "I was
 * handed something I don't understand" must not be indistinguishable
 * from "this request carried no token".
 */
export function readTokenCookie(
	source: HeaderSource,
	name: string = DEFAULT_COOKIE_NAME
): string | undefined {
	const cookieHeader = readHeaderValue(source, "cookie", "readTokenCookie");
	if (typeof cookieHeader !== "string" || cookieHeader.length > 16384) {
		return undefined;
	}
	let found: string | undefined;
	for (const pair of cookieHeader.split(";")) {
		const eq = pair.indexOf("=");
		if (eq === -1) continue;
		if (pair.slice(0, eq).trim() !== name) continue;
		// Cookie shadowing: servers disagree about whether the first or last
		// duplicate wins, so a header carrying the name twice is ambiguous.
		// Ambiguous input is refused rather than guessed at.
		if (found !== undefined) return undefined;
		const value = pair.slice(eq + 1).trim();
		found = COOKIE_VALUE.test(value) && value.length > 0 ? value : "";
	}
	return found === undefined || found === "" ? undefined : found;
}
