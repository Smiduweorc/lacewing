/**
 * Strict JSON object parsing for token segments (RFC 8725 §3.7 strictness).
 *
 * `JSON.parse` silently keeps the *last* value when a member name is
 * duplicated. That is a parser differential: an attacker crafts a header or
 * payload where Lacewing and another consumer disagree about, say, which
 * `alg` or `aud` is authoritative. RFC 8259 §4 says names SHOULD be unique
 * and that behavior is otherwise unpredictable - Lacewing treats a duplicate
 * key at any nesting level as malformed and rejects the token.
 *
 * `JSON.parse` also keeps `"__proto__"` as an own property. A caller that
 * deep-merges the verified claims then writes through it into
 * Object.prototype, and `constructor` -> `prototype` reaches the same place
 * (CVE-2019-10744 in lodash). No registered claim or header uses these
 * names, so they are rejected at any depth, escaped spellings included.
 *
 * The scan runs only after `JSON.parse` has confirmed the text is
 * well-formed, so it can assume valid JSON and stay small.
 */

import { JWTError } from "../util/errors.js";

interface ObjectContext {
	readonly seen: Set<string>;
	expectingKey: boolean;
}

type Context = ObjectContext | "array";

const PROTOTYPE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function readString(text: string, start: number): { value: string; next: number } {
	// text[start] === '"'
	let i = start + 1;
	let out = "";
	const n = text.length;
	while (i < n) {
		const c = text[i] as string;
		if (c === "\"") {
			return { value: out, next: i + 1 };
		}
		if (c === "\\") {
			const e = text[i + 1] as string;
			switch (e) {
			case "\"":
				out += "\"";
				break;
			case "\\":
				out += "\\";
				break;
			case "/":
				out += "/";
				break;
			case "b":
				out += "\b";
				break;
			case "f":
				out += "\f";
				break;
			case "n":
				out += "\n";
				break;
			case "r":
				out += "\r";
				break;
			case "t":
				out += "\t";
				break;
			case "u":
				out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16));
				i += 4;
				break;
			default:
				out += e;
			}
			i += 2;
			continue;
		}
		out += c;
		i++;
	}
	// Unreachable for JSON that already parsed.
	return { value: out, next: i };
}

/**
 * Throw `JWT_INVALID` if `text` (already known to be valid JSON) contains
 * a duplicated member name, or `__proto__`, `constructor` or `prototype` as a
 * member name, in any object at any depth.
 */
export function assertNoDuplicateKeys(text: string, what: string): void {
	const stack: Context[] = [];
	let i = 0;
	const n = text.length;
	while (i < n) {
		const c = text[i] as string;
		if (c === "{") {
			stack.push({ seen: new Set<string>(), expectingKey: true });
			i++;
			continue;
		}
		if (c === "[") {
			stack.push("array");
			i++;
			continue;
		}
		if (c === "}" || c === "]") {
			stack.pop();
			i++;
			continue;
		}
		if (c === "\"") {
			const top = stack[stack.length - 1];
			if (top !== undefined && top !== "array" && top.expectingKey) {
				const { value, next } = readString(text, i);
				if (PROTOTYPE_KEYS.has(value)) {
					throw new JWTError(
						"JWT_INVALID",
						`Token ${what} contains the member name "${value}", which can pollute object prototypes`
					);
				}
				if (top.seen.has(value)) {
					throw new JWTError(
						"JWT_INVALID",
						`Token ${what} contains a duplicate JSON key`
					);
				}
				top.seen.add(value);
				top.expectingKey = false;
				i = next;
			} else {
				i = readString(text, i).next;
			}
			continue;
		}
		if (c === ",") {
			const top = stack[stack.length - 1];
			if (top !== undefined && top !== "array") {
				top.expectingKey = true;
			}
			i++;
			continue;
		}
		i++;
	}
}

/**
 * Decode a token segment's UTF-8 text into a JSON object, rejecting anything
 * that is not a plain object, any duplicate member names, and the member
 * names that reach object prototypes.
 */
export function parseJsonObject(text: string, what: string): Record<string, unknown> {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch (cause) {
		if (cause instanceof JWTError && cause.code === "JWT_INVALID") throw cause;
		throw new JWTError("JWT_INVALID", `Token ${what} is not valid JSON`, { cause });
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw new JWTError("JWT_INVALID", `Token ${what} is not a JSON object`);
	}
	assertNoDuplicateKeys(text, what);
	return parsed as Record<string, unknown>;
}
