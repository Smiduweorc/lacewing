/**
 * Strict UTF-8 encode/decode (RFC 8725 §3.7). Malformed sequences reject
 * the token - no replacement characters, no silently stripped BOM.
 */

import { JWTInvalid } from "../util/errors.js";

const encoder = new TextEncoder();
// fatal: rejects malformed/overlong sequences. ignoreBOM: a leading BOM is
// preserved as U+FEFF so downstream JSON parsing rejects it (BOM tricks).
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// Matches unpaired surrogate halves, which TextEncoder would otherwise
// silently replace with U+FFFD.
const LONE_SURROGATE =
	/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export function encodeUTF8(text: string): Uint8Array {
	if (LONE_SURROGATE.test(text)) {
		throw new JWTInvalid("Text contains unpaired surrogates");
	}
	return encoder.encode(text);
}

export function decodeUTF8(bytes: Uint8Array): string {
	try {
		return decoder.decode(bytes);
	} catch (cause) {
		throw new JWTInvalid("Malformed UTF-8", { cause });
	}
}
