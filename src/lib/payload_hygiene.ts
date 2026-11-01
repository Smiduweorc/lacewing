/**
 * Sign-time payload hygiene scanner (LW-payload).
 *
 * JWS payloads are base64url-encoded **plaintext** - encoding, not
 * encryption. Two tiers, applied recursively so nesting offers no blind
 * spots:
 *  - claim *names* matching a deny-heuristic (`password`, `secret`, ...)
 *  - claim *values* matching high-confidence secret patterns (Luhn-valid
 *    card numbers, PEM private-key blocks, other JWTs)
 *
 * Names are matched by word, not by substring: `businessName` is the words
 * `business` and `name`, so it never reads as `ssn`. A fragment matches when
 * a run of words ends with it, which keeps `accesstoken` and `apiKeys`
 * caught while `tokenizer` and `classNumber` pass.
 *
 * False positives are waived per claim path via the grep-loud
 * `SignJWT.unsafeAllowClaim(...path)`. A waiver covers that one node and
 * its subtree, nothing beside it.
 */

import { JWTError } from "../util/errors.js";

const SENSITIVE_NAME_FRAGMENTS = [
	"password",
	"passwd",
	"passphrase",
	"secret",
	"apikey",
	"privatekey",
	"ssn",
	"socialsecurity",
	"creditcard",
	"cardnumber",
	"cvv",
	"cvc",
	"token",
	"authorization",
	"bearer",
] as const;

const PEM_PRIVATE_KEY = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;

// A compact JWS/JWE always begins with a base64url-encoded JSON object, and
// `{"` encodes to `eyJ`. Anchoring on that keeps ordinary dotted identifiers
// (bare hostnames, reverse-DNS names) from reading as embedded tokens. The
// last segment may be empty - that is exactly an `alg: none` token.
const JWT_LIKE = /^eyJ[A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*$/;

/**
 * Standard OAuth/OIDC claim names that describe *this* token rather than
 * carrying one. Without them, `token_use` (AWS Cognito) and `token_type`
 * trip the `token` fragment and force an `unsafeAllowClaim` waiver onto a
 * perfectly correct payload - which is exactly how a grep-loud marker stops
 * being worth grepping for.
 */
const BENIGN_NAMES = new Set(["tokenuse", "tokentype"]);

/**
 * Issuer Identification Numbers, as `[prefix regex, valid lengths]`. Luhn
 * alone is a 1-in-10 coin flip on any digit string, which rejects roughly a
 * tenth of all snowflake-style numeric user ids; requiring a real card prefix
 * *and* that brand's length makes the check mean something.
 */
const CARD_BRANDS: ReadonlyArray<readonly [RegExp, readonly number[]]> = [
	[/^4/, [13, 16, 19]], // Visa
	[/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/, [16]], // Mastercard
	[/^3[47]/, [15]], // American Express
	[/^(6011|65|64[4-9])/, [16, 19]], // Discover
	[/^3(0[0-5]|095|6|[89])/, [14, 16, 19]], // Diners Club
	[/^35(2[89]|[3-8]\d)/, [16, 17, 18, 19]], // JCB
	[/^62/, [16, 17, 18, 19]], // UnionPay
];

/** `apiKey`, `api_key`, `API-Key` and `APIKey` all become `["api", "key"]`. */
function nameWords(name: string): string[] {
	return name
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
		.toLowerCase()
		.split(/[^a-z0-9]+/)
		.filter((word) => word.length > 0);
}

function sensitiveNameFragment(name: string): string | undefined {
	const words = nameWords(name);
	if (BENIGN_NAMES.has(words.join(""))) {
		return undefined;
	}
	// Every prefix of the word list, so a match always ends on a word boundary.
	let joined = "";
	for (const word of words) {
		joined += word;
		const fragment = SENSITIVE_NAME_FRAGMENTS.find(
			(candidate) => joined.endsWith(candidate) || joined.endsWith(`${candidate}s`)
		);
		if (fragment !== undefined) {
			return fragment;
		}
	}
	return undefined;
}

/** The waiver key for a claim path; arrays add no segment. */
export function claimPathKey(path: readonly string[]): string {
	return JSON.stringify(path);
}

function describePath(path: readonly string[]): string {
	return path.map((segment) => JSON.stringify(segment)).join(", ");
}

function passesLuhn(digits: string): boolean {
	let sum = 0;
	let double = false;
	for (let i = digits.length - 1; i >= 0; i--) {
		let digit = digits.charCodeAt(i) - 48;
		if (double) {
			digit *= 2;
			if (digit > 9) digit -= 9;
		}
		sum += digit;
		double = !double;
	}
	return sum % 10 === 0;
}

function isLuhnValidCardNumber(value: string): boolean {
	const digits = value.replace(/[\s-]/g, "");
	if (!/^\d{13,19}$/.test(digits)) {
		return false;
	}
	const brandMatches = CARD_BRANDS.some(
		([prefix, lengths]) => prefix.test(digits) && lengths.includes(digits.length)
	);
	return brandMatches && passesLuhn(digits);
}

function checkValue(topLevelClaim: string, value: string): void {
	if (PEM_PRIVATE_KEY.test(value)) {
		throw new JWTError(
			"PAYLOAD_HYGIENE_VIOLATION",
			`Claim "${topLevelClaim}" contains a PEM private-key block. ` +
				"JWS payloads are readable plaintext - never embed key material.",
			{ claim: topLevelClaim }
		);
	}
	if (JWT_LIKE.test(value)) {
		throw new JWTError(
			"PAYLOAD_HYGIENE_VIOLATION",
			`Claim "${topLevelClaim}" contains what looks like another JWT. ` +
				"Embedding tokens in tokens leaks credentials to anyone who can read the payload.",
			{ claim: topLevelClaim }
		);
	}
	if (isLuhnValidCardNumber(value)) {
		throw new JWTError(
			"PAYLOAD_HYGIENE_VIOLATION",
			`Claim "${topLevelClaim}" contains what looks like a payment card number. ` +
				"JWS payloads are readable plaintext - never embed cardholder data.",
			{ claim: topLevelClaim }
		);
	}
}

function scanNode(
	topLevelClaim: string,
	path: string[],
	value: unknown,
	allowedPaths: ReadonlySet<string>
): void {
	if (typeof value === "string") {
		checkValue(topLevelClaim, value);
		return;
	}
	if (Array.isArray(value)) {
		for (const entry of value) {
			scanNode(topLevelClaim, path, entry, allowedPaths);
		}
		return;
	}
	if (typeof value === "object" && value !== null) {
		for (const [name, nested] of Object.entries(value)) {
			const nestedPath = [...path, name];
			if (allowedPaths.has(claimPathKey(nestedPath))) {
				continue;
			}
			const fragment = sensitiveNameFragment(name);
			if (fragment !== undefined) {
				throw new JWTError(
					"PAYLOAD_HYGIENE_VIOLATION",
					`Claim "${topLevelClaim}" contains a nested field whose name matches "${fragment}". ` +
						"JWS payloads are readable plaintext - do not put secrets in tokens. " +
						`If this is a false positive, waive that field with unsafeAllowClaim(${describePath(nestedPath)}).`,
					{ claim: topLevelClaim }
				);
			}
			scanNode(topLevelClaim, nestedPath, nested, allowedPaths);
		}
	}
}

/**
 * Scan a payload about to be signed. Throws `PAYLOAD_HYGIENE_VIOLATION`
 * naming the offending claim (never echoing its value). A path in
 * `allowedPaths` (keyed by {@link claimPathKey}) is skipped, subtree included.
 */
export function scanPayloadForSensitiveData(
	payload: Record<string, unknown>,
	allowedPaths: ReadonlySet<string> = new Set()
): void {
	for (const [claim, value] of Object.entries(payload)) {
		if (allowedPaths.has(claimPathKey([claim]))) {
			continue;
		}
		const fragment = sensitiveNameFragment(claim);
		if (fragment !== undefined) {
			throw new JWTError(
				"PAYLOAD_HYGIENE_VIOLATION",
				`Claim name "${claim}" matches the sensitive-name heuristic ("${fragment}"). ` +
					"JWS payloads are readable plaintext - do not put secrets in tokens. " +
					`If this is a false positive, waive it with unsafeAllowClaim(${describePath([claim])}).`,
				{ claim }
			);
		}
		scanNode(claim, [claim], value, allowedPaths);
	}
}
