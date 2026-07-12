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
 * False positives are waived per top-level claim via the grep-loud
 * `SignJWT.unsafeAllowClaim(name)`.
 */

import { PayloadHygieneViolation } from "../util/errors.js";

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
const JWT_LIKE = /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/;

function normalizeName(name: string): string {
	return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function sensitiveNameFragment(name: string): string | undefined {
	const normalized = normalizeName(name);
	return SENSITIVE_NAME_FRAGMENTS.find((fragment) => normalized.includes(fragment));
}

function isLuhnValidCardNumber(value: string): boolean {
	const digits = value.replace(/[\s-]/g, "");
	if (!/^\d{13,19}$/.test(digits)) {
		return false;
	}
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

function checkValue(topLevelClaim: string, value: string): void {
	if (PEM_PRIVATE_KEY.test(value)) {
		throw new PayloadHygieneViolation(
			topLevelClaim,
			`Claim "${topLevelClaim}" contains a PEM private-key block. ` +
				"JWS payloads are readable plaintext - never embed key material."
		);
	}
	if (JWT_LIKE.test(value)) {
		throw new PayloadHygieneViolation(
			topLevelClaim,
			`Claim "${topLevelClaim}" contains what looks like another JWT. ` +
				"Embedding tokens in tokens leaks credentials to anyone who can read the payload."
		);
	}
	if (isLuhnValidCardNumber(value)) {
		throw new PayloadHygieneViolation(
			topLevelClaim,
			`Claim "${topLevelClaim}" contains what looks like a payment card number. ` +
				"JWS payloads are readable plaintext - never embed cardholder data."
		);
	}
}

function scanNode(topLevelClaim: string, value: unknown): void {
	if (typeof value === "string") {
		checkValue(topLevelClaim, value);
		return;
	}
	if (Array.isArray(value)) {
		for (const entry of value) {
			scanNode(topLevelClaim, entry);
		}
		return;
	}
	if (typeof value === "object" && value !== null) {
		for (const [name, nested] of Object.entries(value)) {
			const fragment = sensitiveNameFragment(name);
			if (fragment !== undefined) {
				throw new PayloadHygieneViolation(
					topLevelClaim,
					`Claim "${topLevelClaim}" contains a nested field whose name matches "${fragment}". ` +
						"JWS payloads are readable plaintext - do not put secrets in tokens. " +
						"If this is a false positive, waive it with unsafeAllowClaim()."
				);
			}
			scanNode(topLevelClaim, nested);
		}
	}
}

/**
 * Scan a payload about to be signed. Throws {@link PayloadHygieneViolation}
 * naming the offending claim (never echoing its value). Claims listed in
 * `allowedClaims` are skipped entirely, subtree included.
 */
export function scanPayloadForSensitiveData(
	payload: Record<string, unknown>,
	allowedClaims: ReadonlySet<string> = new Set()
): void {
	for (const [claim, value] of Object.entries(payload)) {
		if (allowedClaims.has(claim)) {
			continue;
		}
		const fragment = sensitiveNameFragment(claim);
		if (fragment !== undefined) {
			throw new PayloadHygieneViolation(
				claim,
				`Claim name "${claim}" matches the sensitive-name heuristic ("${fragment}"). ` +
					"JWS payloads are readable plaintext - do not put secrets in tokens. " +
					"If this is a false positive, waive it with unsafeAllowClaim()."
			);
		}
		scanNode(claim, value);
	}
}
