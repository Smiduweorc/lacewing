/**
 * The sign builder.
 *
 * `.sign()` refuses to produce a token unless `typ` (constructor), `iss`,
 * `aud` and `exp` are set - each requirement individually waivable only
 * via a grep-loud `unsafeAllowMissing*` call. Every token gets a unique
 * `jti`, lifetimes are capped, and the payload hygiene scanner runs as
 * the final step before signing.
 */

import { CompactSign } from "jose";
import {
	KeyTypeMismatch,
	MaxLifetimeExceeded,
	MissingClaim,
} from "../util/errors.js";
import { parseDuration } from "../lib/duration.js";
import { encodeUTF8 } from "../lib/utf8.js";
import { scanPayloadForSensitiveData } from "../lib/payload_hygiene.js";
import { isLacewingKey, type DurationSeconds, type LacewingKey } from "../types.js";

const DEFAULT_MAX_LIFETIME_SECONDS = 3600;

// Set through dedicated methods only, so they can't be smuggled past the
// requirement checks via .claim().
const RESERVED_CLAIMS = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]);

export interface SignJwtOptions {
	/**
	 * Cap on `.expiresIn()`. Default 1h - raising it is a
	 * deliberate, visible configuration choice.
	 */
	maxLifetime?: number | string;
}

/**
 * Fluent builder for a signed JWT. `typ` is a constructor argument, and
 * `.sign()` refuses to run without `issuer`, `audience` and `expiresIn`
 * (each waivable only via a grep-loud `unsafeAllowMissing*` call).
 *
 * @example
 * ```ts
 * const token = await new SignJWT("at+jwt")
 *   .issuer("https://auth.example.com")
 *   .audience("https://api.example.com")
 *   .subject("user-42")
 *   .claim("scope", "read")
 *   .expiresIn("10m")
 *   .sign(privateKey);
 * ```
 */
export class SignJWT {
	readonly #typ: string;
	readonly #maxLifetime: DurationSeconds;
	readonly #claims = new Map<string, unknown>();
	readonly #allowedClaims = new Set<string>();
	#iss?: string;
	#aud?: string | string[];
	#sub?: string;
	#jti?: string;
	#expiresIn?: DurationSeconds;
	#notBefore?: DurationSeconds;
	#waiveIssuer = false;
	#waiveAudience = false;
	#waiveExpiration = false;

	/** Explicit typing is mandatory (§3.11): the `typ` is a constructor argument. */
	constructor(typ: string, options: SignJwtOptions = {}) {
		if (typeof typ !== "string" || typ.length === 0) {
			throw new TypeError(
				"SignJWT requires an explicit token typ, e.g. new SignJWT(\"at+jwt\")"
			);
		}
		this.#typ = typ;
		this.#maxLifetime = parseDuration(options.maxLifetime ?? DEFAULT_MAX_LIFETIME_SECONDS);
	}

	issuer(iss: string): this {
		if (typeof iss !== "string" || iss.length === 0) {
			throw new TypeError("issuer must be a non-empty string");
		}
		this.#iss = iss;
		return this;
	}

	audience(aud: string | string[]): this {
		const values = Array.isArray(aud) ? aud : [aud];
		if (values.length === 0 || values.some((v) => typeof v !== "string" || v.length === 0)) {
			throw new TypeError("audience must be a non-empty string or array of them");
		}
		this.#aud = aud;
		return this;
	}

	subject(sub: string): this {
		if (typeof sub !== "string" || sub.length === 0) {
			throw new TypeError("subject must be a non-empty string");
		}
		this.#sub = sub;
		return this;
	}

	/** Override the auto-assigned `jti`. Uniqueness is then your problem. */
	jwtId(jti: string): this {
		if (typeof jti !== "string" || jti.length === 0) {
			throw new TypeError("jwtId must be a non-empty string");
		}
		this.#jti = jti;
		return this;
	}

	/** Token lifetime from now, e.g. `"10m"` or `600`. Capped by maxLifetime. */
	expiresIn(duration: number | string): this {
		const seconds = parseDuration(duration);
		if (seconds < 1) {
			throw new TypeError("expiresIn must be at least one second");
		}
		this.#expiresIn = seconds;
		return this;
	}

	/** Delay validity by `duration` from now (`nbf`). */
	notBefore(duration: number | string): this {
		this.#notBefore = parseDuration(duration);
		return this;
	}

	/** Set a custom claim. Registered claims must use their dedicated methods. */
	claim(name: string, value: unknown): this {
		if (typeof name !== "string" || name.length === 0) {
			throw new TypeError("claim name must be a non-empty string");
		}
		if (RESERVED_CLAIMS.has(name)) {
			throw new TypeError(
				`"${name}" is a registered claim - use the dedicated builder method`
			);
		}
		this.#claims.set(name, value);
		return this;
	}

	/** Waive the payload hygiene scanner for one claim (LW-payload). Grep for this in review. */
	unsafeAllowClaim(name: string): this {
		this.#allowedClaims.add(name);
		return this;
	}

	/** Waive the mandatory `iss`. Grep for this in review. */
	unsafeAllowMissingIssuer(): this {
		this.#waiveIssuer = true;
		return this;
	}

	/** Waive the mandatory `aud`. Grep for this in review. */
	unsafeAllowMissingAudience(): this {
		this.#waiveAudience = true;
		return this;
	}

	/** Waive the mandatory `exp`. Grep for this in review. */
	unsafeAllowMissingExpiration(): this {
		this.#waiveExpiration = true;
		return this;
	}

	async sign(key: LacewingKey): Promise<string> {
		if (!isLacewingKey(key)) {
			throw new TypeError("sign() only accepts keys imported through Lacewing");
		}
		if (key.keyType === "public") {
			throw new KeyTypeMismatch("Cannot sign with a public key");
		}
		if (this.#iss === undefined && !this.#waiveIssuer) {
			throw new MissingClaim(
				"iss",
				"Tokens must name their issuer - call .issuer() (or, deliberately, .unsafeAllowMissingIssuer())"
			);
		}
		if (this.#aud === undefined && !this.#waiveAudience) {
			throw new MissingClaim(
				"aud",
				"Tokens must name their audience - call .audience() (or, deliberately, .unsafeAllowMissingAudience())"
			);
		}
		if (this.#expiresIn === undefined && !this.#waiveExpiration) {
			throw new MissingClaim(
				"exp",
				"Tokens must expire - call .expiresIn() (or, deliberately, .unsafeAllowMissingExpiration())"
			);
		}
		if (this.#expiresIn !== undefined && this.#expiresIn > this.#maxLifetime) {
			throw new MaxLifetimeExceeded(
				`Requested lifetime exceeds the ${this.#maxLifetime}s cap - ` +
					"long-lived tokens need an explicit maxLifetime option"
			);
		}

		const now = Math.floor(Date.now() / 1000);
		const payload: Record<string, unknown> = Object.fromEntries(this.#claims);
		if (this.#iss !== undefined) payload.iss = this.#iss;
		if (this.#sub !== undefined) payload.sub = this.#sub;
		if (this.#aud !== undefined) payload.aud = this.#aud;
		payload.jti = this.#jti ?? globalThis.crypto.randomUUID();
		if (this.#notBefore !== undefined) payload.nbf = now + this.#notBefore;
		if (this.#expiresIn !== undefined) payload.exp = now + this.#expiresIn;
		payload.iat = now;

		scanPayloadForSensitiveData(payload, this.#allowedClaims);

		return new CompactSign(encodeUTF8(JSON.stringify(payload)))
			.setProtectedHeader({ alg: key.algorithm, typ: this.#typ })
			.sign(key.key as Parameters<CompactSign["sign"]>[0]);
	}
}
