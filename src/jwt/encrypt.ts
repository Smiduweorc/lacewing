/**
 * The encrypted-JWT builder - the JWE counterpart of `SignJWT`.
 *
 * Same claim discipline: `typ` is a constructor argument, `.encrypt()` refuses
 * to run without `iss`, `aud` and `exp` (each waivable only via a grep-loud
 * `unsafeAllowMissing*`), every token gets a unique `jti`, and lifetimes are
 * capped. The one deliberate difference from signing: there is **no** payload
 * hygiene scanner - the whole point of encryption is that the payload is not
 * readable plaintext, so embedding a secret is exactly the supported use.
 */

import { CompactEncrypt } from "jose";
import { KeyTypeMismatch, MaxLifetimeExceeded, MissingClaim } from "../util/errors.js";
import { parseDuration } from "../lib/duration.js";
import { encodeUTF8 } from "../lib/utf8.js";
import { getContentEncryptionProperties, getKeyManagementProperties } from "../lib/jwe_algorithms.js";
import { isLacewingEncryptionKey, type DurationSeconds, type LacewingEncryptionKey } from "../types.js";

const DEFAULT_MAX_LIFETIME_SECONDS = 3600;
const DEFAULT_CONTENT_ENCRYPTION = "A256GCM";
const RESERVED_CLAIMS = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]);

export interface EncryptJwtOptions {
	/** Cap on `.expiresIn()`. Default 1h - raising it is a visible choice. */
	maxLifetime?: number | string;
	/** Content-encryption algorithm (`enc`). Default `A256GCM`. */
	contentEncryption?: string;
}

export class EncryptJWT {
	readonly #typ: string;
	readonly #maxLifetime: DurationSeconds;
	readonly #enc: string;
	readonly #claims = new Map<string, unknown>();
	#iss?: string;
	#aud?: string | string[];
	#sub?: string;
	#jti?: string;
	#expiresIn?: DurationSeconds;
	#notBefore?: DurationSeconds;
	#waiveIssuer = false;
	#waiveAudience = false;
	#waiveExpiration = false;

	constructor(typ: string, options: EncryptJwtOptions = {}) {
		if (typeof typ !== "string" || typ.length === 0) {
			throw new TypeError("EncryptJWT requires an explicit token typ, e.g. new EncryptJWT(\"at+jwt\")");
		}
		this.#typ = typ;
		this.#maxLifetime = parseDuration(options.maxLifetime ?? DEFAULT_MAX_LIFETIME_SECONDS);
		this.#enc = options.contentEncryption ?? DEFAULT_CONTENT_ENCRYPTION;
		// Fail fast on an unknown enc rather than at .encrypt() time.
		getContentEncryptionProperties(this.#enc);
	}

	issuer(iss: string): this {
		if (typeof iss !== "string" || iss.length === 0) throw new TypeError("issuer must be a non-empty string");
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
		if (typeof sub !== "string" || sub.length === 0) throw new TypeError("subject must be a non-empty string");
		this.#sub = sub;
		return this;
	}

	/** Override the auto-assigned `jti`. Uniqueness is then your problem. */
	jwtId(jti: string): this {
		if (typeof jti !== "string" || jti.length === 0) throw new TypeError("jwtId must be a non-empty string");
		this.#jti = jti;
		return this;
	}

	expiresIn(duration: number | string): this {
		const seconds = parseDuration(duration);
		if (seconds < 1) throw new TypeError("expiresIn must be at least one second");
		this.#expiresIn = seconds;
		return this;
	}

	notBefore(duration: number | string): this {
		this.#notBefore = parseDuration(duration);
		return this;
	}

	claim(name: string, value: unknown): this {
		if (typeof name !== "string" || name.length === 0) throw new TypeError("claim name must be a non-empty string");
		if (RESERVED_CLAIMS.has(name)) {
			throw new TypeError(`"${name}" is a registered claim - use the dedicated builder method`);
		}
		this.#claims.set(name, value);
		return this;
	}

	unsafeAllowMissingIssuer(): this {
		this.#waiveIssuer = true;
		return this;
	}

	unsafeAllowMissingAudience(): this {
		this.#waiveAudience = true;
		return this;
	}

	unsafeAllowMissingExpiration(): this {
		this.#waiveExpiration = true;
		return this;
	}

	async encrypt(key: LacewingEncryptionKey): Promise<string> {
		if (!isLacewingEncryptionKey(key)) {
			throw new TypeError("encrypt() only accepts keys imported through importEncryptionKey()/generate*");
		}
		if (key.keyType === "private") {
			throw new KeyTypeMismatch("Encrypt to the recipient's public (or shared secret) key, not a private key");
		}
		const info = getKeyManagementProperties(key.algorithm);
		// A `dir` key IS the content-encryption key, so its size fixes the enc.
		if (info.kind === "dir") {
			const need = getContentEncryptionProperties(this.#enc).cekBytes;
			if ((key.key as Uint8Array).length !== need) {
				throw new KeyTypeMismatch(`This dir key is not sized for ${this.#enc} (needs ${need} bytes)`);
			}
		}
		if (this.#iss === undefined && !this.#waiveIssuer) {
			throw new MissingClaim("iss", "Tokens must name their issuer - call .issuer() (or .unsafeAllowMissingIssuer())");
		}
		if (this.#aud === undefined && !this.#waiveAudience) {
			throw new MissingClaim("aud", "Tokens must name their audience - call .audience() (or .unsafeAllowMissingAudience())");
		}
		if (this.#expiresIn === undefined && !this.#waiveExpiration) {
			throw new MissingClaim("exp", "Tokens must expire - call .expiresIn() (or .unsafeAllowMissingExpiration())");
		}
		if (this.#expiresIn !== undefined && this.#expiresIn > this.#maxLifetime) {
			throw new MaxLifetimeExceeded(
				`Requested lifetime exceeds the ${this.#maxLifetime}s cap - long-lived tokens need an explicit maxLifetime option`
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

		return new CompactEncrypt(encodeUTF8(JSON.stringify(payload)))
			.setProtectedHeader({ alg: key.algorithm, enc: this.#enc, typ: this.#typ })
			.encrypt(key.key as Parameters<CompactEncrypt["encrypt"]>[0]);
	}
}
