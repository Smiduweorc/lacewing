/*
 * Portions of this code are copied or adapted from the 'jose' library.
 * Copyright (c) Filip Skokan (panva)
 * Licensed under the MIT License.
 */

// Claim registry: https://www.iana.org/assignments/jwt/jwt.xhtml

/**
 * A string that has been validated against the algorithm registry.
 * `"none"` is unrepresentable (RFC 8725 §3.2).
 */
export type ValidAlg = string & { readonly __alg: unique symbol };

/**
 * Brand a string as a {@link ValidAlg}. Rejects `"none"` in any casing.
 * Registry membership is enforced separately by `lib/algorithms.ts`;
 * this brand only guarantees the value is not the `none` algorithm.
 */
export const SetAlg = (value: string): ValidAlg => {
	if (value.toLowerCase() === "none") {
		throw new Error("Algorithm 'none' is not allowed");
	}
	return value as ValidAlg;
};

/**
 * Seconds, branded so raw numbers must pass through {@link toSeconds}
 * (or `parseDuration`) before being used as a duration.
 */
export type DurationSeconds = number & { readonly __duration: unique symbol };

export function toSeconds(value: number): DurationSeconds {
	if (!Number.isFinite(value) || !Number.isInteger(value) || value < 0) {
		throw new TypeError("Duration must be a non-negative integer number of seconds");
	}
	return value as DurationSeconds;
}

export interface JwtHeader {
	alg: ValidAlg;
	typ: string;
	cty?: string;
	kid?: string; // case sensitive string, sanitized before any lookup (RFC 8725 §3.10)
}

export interface JwtPayLoad {
	iss: string;
	sub?: string; // Optional per standard
	aud: string | string[]; // Can be a string or an array of strings
	jti?: string; // Optional per RFC 7519; Lacewing auto-assigns one at sign time
	nbf?: number;
	exp: number;
	iat: number;
	[propName: string]: unknown;
}

/** @internal Shared shape behind {@link VerifiedJwt} and {@link UntrustedJwt}. */
type JwtShape = {
	header: JwtHeader;
	payload: JwtPayLoad;
};

/** Only ever produced by `jwtVerify` - proof that every check passed. */
export type VerifiedJwt = JwtShape & { readonly __brand: "VerifiedJwt" };
/** Produced by `unsafeDecode` - type-incompatible with {@link VerifiedJwt}. */
export type UntrustedJwt = JwtShape & { readonly __brand: "UntrustedJwt" };

declare const BrandSymbol: unique symbol;
export type Branded<T, BrandName extends string> = T & {
	readonly [BrandSymbol]: BrandName;
};

/**
 * A key bound to exactly one algorithm at import time.
 * The algorithm travels in the type parameter, so a `LacewingKey<"ES256">`
 * cannot be passed where a `LacewingKey<"HS256">` is expected.
 */
export type LacewingKey<Alg extends string = string> = {
	readonly __brand: "LacewingKey";
	readonly algorithm: Alg & ValidAlg;
	readonly keyType: "public" | "private" | "secret";
	/** The underlying CryptoKey / raw secret. Internal - do not touch. */
	readonly key: unknown;
};

/** Internal constructor - use `importKey` / `generateKeyPair` instead. */
export function createLacewingKey<const Alg extends string>(
	algorithm: Alg & ValidAlg,
	keyType: "public" | "private" | "secret",
	key: unknown
): LacewingKey<Alg> {
	return Object.freeze({
		__brand: "LacewingKey",
		algorithm,
		keyType,
		key,
	}) as LacewingKey<Alg>;
}

export function isLacewingKey(value: unknown): value is LacewingKey {
	return (
		typeof value === "object" &&
		value !== null &&
		(value as { __brand?: unknown }).__brand === "LacewingKey"
	);
}

export type StaticJWK = {
	kty: "RSA" | "EC" | "OKP" | "oct";
	use?: "sig" | "enc";
	alg?: string;
	kid?: string;
	[key: string]: unknown;
};

export type StaticJWKS = {
	keys: StaticJWK[];
};

export type RemoteJWKS = {
	jwksUri: string; // Forces them to supply the absolute URL to fetch from
	cacheTtlSeconds?: number;
	cooldownSeconds?: number;
	timeoutMs?: number;
};

export type JWKSConfig = StaticJWKS | RemoteJWKS;

/** A key resolved by a {@link KeySource} for one specific token. */
export interface ResolvedVerificationKey {
	alg: ValidAlg;
	key: unknown;
}

/**
 * Anything that can produce a verification key for a token header.
 * Implemented by `createLocalJWKSet` and `createRemoteJWKSet`.
 */
export interface KeySource {
	getVerificationKey(
		header: JwtHeader,
		allowedAlgorithms: readonly ValidAlg[]
	): Promise<ResolvedVerificationKey>;
}

export interface TokenRevocationContext {
	jti?: string; // Optional per RFC 7519
	sub?: string; // Optional to prevent runtime crashes on machine tokens
	sid?: string; // Optional Session ID
	exp: number;
	iat: number;
}

export interface RevocationStore {
	isRevoked(context: TokenRevocationContext): Promise<boolean>;
	isAnyRevoked?(contexts: TokenRevocationContext[]): Promise<boolean[]>;
}

export type ValidateClaim = (
	claimValue: unknown,
	fullPayload: Record<string, unknown>
) => void | Promise<void>;

/**
 * The claim-checking slice shared by the verify (JWS) and decrypt (JWE) paths.
 * Both {@link ExpectedJwtProfile} and {@link ExpectedDecryptionProfile}
 * satisfy it, so one claims engine serves both.
 */
export interface ClaimsPolicy {
	iss: string;
	aud: string;
	maxTokenAge: DurationSeconds;
	maxClockSkew: DurationSeconds;
	subject?: string;
	claimValidators?: Record<string, ValidateClaim>;
}

/**
 * A key bound to exactly one JWE key-management algorithm at import time - the
 * encryption counterpart of {@link LacewingKey}. Kept a distinct brand so an
 * encryption key can never be handed to `SignJWT.sign`, nor a signing key to
 * `EncryptJWT.encrypt`.
 */
export type LacewingEncryptionKey<Alg extends string = string> = {
	readonly __brand: "LacewingEncryptionKey";
	readonly algorithm: Alg & ValidAlg;
	readonly keyType: "public" | "private" | "secret";
	readonly key: unknown;
};

/** Internal constructor - use `importEncryptionKey` / `generateEncryptionKeyPair`. */
export function createLacewingEncryptionKey<const Alg extends string>(
	algorithm: Alg & ValidAlg,
	keyType: "public" | "private" | "secret",
	key: unknown
): LacewingEncryptionKey<Alg> {
	return Object.freeze({
		__brand: "LacewingEncryptionKey",
		algorithm,
		keyType,
		key,
	}) as LacewingEncryptionKey<Alg>;
}

export function isLacewingEncryptionKey(value: unknown): value is LacewingEncryptionKey {
	return (
		typeof value === "object" &&
		value !== null &&
		(value as { __brand?: unknown }).__brand === "LacewingEncryptionKey"
	);
}

/** A decrypted JWE's protected header (adds `enc` to the JWS header shape). */
export interface JweHeader {
	alg: ValidAlg;
	enc: ValidAlg;
	typ: string;
	cty?: string;
	kid?: string;
}

/**
 * Only ever produced by `jwtDecrypt`: proof that a token decrypted (and thus
 * authenticated by its AEAD) and passed every claim check. A distinct brand
 * from {@link VerifiedJwt} - the two are not interchangeable.
 */
export type DecryptedJwt = {
	header: JweHeader;
	payload: JwtPayLoad;
} & { readonly __brand: "DecryptedJwt" };

/**
 * The security boundary for decryption - the JWE analogue of
 * {@link ExpectedJwtProfile}. Built by `defineDecryptionProfile`, the only
 * argument shape `jwtDecrypt` accepts.
 */
export interface ExpectedDecryptionProfile extends ClaimsPolicy {
	typ: string;
	/** Allowlist of key-management (`alg`) algorithms; the header never decides. */
	keyManagementAlgorithms: readonly ValidAlg[];
	/** Allowlist of content-encryption (`enc`) algorithms. */
	contentEncryptionAlgorithms: readonly ValidAlg[];
	/** The private/secret key that decrypts (scoped to this profile's issuer). */
	key: LacewingEncryptionKey;
	revocation?: RevocationStore;
	unsafeFailOpenOnRevocationError?: boolean;
}

/**
 * The security boundary for verification (RFC 8725 §3.12).
 * Built by `defineProfile` - the only argument shape `jwtVerify` accepts.
 */
export interface ExpectedJwtProfile {
	typ: string;
	iss: string;
	aud: string; // The specific audience this API expects to be inside the token
	alg: readonly ValidAlg[];
	keys: KeySource | LacewingKey;
	maxTokenAge: DurationSeconds;
	maxClockSkew: DurationSeconds;
	revocation?: RevocationStore;
	claimValidators?: Record<string, ValidateClaim>;
	subject?: string;
	/**
	 * Deliberately ugly escape hatch: when the revocation store errors,
	 * accept the token anyway instead of failing closed (LW-rev.4).
	 */
	unsafeFailOpenOnRevocationError?: boolean;
}
