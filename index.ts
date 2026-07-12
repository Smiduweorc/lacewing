/**
 * Lacewing - an opinionated JWT library where RFC 8725 (JWT Best Current
 * Practices) is the default behavior, not an optional configuration.
 *
 * This barrel is the public API. Internals under `src/lib/` are policy
 * machinery and stay private; legacy interop algorithms live behind the
 * explicit `lacewing/legacy/*` imports.
 */

// Verification profiles + the one verification path
export { defineProfile, type ProfileOptions } from "./src/jwt/profile.js";
export { jwtVerify } from "./src/jwt/verify.js";

// Signing
export { SignJWT, type SignJwtOptions } from "./src/jwt/sign.js";

// Encryption (JWE) - same profile discipline as sign/verify
export { EncryptJWT, type EncryptJwtOptions } from "./src/jwt/encrypt.js";
export { jwtDecrypt } from "./src/jwt/decrypt.js";
export {
	defineDecryptionProfile,
	type DecryptionProfileOptions,
} from "./src/jwt/decryption_profile.js";
export {
	generateEncryptionKeyPair,
	generateEncryptionSecret,
	generateDirectKey,
	importEncryptionKey,
	type EncryptionKeyMaterial,
	type GenerateEncryptionKeyPairOptions,
} from "./src/key/encryption.js";

// Cookbook: the access-vs-refresh split, shipped rather than left as homework
export {
	accessTokenProfile,
	refreshTokenProfile,
	newAccessToken,
	newRefreshToken,
	ACCESS_TOKEN_TYP,
	REFRESH_TOKEN_TYP,
	type TokenProfileOptions,
} from "./src/cookbook/access-refresh.js";

// Keys
export { importKey, type KeyMaterial } from "./src/key/import.js";
export {
	generateKeyPair,
	generateSecret,
	type GenerateKeyPairOptions,
} from "./src/key/generate.js";
export { exportKeyJWK, exportKeyPEM } from "./src/key/export.js";

// JWKS key sources
export { createLocalJWKSet } from "./src/jwks/local.js";
export { createRemoteJWKSet, type RemoteJWKSetOptions } from "./src/jwks/remote.js";

// Revocation
export { buildRevocationContext } from "./src/revocation/store.js";
export { MemoryRevocationStore } from "./src/revocation/memory.js";

// HTTP transport helpers (the paved road: no localStorage, ever)
export {
	buildTokenCookie,
	setTokenCookie,
	clearTokenCookie,
	readTokenCookie,
	type TokenCookieOptions,
} from "./src/http/cookies.js";
export { parseBearer } from "./src/http/bearer.js";

// Debugging escape hatch - branded untrusted, incompatible with VerifiedJwt
export { unsafeDecode } from "./src/util/unsafe-decode.js";

// Typed errors
export {
	JWTError,
	JWTInvalid,
	JWTExpired,
	JWTClaimValidationFailed,
	MissingClaim,
	AlgorithmNotAllowed,
	KeyImportFailed,
	KeyExportFailed,
	KeyTypeMismatch,
	EntropyCheckFailed,
	JWKSFetchFailed,
	JWKSNoMatchingKey,
	JWTRevoked,
	RevocationCheckFailed,
	PayloadHygieneViolation,
	MaxLifetimeExceeded,
	BearerParseFailed,
} from "./src/util/errors.js";

// Public types
export {
	toSeconds,
	type ClaimsPolicy,
	type DecryptedJwt,
	type DurationSeconds,
	type ExpectedDecryptionProfile,
	type ExpectedJwtProfile,
	type JweHeader,
	type JwtHeader,
	type LacewingEncryptionKey,
	type JwtPayLoad,
	type JWKSConfig,
	type KeySource,
	type LacewingKey,
	type RemoteJWKS,
	type ResolvedVerificationKey,
	type RevocationStore,
	type StaticJWK,
	type StaticJWKS,
	type TokenRevocationContext,
	type UntrustedJwt,
	type ValidAlg,
	type ValidateClaim,
	type VerifiedJwt,
} from "./src/types.js";
