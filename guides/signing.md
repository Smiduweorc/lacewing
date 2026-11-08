---
title: Signing and encrypting
---

# Signing and encrypting

## Signing

```ts
import { SignJWT, generateKeyPair } from "lacewing";

const { publicKey, privateKey } = await generateKeyPair(); // EdDSA by default

const token = await new SignJWT("at+jwt")
	.issuer("https://auth.example.com")
	.audience("https://api.example.com")
	.subject("user-42")
	.claim("scope", "read")
	.expiresIn("10m")
	.sign(privateKey);
```

`typ` is a constructor argument, and `.sign()` refuses to run without
`issuer`, `audience` and `expiresIn` unless you call the matching
`unsafeAllowMissing*()`. Every token gets a random `jti` unless you set one
with `.jwtId()`, and `iat` is set at sign time. Lifetimes are capped at 1h by
default (`MAX_LIFETIME_EXCEEDED` above that). Raise the cap with
`new SignJWT("at+jwt", { maxLifetime: "24h" })`, up to 30 days; beyond that
it takes `unsafeAllowLongLifetime: true`.

`SignJWT` writes only `alg` and `typ` to the header and cannot set a `kid`.
That matters when you rotate keys behind a JWKS; see "Before you plan a
rotation" in [Getting started](../GETTING-STARTED.md).

## The payload scanner

A JWS payload is base64url-encoded plaintext, readable by anyone who holds
the token, so the payload is scanned before signing. It refuses claim names
that read as passwords, secrets, API or private keys, tokens, SSNs or card
data, and values that are PEM private keys, other JWTs or JWEs, or card
numbers with a real brand prefix, length and Luhn check, written as text or
as a number. Names are matched by word: `apiKey` and `accesstoken` are
refused, `businessName` and `tokenizer` are not.

```ts
await new SignJWT("at+jwt")
	.issuer(ISSUER).audience(AUDIENCE).expiresIn("5m")
	.claim("password", "hunter2")
	.sign(privateKey); // throws PAYLOAD_HYGIENE_VIOLATION
```

It catches the copy-paste accident. It does not catch a password in a claim
called `note`, base64 of anything, or anything else that looks like ordinary
text. Don't put secrets in a signed payload, scanner or no scanner.

For a real false positive, waive one claim, or one field inside it, by path.
The refusal tells you the path to write. A waiver covers that node and what's
under it, nothing beside it:

```ts
.unsafeAllowClaim("password_changed_at")
.unsafeAllowClaim("profile", "passwordHint") // only this nested field
```

## HMAC

`HS256`, `HS384` and `HS512` work, but every verifier holds the secret and
can therefore also sign tokens. Use asymmetric keys and a JWKS unless it is
one service.

`importKey` enforces the RFC 7518 length floor and an entropy check, so
`"my-secret-password-123"` throws `ENTROPY_CHECK_FAILED` at startup. A string
secret must be random bytes written as hex or base64(url), long enough for
the algorithm: for HS256 that is 64 hex or 43 base64 characters. Spaces and
punctuation are refused, which also catches generators that mix in symbols.
If that fires on a secret you already use, replace the secret.

The check cannot tell a random 32 bytes from a long string you made up, and
the made-up one will pass. Use `generateSecret("HS256")`, which produces one
at the algorithm's minimum size, and don't hand-write key material.

Symmetric keys are refused from a remote JWKS ([Verifying](./verifying.md)).

## Encrypting (JWE)

A signed JWT is readable. When the payload has to be hidden, use an
encrypted JWT. The same rules apply as for signing (mandatory `typ`, required
`iss`/`aud`/`exp`, a `jti`, a capped lifetime), with a fixed set of
encryption algorithms. The payload scanner is off here, since hiding the
payload is the point:

```ts
import {
  EncryptJWT, jwtDecrypt, defineDecryptionProfile, generateEncryptionKeyPair,
} from "lacewing";

const { publicKey, privateKey } = await generateEncryptionKeyPair("ECDH-ES+A256KW");

const token = await new EncryptJWT("at+jwt", { contentEncryption: "A256GCM" })
  .issuer("https://auth.example.com")
  .audience("https://api.example.com")
  .subject("user-42")
  .claim("ssn", "123-45-6789") // allowed: the payload is encrypted
  .expiresIn("10m")
  .encrypt(publicKey);

const profile = defineDecryptionProfile({
  typ: "at+jwt",
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  keyManagementAlgorithms: ["ECDH-ES+A256KW"],
  contentEncryptionAlgorithms: ["A256GCM"],
  key: privateKey,
  maxTokenAge: "10m",
});

const { payload } = await jwtDecrypt(token, profile); // DecryptedJwt, distinct from VerifiedJwt
```

`none`, `RSA1_5`, `RSA-OAEP` (SHA-1) and the password-based `PBES2*` family
are not available. A JWS handed to `jwtDecrypt`, or a JWE handed to
`jwtVerify`, is rejected. The age, skew and validator rules apply to
decryption profiles the same way.

The `A192*` algorithms (`A192KW`, `A192GCMKW`, `A192GCM`, `A192CBC-HS384`)
work on Node 24, but WebCrypto in browsers and some edge runtimes does not
implement 192-bit AES. If tokens must be decrypted outside Node, use the
`A128*` or `A256*` variants. There is no security reason to prefer 192-bit
anyway.
