---
title: Signing and encrypting
---

# Signing and encrypting

**What `SignJWT` refuses, the payload scanner, HMAC, and encrypted JWTs.**

## Signing

`typ` is a constructor argument, and `.sign()` refuses to run without
`issuer`, `audience` and `expiresIn` (waivable only via
`unsafeAllowMissing*` calls). Every token gets a random `jti` unless you set
one with `.jwtId()`, and lifetimes are capped: 1h by default, raisable to 30
days with `maxLifetime`, beyond that only with `unsafeAllowLongLifetime`.

Then the payload scanner runs, because **a JWS payload is base64url-encoded plaintext**,
readable by anyone who holds the token. It refuses claim names
that read as passwords, secrets, API or private keys, tokens, SSNs or card
data (matched by word: `apiKey` and `accesstoken` are refused, `businessName`
and `tokenizer` are not), and values that are PEM private keys, other JWTs or
JWEs, or card numbers with a real brand prefix, length and Luhn check, written
as text or as a number. That catches
the copy-paste accident. It does not catch a password in a claim called
`note`, base64 of anything, or anything else that looks like ordinary text.
Never put secrets in it, scanner or no scanner.

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

For a real false positive, waive one claim, or one field inside it, by path:
`.unsafeAllowClaim("profile", "passwordHint")`. The refusal tells you the
path to write. A waiver covers that node and what's under it, nothing beside
it.

A note on HMAC (`HS256/384/512`): it is supported, but every verifier of an
HMAC token holds the same secret and can therefore also **mint** them. For
anything beyond a single service, use asymmetric keys + JWKS. HMAC secrets
must meet the RFC 7518 length floor and pass an entropy check, so
`"my-secret"` will not import, ever. What no library can do is prove a byte
string came out of a random number generator, so a long, high-entropy string
a human made up will import. PLEASE use `generateSecret()` and don't
hand-write key material. Symmetric keys are also refused from a *remote*
JWKS: that endpoint is public, so a secret published there is one anyone can
mint with.

## Encrypting (JWE): when the payload really is a secret

A signed JWT is readable plaintext. When you genuinely need the payload
*hidden*, not just tamper-evident, use an encrypted JWT. Same discipline as
signing (mandatory `typ`, required `iss`/`aud`/`exp`, a `jti`, capped
lifetime), but with a curated set of encryption algorithms and no `none`. The
sign-time payload scanner is off here, since hiding secrets is the whole
point:

```ts
import {
  EncryptJWT, jwtDecrypt, defineDecryptionProfile, generateEncryptionKeyPair,
} from "lacewing";

const { publicKey, privateKey } = await generateEncryptionKeyPair("ECDH-ES+A256KW");

const token = await new EncryptJWT("at+jwt", { contentEncryption: "A256GCM" })
  .issuer("https://auth.example.com")
  .audience("https://api.example.com")
  .subject("user-42")
  .claim("ssn", "123-45-6789") // fine: it's encrypted, not just encoded
  .expiresIn("10m")
  .encrypt(publicKey);

const profile = defineDecryptionProfile({
  typ: "at+jwt",
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  keyManagementAlgorithms: ["ECDH-ES+A256KW"], // the header never chooses
  contentEncryptionAlgorithms: ["A256GCM"],
  key: privateKey,
  maxTokenAge: "10m",
});

const { payload } = await jwtDecrypt(token, profile); // DecryptedJwt, distinct from VerifiedJwt
```

`none`, `RSA1_5`, `RSA-OAEP` (SHA-1) and the password-based `PBES2*` family are
absent by construction. A JWS handed to `jwtDecrypt` (or a JWE handed to
`jwtVerify`) is rejected: the two formats never cross over. The age, skew and
validator rules above apply to decryption profiles the same way.

**Portability (192-bit AES):** the registry includes the `A192*`
algorithms (`A192KW`, `A192GCMKW`, `A192GCM`, `A192CBC-HS384`) for JOSE
completeness, and they work on Node >= 24 (Lacewing's floor). But WebCrypto
implementations in browsers and some edge runtimes do not implement 192-bit
AES at all. If tokens must be decrypted outside Node, stick to the `A128*` /
`A256*` variants. There is no security reason to prefer 192-bit anyway.
