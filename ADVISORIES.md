---
title: Security advisories
---

# Security advisories

Every security advisory published for Lacewing, newest first. Each one links
to its GitHub advisory, which carries the full write-up: details, a proof of
concept where there is one, and workarounds for anyone who cannot upgrade yet.

Fixes ship for the latest minor version only (see [SECURITY.md](./SECURITY.md)).
If your installed version falls inside an affected range below, upgrade.

| Advisory | Severity | Affected | Fixed in | Published |
| --- | --- | --- | --- | --- |
| [GHSA-x2q2-4jwp-wfgg](https://github.com/Smiduweorc/lacewing/security/advisories/GHSA-x2q2-4jwp-wfgg) | Low | <= 1.2.0 | 1.2.1 | 2026-10-10 |
| [GHSA-vwp5-4h2j-vhhq](https://github.com/Smiduweorc/lacewing/security/advisories/GHSA-vwp5-4h2j-vhhq) | Medium | 1.0.0 | 1.0.1 | 2026-07-29 |
| [GHSA-gg54-pwrg-hjx7](https://github.com/Smiduweorc/lacewing/security/advisories/GHSA-gg54-pwrg-hjx7) | Low | 1.0.0 | 1.0.1 | 2026-07-29 |

## GHSA-x2q2-4jwp-wfgg: JWKS keys without `alg` verify under every allowlisted algorithm of their key type

A JWKS entry with no `alg` member could be used under every algorithm in the
profile's allowlist that shares its key type, so one RSA key verified PS256,
PS384 and PS512 tokens, and one `oct` key verified HS256, HS384 and HS512. That
breaks RFC 8725 §3.1's "one key, one algorithm". Custom key sources had the
same gap: the `alg` they returned was ignored, and raw HMAC secrets they
returned skipped the strength check.

You are affected only if a profile allows more than one RSA or more than one
HMAC algorithm *and* uses a JWKS key without `alg` or a custom key source. No
forgery is known to follow from it.

**Workaround:** set `alg` on every JWKS key, or allow one algorithm per key
type per profile.

## GHSA-vwp5-4h2j-vhhq: Revoked JWKS keys stay trusted indefinitely while the endpoint is unreachable

`createRemoteJWKSet` served the last good key set for as long as refetches
kept failing, with no upper bound. A key removed from the JWKS because it was
compromised stayed trusted for the whole outage, and an attacker holding that
key has a reason to cause one. 1.0.1 added the bounded `staleWhileErrorSeconds`
window.

**Workaround:** pin keys directly, or use a custom key source with your own
freshness policy. Lowering `cacheTtlSeconds` does not help.

## GHSA-gg54-pwrg-hjx7: `jwtDecrypt` accepts non-canonical base64url, making JWE token strings malleable

Only the JWE header segment was strictly decoded. Unused trailing bits in the
other segments could be changed without changing the plaintext, so one
token had several valid spellings. Confidentiality and integrity are
unaffected, but anything keyed on the raw token string (denylists, replay
caches) could be bypassed. Revocation keyed on `jti` was unaffected.
