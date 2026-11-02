---
title: Evidence
---

# Evidence

**What the test suite proves about Lacewing, what it leaves to jose and Node, and how to re-run each part.**

## The requirement gate

Every RFC 8725 (JWT Best Current Practices) requirement a library can check,
and every Lacewing guarantee the docs make, is a row in
`tests/compliance/requirements.json`. Tests name the rows they prove in their
titles (`[8725-3.1.1] ...`), and `npm run compliance` runs the suite and fails
if any row has no passing test. It writes the matrix to `compliance-report.md`.

## Whose code does the cryptography

**The signature maths is not ours.** Lacewing enforces the *policy* RFC 8725 asks for. The ECDSA and EdDSA signing and verifying, curve point checks, and nonce generation are done by [jose](https://github.com/panva/jose) on top of Node's WebCrypto (OpenSSL). Lacewing does not control or re-check them. ECDSA nonces are whatever Node's OpenSSL build produces (randomised, not RFC 6979 deterministic), and low-level primitive conformance is only as good as your Node version. The compliance suite tests that Lacewing calls these primitives correctly, not the primitives themselves.

**Built on jose.** Lacewing does not reimplement cryptography. It is a policy layer over [jose](https://github.com/panva/jose), so the code that's ours is the policy, not the crypto. Tokens Lacewing signs or encrypts are standard JWTs/JWEs.

## Tokens Lacewing did not make

`tests/conformance/golden/` holds tokens Lacewing did not make. Seven were built with no JOSE library at all and must be accepted: HS256 from the OpenSSL CLI, and Ed25519, ES256, PS256, `dir`/A256GCM and ECDH-ES+A256KW/A256GCM from pyca/cryptography (`tools/golden-vectors.py` is how; re-run it and diff). One more OpenSSL token must be refused for its audience. The four RFC 7515/7516/7519 worked examples are all *refused*, each for the reason it should be: no `aud`, no `typ`, `RSA1_5`, `RSA-OAEP` with SHA-1. No RFC example can pass, because none of them carries a `typ` and an `aud`. Separately, the jose round-trip tests show jose accepts what Lacewing signs, which mostly shows we call jose correctly, since that is what Lacewing is built on.
