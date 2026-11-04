"""Write the pyca/cryptography golden vectors under tests/conformance/golden/.

Every token here is built from RFC 7515/7516/7518 by hand over
pyca/cryptography primitives, with no JOSE library involved, so a vector
Lacewing accepts is evidence of interop rather than of agreeing with itself.

The golden directory is append-only: this refuses to overwrite a vector that
already exists. ECDSA and RSA-PSS signatures and the JWE CEK and IV are
random, so a re-run produces different (equally valid) tokens; the committed
files are the evidence, this script is how they were made.

Run from the repository root: python3 -I tools/golden-vectors.py
"""

import base64
import json
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

GOLDEN = Path("tests/conformance/golden")
ISSUER = "https://auth.example.com"
AUDIENCE = "https://api.example.com"
IAT = 1767225600  # 2026-01-01T00:00:00Z
CLOCK_AT = IAT + 60


def b64url(data: bytes) -> str:
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def int_bytes(value: int, length: int) -> bytes:
	return value.to_bytes(length, "big")


def segment(obj: dict) -> str:
	return b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def claims(jti: str) -> dict:
	return {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-42", "jti": jti, "iat": IAT, "exp": IAT + 300}


def ec_public_jwk(key: ec.EllipticCurvePublicKey) -> dict:
	numbers = key.public_numbers()
	return {"kty": "EC", "crv": "P-256", "x": b64url(int_bytes(numbers.x, 32)), "y": b64url(int_bytes(numbers.y, 32))}


def es256() -> dict:
	key = ec.generate_private_key(ec.SECP256R1())
	signing_input = f"{segment({'alg': 'ES256', 'typ': 'at+jwt'})}.{segment(claims('golden-es256-1'))}"
	# RFC 7518 3.4: the JWS signature is R || S, not the DER pyca returns.
	r, s = decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
	token = f"{signing_input}.{b64url(int_bytes(r, 32) + int_bytes(s, 32))}"
	return {
		"name": "python-cryptography-produced ES256 token that meets policy - verifies",
		"source": "pyca/cryptography EllipticCurvePrivateKey.sign, DER converted to R||S by hand (no jose involved)",
		"description": "A policy-compliant ES256 token signed by pyca/cryptography over the exact signing input, with the DER signature re-encoded as RFC 7518 3.4 R||S, verified against the public key as an EC JWK. Written by tools/golden-vectors.py. Clock pinned to 2026-01-01T00:01:00Z.",
		"format": "jws",
		"clockAt": CLOCK_AT,
		"token": token,
		"key": ec_public_jwk(key.public_key()),
		"keyAlg": "ES256",
		"profile": {"typ": "at+jwt", "issuer": ISSUER, "audience": AUDIENCE, "algorithms": ["ES256"], "maxTokenAge": "15m"},
		"relatedRequirements": ["8725-3.1.1", "8725-3.4.1"],
		"expect": {"outcome": "accept", "claims": {"sub": "user-42", "jti": "golden-es256-1"}},
	}


def ps256() -> dict:
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	signing_input = f"{segment({'alg': 'PS256', 'typ': 'at+jwt'})}.{segment(claims('golden-ps256-1'))}"
	# RFC 7518 3.5: MGF1 with the same hash, salt as long as the hash output.
	signature = key.sign(
		signing_input.encode("ascii"),
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
		hashes.SHA256(),
	)
	numbers = key.public_key().public_numbers()
	return {
		"name": "python-cryptography-produced PS256 token that meets policy - verifies",
		"source": "pyca/cryptography RSAPrivateKey.sign with PSS/MGF1-SHA256, 32-byte salt (no jose involved)",
		"description": "A policy-compliant PS256 token signed by pyca/cryptography over the exact signing input with RFC 7518 3.5 parameters, verified against a 2048-bit RSA public key as a JWK. Written by tools/golden-vectors.py. Clock pinned to 2026-01-01T00:01:00Z.",
		"format": "jws",
		"clockAt": CLOCK_AT,
		"token": f"{signing_input}.{b64url(signature)}",
		"key": {
			"kty": "RSA",
			"n": b64url(int_bytes(numbers.n, 256)),
			"e": b64url(int_bytes(numbers.e, 3)),
			"alg": "PS256",
		},
		"keyAlg": "PS256",
		"profile": {"typ": "at+jwt", "issuer": ISSUER, "audience": AUDIENCE, "algorithms": ["PS256"], "maxTokenAge": "15m"},
		"relatedRequirements": ["8725-3.1.1"],
		"expect": {"outcome": "accept", "claims": {"sub": "user-42", "jti": "golden-ps256-1"}},
	}


def concat_kdf(shared: bytes, algorithm_id: str, bits: int) -> bytes:
	# RFC 7518 4.6.2: AlgorithmID, PartyUInfo, PartyVInfo each length-prefixed;
	# SuppPubInfo is the key length in bits; apu and apv are empty here.
	def prefixed(data: bytes) -> bytes:
		return struct.pack(">I", len(data)) + data

	other_info = prefixed(algorithm_id.encode("ascii")) + prefixed(b"") + prefixed(b"") + struct.pack(">I", bits)
	return ConcatKDFHash(algorithm=hashes.SHA256(), length=bits // 8, otherinfo=other_info).derive(shared)


def ecdh_es_a256kw() -> dict:
	recipient = ec.generate_private_key(ec.SECP256R1())
	ephemeral = ec.generate_private_key(ec.SECP256R1())
	kek = concat_kdf(ephemeral.exchange(ec.ECDH(), recipient.public_key()), "ECDH-ES+A256KW", 256)
	cek = os.urandom(32)
	header = segment({
		"alg": "ECDH-ES+A256KW",
		"enc": "A256GCM",
		"typ": "at+jwt",
		"epk": ec_public_jwk(ephemeral.public_key()),
	})
	iv = os.urandom(12)
	sealed = AESGCM(cek).encrypt(iv, json.dumps(claims("golden-ecdh-1"), separators=(",", ":")).encode("utf-8"), header.encode("ascii"))
	ciphertext, tag = sealed[:-16], sealed[-16:]
	token = ".".join([header, b64url(aes_key_wrap(kek, cek)), b64url(iv), b64url(ciphertext), b64url(tag)])
	private = recipient.private_numbers()
	return {
		"name": "python-cryptography-produced ECDH-ES+A256KW/A256GCM JWE that meets policy - decrypts",
		"source": "pyca/cryptography ECDH, ConcatKDFHash, aes_key_wrap and AESGCM over the compact-JWE construction (no jose involved)",
		"description": "A policy-compliant encrypted JWT assembled by hand: P-256 ECDH with an ephemeral key carried as epk, the RFC 7518 4.6.2 Concat KDF with empty apu/apv, the CEK wrapped with AES-256 key wrap, and AES-256-GCM over the payload with the protected header as AAD. Written by tools/golden-vectors.py. Clock pinned to 2026-01-01T00:01:00Z.",
		"format": "jwe",
		"clockAt": CLOCK_AT,
		"token": token,
		"key": {**ec_public_jwk(recipient.public_key()), "d": b64url(int_bytes(private.private_value, 32))},
		"keyAlg": "ECDH-ES+A256KW",
		"profile": {
			"typ": "at+jwt",
			"issuer": ISSUER,
			"audience": AUDIENCE,
			"keyManagementAlgorithms": ["ECDH-ES+A256KW"],
			"contentEncryptionAlgorithms": ["A256GCM"],
			"maxTokenAge": "15m",
		},
		"relatedRequirements": ["LW-enc.2"],
		"expect": {"outcome": "accept", "claims": {"sub": "user-42", "jti": "golden-ecdh-1"}},
	}


VECTORS = {
	"pyca-es256-accept.json": es256,
	"pyca-ps256-accept.json": ps256,
	"pyca-ecdh-es-a256kw-accept.json": ecdh_es_a256kw,
}


def main() -> int:
	for name, build in VECTORS.items():
		path = GOLDEN / name
		if path.exists():
			print(f"{path} exists; golden vectors are append-only, leaving it", file=sys.stderr)
			continue
		text = json.dumps(build(), indent="\t", ensure_ascii=True) + "\n"
		path.write_text(text, encoding="ascii")
		print(f"wrote {path}")
	return 0


if __name__ == "__main__":
	sys.exit(main())
