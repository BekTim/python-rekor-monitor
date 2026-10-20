"""Unit tests for util.py with freshly generated keys. No network."""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from util import extract_public_key, verify_artifact_signature

PEM = serialization.Encoding.PEM
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def make_certificate(key: ec.EllipticCurvePrivateKey) -> bytes:
    """A self-signed PEM certificate for the given key."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(PEM)


def test_extract_public_key_matches_certificate_key() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    expected = key.public_key().public_bytes(PEM, SPKI)
    assert extract_public_key(make_certificate(key)) == expected


def test_signature_valid_then_tampered(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    public_pem = extract_public_key(make_certificate(key))
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"trb9598\n")
    signature = key.sign(b"trb9598\n", ec.ECDSA(hashes.SHA256()))

    assert verify_artifact_signature(signature, public_pem, str(artifact)) is True
    artifact.write_bytes(b"tampered\n")
    assert verify_artifact_signature(signature, public_pem, str(artifact)) is False


def test_non_elliptic_curve_key_is_rejected(tmp_path: Path) -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_key.public_key().public_bytes(PEM, SPKI)
    artifact = tmp_path / "artifact.md"
    artifact.write_bytes(b"data")
    assert verify_artifact_signature(b"sig", rsa_pem, str(artifact)) is False
