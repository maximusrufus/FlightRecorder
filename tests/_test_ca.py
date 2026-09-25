"""Test-only helper: build a real X.509 root CA + TSA leaf cert, and sign a
real RFC 3161 CMS TimeStampToken over an arbitrary digest — entirely
offline, using `cryptography` + `asn1crypto`. Used by
`test_rfc3161_verify.py` so the full CMS verification path is tested
against a token that is byte-for-byte a real, spec-shaped TSA response,
never a live network call.
"""

from __future__ import annotations

import datetime
import hashlib

from asn1crypto import cms, core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class TestCA:
    def __init__(self):
        self.root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "FlightRecorder Test Root")]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        self.root_cert = (
            x509.CertificateBuilder()
            .subject_name(root_name)
            .issuer_name(root_name)
            .public_key(self.root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(self.root_key, hashes.SHA256())
        )

        self.tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        tsa_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "FlightRecorder Test TSA")]
        )
        self.tsa_cert = (
            x509.CertificateBuilder()
            .subject_name(tsa_name)
            .issuer_name(root_name)
            .public_key(self.tsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                critical=True,
            )
            .sign(self.root_key, hashes.SHA256())
        )

    def root_der(self) -> bytes:
        return self.root_cert.public_bytes(serialization.Encoding.DER)

    def sign_token(
        self,
        digest: bytes,
        *,
        wrong_signature: bool = False,
        wrong_imprint: bool = False,
    ) -> bytes:
        """Build a real RFC3161 CMS TimeStampToken over `digest`, signed by
        this CA's TSA leaf. `wrong_signature`/`wrong_imprint` produce
        deliberately-broken tokens for negative tests."""
        imprint_digest = (b"\x00" * 32) if wrong_imprint else digest

        tst_info = tsp_tst_info(imprint_digest)
        tst_info_der = tst_info.dump()
        econtent_digest = hashlib.sha256(tst_info_der).digest()

        signed_attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
                cms.CMSAttribute(
                    {"type": "message_digest", "values": [econtent_digest]}
                ),
            ]
        )

        leaf_asn1 = asn1_x509.Certificate.load(
            self.tsa_cert.public_bytes(serialization.Encoding.DER)
        )

        to_sign = signed_attrs.dump()
        if wrong_signature:
            sig = self.root_key.sign(
                to_sign, padding.PKCS1v15(), hashes.SHA256()
            )  # wrong key
        else:
            sig = self.tsa_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())

        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                            {
                                "issuer": leaf_asn1.issuer,
                                "serial_number": leaf_asn1.serial_number,
                            }
                        )
                    }
                ),
                "digest_algorithm": {"algorithm": "sha256"},
                "signed_attrs": signed_attrs,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": sig,
            }
        )

        signed_data = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {
                    "content_type": "tst_info",
                    "content": cms.ParsableOctetString(tst_info_der),
                },
                "certificates": [cms.CertificateChoices({"certificate": leaf_asn1})],
                "signer_infos": [signer_info],
            }
        )

        content_info = cms.ContentInfo(
            {"content_type": "signed_data", "content": signed_data}
        )
        return content_info.dump()


def tsp_tst_info(digest: bytes):
    from asn1crypto import tsp

    return tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": digest,
            },
            "serial_number": 1,
            "gen_time": core.GeneralizedTime(
                datetime.datetime.now(datetime.timezone.utc)
            ),
        }
    )


def build_other_root() -> bytes:
    """A second, unrelated root cert -- used to test 'wrong root' rejection."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some Other Root")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)
