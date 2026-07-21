"""Self-signed certificate generation for Entra ID certificate credentials.

The relay can authenticate to Microsoft Graph with either a client secret
or a certificate (see `graph_client.GraphClient`). Certificate credentials
are more secure: only the *public* certificate is uploaded to the Entra app
registration, while the private key never leaves this deployment (it is
Fernet-encrypted at rest exactly like the client secret).

Because the application generates the key pair itself, the expiry date is
known at creation time — there is nothing for the operator to transcribe.

`cryptography` is already a dependency (Fernet), so this module adds no new
package.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# 2048-bit RSA is the Entra minimum and the pragmatic default: 4096 makes
# every token-signing operation noticeably heavier for no meaningful gain
# at this scale.
_RSA_KEY_SIZE = 2048

# Validity choices surfaced in the UI. Kept here so the router and the
# template validate against a single source of truth.
ALLOWED_VALIDITY_YEARS = (1, 2, 3, 5)
DEFAULT_VALIDITY_YEARS = 5

# Days per year used for the not-after horizon. 365 (no leap-day handling)
# is intentionally conservative — a certificate that expires a day or two
# "early" is harmless; one that lingers past its advertised date is not.
_DAYS_PER_YEAR = 365


@dataclass(slots=True)
class GeneratedCert:
    """A freshly minted self-signed certificate and its private key.

    `private_key_pem` is PKCS#8 PEM with **no** passphrase — the caller is
    expected to Fernet-encrypt it before persistence. `public_cert_pem` is
    what the operator uploads to Entra. `thumbprint_sha1` is the uppercase,
    colon-free hex SHA-1 fingerprint, matching what MSAL expects and what
    the Entra portal displays.
    """

    private_key_pem: str
    public_cert_pem: str
    thumbprint_sha1: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    subject_cn: str


def generate_self_signed(
    subject_cn: str = "smtp-relay",
    valid_years: int = DEFAULT_VALIDITY_YEARS,
) -> GeneratedCert:
    """Generate an RSA key pair + self-signed X.509 certificate.

    Raises ValueError if `valid_years` is not one of ALLOWED_VALIDITY_YEARS.
    """
    if valid_years not in ALLOWED_VALIDITY_YEARS:
        raise ValueError(
            f"valid_years must be one of {ALLOWED_VALIDITY_YEARS}, got {valid_years!r}"
        )

    key = rsa.generate_private_key(public_exponent=65537, key_size=_RSA_KEY_SIZE)

    now = _dt.datetime.now(_dt.timezone.utc)
    # Back-date not-before slightly to tolerate small clock skew between
    # this host and Entra.
    not_before = now - _dt.timedelta(minutes=5)
    not_after = now + _dt.timedelta(days=_DAYS_PER_YEAR * valid_years)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: subject == issuer
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()

    return GeneratedCert(
        private_key_pem=private_key_pem,
        public_cert_pem=public_cert_pem,
        thumbprint_sha1=thumbprint,
        not_before=not_before,
        not_after=not_after,
        subject_cn=subject_cn,
    )
