"""Локальный TLS-сертификат создаётся один раз в Docker volume."""

import datetime
import ipaddress
import ssl
from pathlib import Path
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

cert, key = Path("/certs/localhost.crt"), Path("/certs/localhost.key")
if not cert.exists():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(private, hashes.SHA256())
    )
    key.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key.chmod(0o600)
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
uvicorn.run(
    "app.main:app",
    host="0.0.0.0",
    port=8443,
    ssl_keyfile=str(key),
    ssl_certfile=str(cert),
    ssl_version=ssl.PROTOCOL_TLS_SERVER,
    access_log=False,
)
