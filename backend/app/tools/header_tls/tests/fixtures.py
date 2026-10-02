"""Fixture servers for the header/TLS checker: real sockets on 127.0.0.1.

Certificates are minted per test session with ``cryptography`` (a private
test CA, a valid "localhost" leaf, an expired leaf, a self-signed one and one
for the wrong host), so no certificate files are committed to the repo.
"""

import asyncio
import datetime
import ssl
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = datetime.datetime.now(datetime.UTC)


@dataclass(frozen=True)
class Pem:
    cert: Path
    key: Path


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(
    directory: Path, stem: str, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey
) -> Pem:
    cert_path = directory / f"{stem}.crt"
    key_path = directory / f"{stem}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return Pem(cert_path, key_path)


@dataclass
class Certs:
    directory: Path
    ca: Path
    good: Pem
    expired: Pem
    self_signed: Pem
    wrong_host: Pem


def make_certs() -> Certs:
    directory = Path(tempfile.mkdtemp(prefix="sentinel-tls-"))
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("Sentinel Test CA"))
        .issuer_name(_name("Sentinel Test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - datetime.timedelta(days=30))
        .not_valid_after(NOW + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    ca_path = directory / "ca.crt"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def leaf(
        stem: str, names: list[str], days_before: int, days_after: int, *, self_sign: bool = False
    ) -> Pem:
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(names[0]))
            .issuer_name(_name(names[0]) if self_sign else ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW + datetime.timedelta(days=days_before))
            .not_valid_after(NOW + datetime.timedelta(days=days_after))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False
            )
        )
        cert = builder.sign(key if self_sign else ca_key, hashes.SHA256())
        return _write(directory, stem, cert, key)

    return Certs(
        directory=directory,
        ca=ca_path,
        good=leaf("good", ["localhost"], -1, 200),
        expired=leaf("expired", ["localhost"], -90, -10),
        self_signed=leaf("selfsigned", ["localhost"], -1, 200, self_sign=True),
        wrong_host=leaf("wronghost", ["other.example"], -1, 200),
    )


GOOD_HEADERS = [
    ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
    ("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=()"),
    ("Server", "nginx"),
    ("Set-Cookie", "sessionid=TOPSECRETVALUE; Path=/; Secure; HttpOnly; SameSite=Lax"),
]

BAD_HEADERS = [
    ("Server", "Apache/2.4.29 (Ubuntu)"),
    ("X-Powered-By", "PHP/7.2.24"),
    ("Content-Security-Policy", "default-src * 'unsafe-inline'"),
    ("Referrer-Policy", "unsafe-url"),
    ("Set-Cookie", "sessionid=TOPSECRETVALUE; Path=/"),
    ("Set-Cookie", "prefs=dark; SameSite=None"),
]


@dataclass
class Server:
    port: int
    sni_seen: list[str | None] = field(default_factory=list)
    requests: list[bytes] = field(default_factory=list)


@asynccontextmanager
async def serve(
    headers: list[tuple[str, str]],
    *,
    status: str = "200 OK",
    pem: Pem | None = None,
) -> AsyncIterator[Server]:
    """A one-route HTTP(S) server returning ``status`` and ``headers``."""
    server_state = Server(port=0)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(reader.read(4096), 5)
            server_state.requests.append(request)
            lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers]
            lines += ["Content-Length: 2", "Connection: close", "", "ok"]
            writer.write("\r\n".join(lines).encode())
            await writer.drain()
        except (TimeoutError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    context = None
    if pem is not None:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(str(pem.cert), str(pem.key))

        def remember_sni(sock: ssl.SSLObject, name: str | None, ctx: ssl.SSLContext) -> None:
            server_state.sni_seen.append(name)

        context.sni_callback = remember_sni
    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    server_state.port = server.sockets[0].getsockname()[1]
    try:
        yield server_state
    finally:
        server.close()
