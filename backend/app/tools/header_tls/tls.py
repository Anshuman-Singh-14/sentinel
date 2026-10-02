"""TLS inspection with the standard ``ssl`` module (plus ``cryptography`` for parsing).

Three handshakes to the *pinned* address, each bounded by a timeout:

1. **Verified** (system trust store, hostname check). Success means the chain
   and the name are valid. On failure the ``ssl`` error says why (expired,
   self-signed, unknown issuer, hostname mismatch).
2. **Unverified**, only when (1) failed: to read the certificate anyway, so
   an expired or self-signed certificate can still be described. Nothing is
   sent over this connection.
3. **Legacy probe**: TLS 1.0/1.1 only. If the server accepts it, it still
   allows protocols deprecated by RFC 8996. Some client builds cannot even
   offer these versions; the result is then "not tested", never a guess.
"""

import asyncio
import contextlib
import datetime
import ipaddress
import ssl
import warnings
from dataclasses import asdict, dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

HANDSHAKE_TIMEOUT = 8.0

# OpenSSL X509_V_ERR codes worth naming (openssl/x509_vfy.h).
VERIFY_REASONS = {
    9: "not_yet_valid",
    10: "expired",
    18: "self_signed",
    19: "self_signed_chain",
    20: "unknown_issuer",
    21: "unknown_issuer",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
}


@dataclass(slots=True)
class CertInfo:
    subject: str
    issuer: str
    common_name: str | None
    san_dns: list[str]
    san_ip: list[str]
    not_before: str
    not_after: str
    days_remaining: int
    serial: str
    signature_hash: str | None
    key_type: str
    key_bits: int | None
    self_signed: bool


@dataclass(slots=True)
class TlsInfo:
    reachable: bool
    error: str | None = None
    protocol: str | None = None
    cipher: str | None = None
    verified: bool = False
    verify_reason: str | None = None  # see VERIFY_REASONS
    verify_message: str | None = None
    hostname_match: bool | None = None
    legacy_protocols_accepted: bool | None = None  # None = could not be tested
    cert: CertInfo | None = None
    notes: list[str] = field(default_factory=list)


def _name(value: x509.Name) -> str:
    return value.rfc4514_string()


def _cn(value: x509.Name) -> str | None:
    attrs = value.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def parse_certificate(der: bytes, now: datetime.datetime | None = None) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.datetime.now(datetime.UTC)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_dns = [str(n) for n in san.get_values_for_type(x509.DNSName)]
        san_ip = [str(n) for n in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san_dns, san_ip = [], []
    key = cert.public_key()
    key_type: str
    key_bits: int | None
    if isinstance(key, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, key_bits = f"EC ({key.curve.name})", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, key_bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, key_bits = "Ed448", 456
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", key.key_size
    else:
        key_type, key_bits = type(key).__name__, None
    not_after = cert.not_valid_after_utc
    return CertInfo(
        subject=_name(cert.subject),
        issuer=_name(cert.issuer),
        common_name=_cn(cert.subject),
        san_dns=san_dns[:100],
        san_ip=san_ip[:100],
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=not_after.isoformat(),
        days_remaining=(not_after - now).days,
        serial=format(cert.serial_number, "x"),
        signature_hash=cert.signature_hash_algorithm.name
        if cert.signature_hash_algorithm
        else None,
        key_type=key_type,
        key_bits=key_bits,
        self_signed=cert.issuer == cert.subject,
    )


def hostname_matches(host: str, cert: CertInfo) -> bool:
    """RFC 6125 matching on SANs (CN only if there are no SANs): one left-most wildcard label."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        return any(ipaddress.ip_address(ip) == address for ip in cert.san_ip)
    names = cert.san_dns or ([cert.common_name] if cert.common_name else [])
    host_labels = host.lower().rstrip(".").split(".")
    for name in names:
        labels = name.lower().rstrip(".").split(".")
        if len(labels) != len(host_labels):
            continue
        if labels[0] == "*" and len(labels) > 2:
            if labels[1:] == host_labels[1:]:
                return True
        elif labels == host_labels:
            return True
    return False


async def _handshake(
    address: str, port: int, server_name: str | None, context: ssl.SSLContext
) -> ssl.SSLObject:
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port, ssl=context, server_hostname=server_name),
        HANDSHAKE_TIMEOUT,
    )
    ssl_object = writer.get_extra_info("ssl_object")
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 2.0)
    return ssl_object  # type: ignore[no-any-return]


def verified_context(cafile: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def unverified_context() -> ssl.SSLContext:
    # Used only to *read* a certificate that failed verification; nothing is
    # sent over this connection.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _legacy_context() -> ssl.SSLContext | None:
    try:
        # Offering the deprecated versions *is* the test, so the deprecation
        # warnings for using them are expected here and silenced locally.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context = unverified_context()
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_1
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return context


async def inspect_tls(
    address: str, port: int, host: str, *, verify_context: ssl.SSLContext | None = None
) -> TlsInfo:
    server_name = host  # an IP literal is matched against IP SANs by ssl
    info = TlsInfo(reachable=False)
    context = verify_context or verified_context()
    der: bytes | None = None
    try:
        ssl_object = await _handshake(address, port, server_name, context)
        info.reachable = True
        info.verified = True
        info.hostname_match = True
        info.protocol = ssl_object.version()
        cipher = ssl_object.cipher()
        info.cipher = cipher[0] if cipher else None
        der = ssl_object.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        info.reachable = True
        info.verify_reason = VERIFY_REASONS.get(exc.verify_code, "verification_failed")
        info.verify_message = str(exc.verify_message)
    except (ssl.SSLError, ConnectionError, OSError, TimeoutError) as exc:
        info.error = "timeout" if isinstance(exc, TimeoutError) else type(exc).__name__
        return info

    if der is None:
        try:
            ssl_object = await _handshake(address, port, server_name, unverified_context())
            info.protocol = ssl_object.version()
            cipher = ssl_object.cipher()
            info.cipher = cipher[0] if cipher else None
            der = ssl_object.getpeercert(binary_form=True)
        except (ssl.SSLError, ConnectionError, OSError, TimeoutError):
            info.notes.append("The certificate could not be read after verification failed.")

    if der:
        info.cert = parse_certificate(der)
        if info.hostname_match is None:
            info.hostname_match = hostname_matches(host, info.cert)

    legacy = _legacy_context()
    if legacy is None:
        info.notes.append(
            "This server's TLS library cannot offer TLS 1.0/1.1, so they were not tested."
        )
    else:
        try:
            await _handshake(address, port, server_name, legacy)
            info.legacy_protocols_accepted = True
        except ssl.SSLError as exc:
            # "no protocols available" is raised by *our* side before anything
            # is sent: the local OpenSSL refuses to offer TLS 1.0/1.1 at all.
            if "no protocols available" in str(exc).lower():
                info.notes.append("TLS 1.0/1.1 could not be offered by this client; not tested.")
            else:
                info.legacy_protocols_accepted = False
        except (ConnectionError, OSError, TimeoutError):
            info.legacy_protocols_accepted = False
    return info


def tls_to_dict(info: TlsInfo) -> dict[str, Any]:
    return asdict(info)
