"""Port presets, port-spec parsing and the local port -> service map.

The presets are Sentinel's own curated lists of commonly exposed services
(IANA assignments plus well-known defaults). They are *not* Nmap's
frequency-ranked "top ports" data; the names follow the familiar convention.
"""

from dataclasses import dataclass
from typing import Literal

Exposure = Literal[
    "cleartext_admin",
    "cleartext_file",
    "database",
    "remote_desktop",
    "file_sharing",
    "container_api",
    "remote_admin",
    "mail_cleartext",
    "mail",
    "web",
    "web_tls",
    "directory",
    "message_queue",
    "infrastructure",
    "unknown",
]


@dataclass(frozen=True, slots=True)
class Service:
    name: str
    exposure: Exposure


SERVICES: dict[int, Service] = {
    21: Service("FTP", "cleartext_file"),
    22: Service("SSH", "remote_admin"),
    23: Service("Telnet", "cleartext_admin"),
    25: Service("SMTP", "mail"),
    53: Service("DNS", "infrastructure"),
    80: Service("HTTP", "web"),
    110: Service("POP3", "mail_cleartext"),
    111: Service("RPC portmapper", "infrastructure"),
    135: Service("MS RPC", "file_sharing"),
    139: Service("NetBIOS session", "file_sharing"),
    143: Service("IMAP", "mail_cleartext"),
    389: Service("LDAP", "directory"),
    443: Service("HTTPS", "web_tls"),
    445: Service("SMB", "file_sharing"),
    465: Service("SMTPS", "mail"),
    512: Service("rexec", "cleartext_admin"),
    513: Service("rlogin", "cleartext_admin"),
    514: Service("rsh", "cleartext_admin"),
    587: Service("SMTP submission", "mail"),
    636: Service("LDAPS", "directory"),
    873: Service("rsync", "cleartext_file"),
    993: Service("IMAPS", "mail"),
    995: Service("POP3S", "mail"),
    1433: Service("Microsoft SQL Server", "database"),
    1521: Service("Oracle DB", "database"),
    1883: Service("MQTT", "message_queue"),
    2049: Service("NFS", "file_sharing"),
    2375: Service("Docker API (no TLS)", "container_api"),
    2376: Service("Docker API (TLS)", "container_api"),
    3000: Service("HTTP (dev / dashboards)", "web"),
    3306: Service("MySQL / MariaDB", "database"),
    3389: Service("RDP", "remote_desktop"),
    5000: Service("HTTP (dev / registry)", "web"),
    5432: Service("PostgreSQL", "database"),
    5601: Service("Kibana", "web"),
    5672: Service("AMQP (RabbitMQ)", "message_queue"),
    5900: Service("VNC", "remote_desktop"),
    5984: Service("CouchDB", "database"),
    6379: Service("Redis", "database"),
    6443: Service("Kubernetes API", "container_api"),
    8000: Service("HTTP (alt)", "web"),
    8008: Service("HTTP (alt)", "web"),
    8080: Service("HTTP (proxy / alt)", "web"),
    8086: Service("InfluxDB", "database"),
    8443: Service("HTTPS (alt)", "web_tls"),
    8888: Service("HTTP (alt)", "web"),
    9000: Service("HTTP (alt)", "web"),
    9042: Service("Cassandra", "database"),
    9090: Service("HTTP (Prometheus / alt)", "web"),
    9092: Service("Kafka", "message_queue"),
    9200: Service("Elasticsearch", "database"),
    9300: Service("Elasticsearch transport", "database"),
    10250: Service("Kubelet API", "container_api"),
    11211: Service("Memcached", "database"),
    15672: Service("RabbitMQ management", "web"),
    27017: Service("MongoDB", "database"),
}

# Ports that speak HTTP in clear text and get a single HEAD probe.
HTTP_PORTS = frozenset({80, 3000, 5000, 5601, 8000, 8008, 8080, 8888, 9000, 9090, 15672})
# TLS ports are not probed in plain text (Phase 7's TLS checker covers them).
TLS_PORTS = frozenset({443, 465, 636, 993, 995, 2376, 6443, 8443, 10250})

WEB_PRESET = sorted({80, 443, 3000, 5000, 8000, 8008, 8080, 8443, 8888, 9000, 9090})

# Further commonly exposed ports (IANA / vendor defaults) used to fill the presets.
_COMMON_EXTRA = (
    7, 9, 13, 37, 79, 81, 88, 106, 113, 119, 144, 179, 199, 444, 515, 543, 544, 548, 554,
    631, 646, 990, 1025, 1026, 1027, 1028, 1029, 1110, 1720, 1723, 1900, 2000, 2001, 2121,
    2717, 3128, 3986, 4899, 5009, 5051, 5060, 5101, 5190, 5357, 5631, 5666, 5800, 6000,
    6001, 6646, 7070, 8009, 8081, 8082, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
)  # fmt: skip


def _fill(base: list[int], size: int) -> list[int]:
    chosen = list(dict.fromkeys(base))
    for port in (*_COMMON_EXTRA, *range(1, 65536)):
        if len(chosen) >= size:
            break
        if port not in chosen:
            chosen.append(port)
    return sorted(chosen[:size])


TOP_100 = _fill(sorted(SERVICES), 100)
TOP_1000 = _fill(TOP_100, 1000)

Preset = Literal["top-100", "top-1000", "web", "custom"]
PRESETS: dict[str, list[int]] = {"top-100": TOP_100, "top-1000": TOP_1000, "web": WEB_PRESET}


def service_for(port: int) -> Service:
    return SERVICES.get(port, Service("unknown", "unknown"))


def parse_ports(spec: str, limit: int) -> list[int]:
    """Parse '22,80,8000-8100' into sorted unique ports, enforcing 1-65535 and ``limit``.

    The count is checked *while* expanding, so '1-65535' with a small limit
    fails fast instead of building a huge list first.
    """
    ports: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue
        low_s, sep, high_s = part.partition("-")
        if not low_s.strip().isdigit() or (sep and not high_s.strip().isdigit()):
            raise ValueError(f'"{part}" is not a port or range (use 22 or 8000-8100).')
        low = int(low_s)
        high = int(high_s) if sep else low
        if not (1 <= low <= 65535 and 1 <= high <= 65535):
            raise ValueError(f'"{part}": ports must be between 1 and 65535.')
        if high < low:
            raise ValueError(f'"{part}": the range end is below its start.')
        if high - low + 1 > limit:
            raise ValueError(f"At most {limit} ports per scan.")
        ports.update(range(low, high + 1))
        if len(ports) > limit:
            raise ValueError(f"At most {limit} ports per scan (got {len(ports)}).")
    if not ports:
        raise ValueError("Enter at least one port.")
    return sorted(ports)
