"""TCP connect scanning and banner grabbing. Pure async I/O, no framework imports.

What this does and deliberately does not do (02-modules.md):

* A full TCP connect per port (``asyncio.open_connection``): the same thing
  any client does. No SYN/stealth scanning, no raw sockets, no OS
  fingerprinting, no exploit checks.
* Banners are read passively. The one active probe is ``HEAD / HTTP/1.0``
  on known clear-text HTTP ports, which any browser could send.
* Everything is bounded: a semaphore caps concurrency, every connect and
  read has a timeout, banners are capped, and cancellation is checked
  before each connection.
"""

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any, Literal

from app.engine.base_tool import RawOutput, ToolContext
from app.tools.port_scanner.fingerprint import identify, sanitize_banner
from app.tools.port_scanner.ports import HTTP_PORTS, TLS_PORTS, service_for

READ_BYTES = 2048
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nUser-Agent: Sentinel-Scanner (defensive audit)\r\n\r\n"

State = Literal["open", "closed", "filtered"]


@dataclass(frozen=True, slots=True)
class ScanConfig:
    concurrency: int
    connect_timeout: float
    banner_timeout: float
    grab_banners: bool


@dataclass(slots=True)
class PortResult:
    port: int
    state: State
    raw_banner: bytes = b""


async def _read(reader: asyncio.StreamReader, limit_seconds: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(READ_BYTES), limit_seconds)
    except (TimeoutError, OSError):
        return b""


async def probe(address: str, port: int, config: ScanConfig) -> PortResult:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), config.connect_timeout
        )
    except ConnectionRefusedError:
        return PortResult(port, "closed")
    except (TimeoutError, OSError):
        # No answer (dropped by a firewall) or the host is unreachable.
        return PortResult(port, "filtered")

    banner = b""
    try:
        if config.grab_banners and port not in TLS_PORTS:
            if port in HTTP_PORTS:
                writer.write(HTTP_PROBE)
                await writer.drain()
                banner = await _read(reader, config.banner_timeout)
            else:
                banner = await _read(reader, config.banner_timeout)
    except OSError:
        pass
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1.0)
    return PortResult(port, "open", banner)


def http_summary(banner: str) -> str:
    """Keep the status line and the Server header of an HTTP response."""
    lines = banner.splitlines()
    keep = [lines[0]] if lines else []
    keep += [line for line in lines[1:] if line.lower().startswith(("server:", "x-powered-by:"))]
    return "\n".join(keep)


async def scan(address: str, ports: list[int], config: ScanConfig, ctx: ToolContext) -> RawOutput:
    semaphore = asyncio.Semaphore(config.concurrency)
    total = len(ports)
    done = 0
    step = max(1, total // 20)  # progress roughly every 5 %

    async def bounded(port: int) -> PortResult:
        nonlocal done
        async with semaphore:
            await ctx.raise_if_cancelled()
            result = await probe(address, port, config)
        done += 1
        if done % step == 0 or done == total:
            # Scanning is 0-85 %; CVE enrichment uses the rest.
            await ctx.report_progress(round(done / total * 85), f"Scanned {done}/{total} ports")
        return result

    results = await asyncio.gather(*(bounded(p) for p in ports))

    open_ports: list[dict[str, Any]] = []
    for result in sorted((r for r in results if r.state == "open"), key=lambda r: r.port):
        service = service_for(result.port)
        banner = sanitize_banner(result.raw_banner)
        if result.port in HTTP_PORTS and banner.upper().startswith("HTTP/"):
            banner = http_summary(banner)
        product = identify(result.raw_banner, banner)
        open_ports.append(
            {
                "port": result.port,
                "service": service.name,
                "exposure": service.exposure,
                "banner": banner,
                "tls": result.port in TLS_PORTS,
                "product": None
                if product is None
                else {
                    "name": product.name,
                    "version": product.version,
                    "cpe_candidates": product.cpe_candidates,
                    "confidence": product.confidence,
                    "confidence_reason": product.confidence_reason,
                    "evidence": product.evidence,
                },
            }
        )
    return {
        "address": address,
        "ports_scanned": total,
        "open": open_ports,
        "closed_count": sum(1 for r in results if r.state == "closed"),
        "filtered_count": sum(1 for r in results if r.state == "filtered"),
    }
