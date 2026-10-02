"""HTTP fetching for the header/TLS checker, with the SSRF guard on every hop.

* Requests go to a *pinned* IP with the real host in ``Host`` and TLS SNI
  (prototyped first: httpcore verifies the certificate against the SNI name).
* ``follow_redirects=False``: each redirect is parsed, re-validated and,
  for a new host, re-checked by the scope policy via ``ctx.scope_check``.
* ``trust_env=False``: proxy environment variables are ignored, so a stray
  ``HTTP_PROXY`` cannot route requests somewhere unexpected.
* Bodies are never needed beyond a bounded read; headers are capped.
* Cookie *values* are discarded on receipt. Only names and attributes are
  kept: a session cookie is a credential and must never reach storage or logs.
"""

import ipaddress
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.core.errors import ScopeDenied
from app.core.security.ssrf import TargetUrl, resolve_redirect
from app.engine.base_tool import ToolContext

USER_AGENT = "Sentinel-HeaderCheck/1.0 (defensive configuration audit)"
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_HEADERS = 100
MAX_HEADER_VALUE = 1024


@dataclass(slots=True)
class Cookie:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    path: str | None
    domain: str | None
    persistent: bool


def parse_set_cookie(header: str) -> Cookie | None:
    """Parse one Set-Cookie header, keeping the name and attributes only (never the value)."""
    parts = [p.strip() for p in header.split(";")]
    name, sep, _value = parts[0].partition("=")
    name = name.strip()
    if not sep or not name:
        return None
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    same_site = attrs.get("samesite")
    return Cookie(
        name=name[:128],
        secure="secure" in attrs,
        http_only="httponly" in attrs,
        same_site=same_site.capitalize() if same_site else None,
        path=attrs.get("path") or None,
        domain=attrs.get("domain") or None,
        persistent="expires" in attrs or "max-age" in attrs,
    )


@dataclass(slots=True)
class Hop:
    url: str
    address: str
    status: int | None = None
    location: str | None = None
    followed: bool = False
    note: str | None = None
    error: str | None = None
    tls_unverified: bool = False


@dataclass(slots=True)
class FinalResponse:
    url: str
    status: int
    http_version: str
    headers: list[tuple[str, str]]
    cookies: list[Cookie]
    body_bytes: int
    body_truncated: bool


@dataclass(slots=True)
class CrawlResult:
    hops: list[Hop] = field(default_factory=list)
    final: FinalResponse | None = None
    final_target: TargetUrl | None = None
    final_addresses: tuple[str, ...] = ()


def pick_address(addresses: tuple[str, ...]) -> str:
    for address in addresses:
        if ipaddress.ip_address(address).version == 4:
            return address
    return addresses[0]


class Fetcher:
    def __init__(self, timeout: float, max_body: int, verify: ssl.SSLContext | None = None) -> None:
        common: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout),
            "follow_redirects": False,
            "trust_env": False,
            "limits": httpx.Limits(max_connections=4, max_keepalive_connections=0),
            "headers": {"User-Agent": USER_AGENT, "Accept": "*/*"},
        }
        self.max_body = max_body
        self.verified = httpx.AsyncClient(verify=verify or ssl.create_default_context(), **common)
        unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        self.unverified = httpx.AsyncClient(verify=unverified, **common)

    async def aclose(self) -> None:
        await self.verified.aclose()
        await self.unverified.aclose()

    async def get(
        self, target: TargetUrl, address: str, *, verify: bool = True
    ) -> tuple[httpx.Response, int, bool]:
        client = self.verified if verify else self.unverified
        extensions = (
            {"sni_hostname": target.host} if target.is_https and not target.host_is_ip else {}
        )
        request = client.build_request(
            "GET",
            target.url_for(address),
            headers={"Host": target.host_header},
            extensions=extensions,
        )
        response = await client.send(request, stream=True)
        size, truncated = 0, False
        try:
            async for chunk in response.aiter_raw():
                size += len(chunk)
                if size >= self.max_body:
                    truncated = True
                    break
        finally:
            await response.aclose()
        return response, size, truncated


def _clean_headers(response: httpx.Response) -> tuple[list[tuple[str, str]], list[Cookie]]:
    headers: list[tuple[str, str]] = []
    cookies: list[Cookie] = []
    for name, value in response.headers.multi_items():
        if name.lower() == "set-cookie":
            cookie = parse_set_cookie(value)
            if cookie:
                cookies.append(cookie)
            continue  # the value is a credential: never kept
        if len(headers) < MAX_HEADERS:
            headers.append((name.lower(), value[:MAX_HEADER_VALUE]))
    return headers, cookies


async def crawl(
    start: TargetUrl,
    addresses: tuple[str, ...],
    fetcher: Fetcher,
    ctx: ToolContext,
    *,
    allowed_ports: frozenset[int],
    max_redirects: int,
) -> CrawlResult:
    result = CrawlResult()
    current, current_addresses = start, addresses
    for hop_number in range(max_redirects + 1):
        await ctx.raise_if_cancelled()
        address = pick_address(current_addresses)
        hop = Hop(url=str(current), address=address)
        result.hops.append(hop)
        try:
            try:
                response, size, truncated = await fetcher.get(current, address)
            except httpx.ConnectError as exc:
                if current.is_https and "CERTIFICATE_VERIFY_FAILED" in str(exc):
                    # Still read the headers; the TLS findings explain the certificate.
                    hop.tls_unverified = True
                    response, size, truncated = await fetcher.get(current, address, verify=False)
                else:
                    raise
        except httpx.TimeoutException:
            hop.error = "The request timed out."
            return result
        except httpx.HTTPError as exc:
            hop.error = f"The request failed ({type(exc).__name__})."
            return result

        hop.status = response.status_code
        location = response.headers.get("location")
        if response.status_code in REDIRECT_STATUSES and location:
            hop.location = location[:MAX_HEADER_VALUE]
            if hop_number == max_redirects:
                hop.note = f"Redirect limit ({max_redirects}) reached; not followed."
                return result
            try:
                nxt = resolve_redirect(current, location, allowed_ports)
            except ValueError as exc:
                hop.note = f"Not followed: {exc}"
                return result
            if nxt.host == current.host:
                next_addresses = current_addresses  # same host: keep the pinned addresses
            elif ctx.scope_check is None:
                hop.note = "Not followed: the redirect goes to another host."
                return result
            else:
                try:
                    next_addresses = await ctx.scope_check(nxt.host)
                except ScopeDenied as exc:
                    hop.note = f"Not followed (outside the scan scope): {exc.message}"
                    return result
            hop.followed = True
            current, current_addresses = nxt, next_addresses
            continue

        headers, cookies = _clean_headers(response)
        result.final = FinalResponse(
            url=str(current),
            status=response.status_code,
            http_version=response.http_version,
            headers=headers,
            cookies=cookies,
            body_bytes=size,
            body_truncated=truncated,
        )
        result.final_target = current
        result.final_addresses = current_addresses
        return result
    return result  # pragma: no cover
