"""Raw header/TLS data -> educational findings. Pure functions over the raw output."""

import re
from typing import Any

from app.engine.base_tool import RawOutput
from app.engine.knowledge import get_knowledge_base
from app.engine.schemas import Finding, FindingStatus, Severity
from app.engine.severity import sort_by_severity
from app.tools.header_tls.schemas import HeaderTlsParams

HSTS_MIN_SECONDS = 15_552_000  # 180 days (Mozilla guidelines)
SESSION_NAME = re.compile(r"sess|sid|token|auth|jwt|login|remember", re.IGNORECASE)
VERSION_IN_VALUE = re.compile(r"\d+\.\d+")


def _f(
    key: str,
    *,
    category: str,
    status: FindingStatus,
    evidence: dict[str, Any] | None = None,
    severity: Severity | None = None,
    **values: object,
) -> Finding:
    entry = get_knowledge_base().get(key)
    return Finding(
        item=entry.render("title", **values)[:300],
        category=category,
        status=status,
        severity=severity or entry.severity,
        severity_rationale=entry.render("severity_rationale", **values),
        explanation=entry.render("explanation", **values),
        remediation=entry.render("remediation", **values),
        evidence=evidence or {},
        references=list(entry.references),
    )


def header_map(headers: list[list[str]] | list[tuple[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, value in headers:
        out.setdefault(name.lower(), []).append(value)
    return out


def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return directives


def csp_issues(policy: str) -> list[str]:
    d = parse_csp(policy)
    script = d.get("script-src", d.get("default-src"))
    issues: list[str] = []
    if script is None:
        issues.append("there is no script-src or default-src, so scripts are unrestricted")
    else:
        lowered = [s.lower() for s in script]
        if "'unsafe-inline'" in lowered and not any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
            for s in lowered
        ):
            issues.append("scripts allow 'unsafe-inline'")
        if "'unsafe-eval'" in lowered:
            issues.append("scripts allow 'unsafe-eval'")
        if any(s in ("*", "http:", "https:", "data:") for s in lowered):
            issues.append("script sources include a wildcard or a whole scheme (*, https:, data:)")
    if "object-src" not in d and "default-src" not in d:
        issues.append("plugins (object-src) are unrestricted")
    return issues


def parse_hsts(value: str) -> tuple[int | None, bool, bool]:
    max_age = None
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    if match:
        max_age = int(match.group(1))
    lowered = value.lower()
    return max_age, "includesubdomains" in lowered, "preload" in lowered


def _header_findings(h: dict[str, list[str]], https: bool, host: str) -> list[Finding]:
    out: list[Finding] = []
    # HSTS (ignored by browsers over HTTP, so only assessed on HTTPS)
    if https:
        hsts = h.get("strict-transport-security", [None])[0]
        if not hsts:
            out.append(
                _f(
                    "header_tls.hsts_missing",
                    category="HTTP_HEADERS",
                    status=FindingStatus.MISSING,
                    host=host,
                )
            )
        else:
            max_age, subdomains, preload = parse_hsts(hsts)
            issues = []
            if max_age is None:
                issues.append("it has no valid max-age")
            elif max_age < HSTS_MIN_SECONDS:
                issues.append(f"max-age is only {max_age} seconds (under 180 days)")
            if not subdomains:
                issues.append("it does not cover subdomains (includeSubDomains)")
            if issues:
                out.append(
                    _f(
                        "header_tls.hsts_weak",
                        category="HTTP_HEADERS",
                        status=FindingStatus.WEAK,
                        evidence={"strict-transport-security": hsts},
                        value=hsts,
                        issues=" and ".join(issues),
                    )
                )
            else:
                note = " The domain is marked for the HSTS preload list." if preload else ""
                out.append(
                    _f(
                        "header_tls.hsts_ok",
                        category="HTTP_HEADERS",
                        status=FindingStatus.PASS,
                        evidence={"strict-transport-security": hsts},
                        value=hsts,
                        preload_note=note,
                    )
                )

    csp = h.get("content-security-policy", [None])[0]
    if not csp:
        if h.get("content-security-policy-report-only"):
            out.append(
                _f("header_tls.csp_report_only", category="HTTP_HEADERS", status=FindingStatus.WEAK)
            )
        else:
            out.append(
                _f("header_tls.csp_missing", category="HTTP_HEADERS", status=FindingStatus.MISSING)
            )
    else:
        issues = csp_issues(csp)
        if issues:
            out.append(
                _f(
                    "header_tls.csp_weak",
                    category="HTTP_HEADERS",
                    status=FindingStatus.WEAK,
                    evidence={"content-security-policy": csp, "issues": issues},
                    value=csp[:300],
                    issues="; ".join(issues),
                )
            )
        else:
            out.append(
                _f(
                    "header_tls.csp_ok",
                    category="HTTP_HEADERS",
                    status=FindingStatus.PASS,
                    evidence={"content-security-policy": csp},
                    value=csp[:300],
                )
            )

    xfo = (h.get("x-frame-options", [""])[0] or "").strip().upper()
    frame_ancestors = "frame-ancestors" in parse_csp(csp or "")
    if xfo in ("DENY", "SAMEORIGIN") or frame_ancestors:
        mechanism = "CSP frame-ancestors" if frame_ancestors else f"X-Frame-Options: {xfo}"
        out.append(
            _f(
                "header_tls.clickjacking_ok",
                category="HTTP_HEADERS",
                status=FindingStatus.PASS,
                mechanism=mechanism,
            )
        )
    else:
        out.append(
            _f(
                "header_tls.clickjacking_missing",
                category="HTTP_HEADERS",
                status=FindingStatus.MISSING,
                evidence={"x-frame-options": xfo or None},
            )
        )

    xcto = (h.get("x-content-type-options", [""])[0] or "").strip().lower()
    if xcto == "nosniff":
        out.append(_f("header_tls.xcto_ok", category="HTTP_HEADERS", status=FindingStatus.PASS))
    else:
        out.append(
            _f("header_tls.xcto_missing", category="HTTP_HEADERS", status=FindingStatus.MISSING)
        )

    referrer = (h.get("referrer-policy", [""])[-1] or "").strip()
    if not referrer:
        out.append(
            _f("header_tls.referrer_missing", category="HTTP_HEADERS", status=FindingStatus.MISSING)
        )
    elif "unsafe-url" in referrer.lower():
        out.append(
            _f(
                "header_tls.referrer_unsafe",
                category="HTTP_HEADERS",
                status=FindingStatus.WEAK,
                value=referrer,
            )
        )
    else:
        out.append(
            _f(
                "header_tls.referrer_ok",
                category="HTTP_HEADERS",
                status=FindingStatus.PASS,
                value=referrer,
            )
        )

    permissions = h.get("permissions-policy", [None])[0]
    if permissions:
        out.append(
            _f(
                "header_tls.permissions_ok",
                category="HTTP_HEADERS",
                status=FindingStatus.PASS,
                value=permissions[:200],
            )
        )
    else:
        out.append(
            _f(
                "header_tls.permissions_missing",
                category="HTTP_HEADERS",
                status=FindingStatus.MISSING,
            )
        )

    disclosed = {}
    server = h.get("server", [None])[0]
    if server and VERSION_IN_VALUE.search(server):
        disclosed["Server"] = server
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if h.get(name):
            disclosed[name.title()] = h[name][0]
    if disclosed:
        text = "; ".join(f"{k}: {v}" for k, v in disclosed.items())
        out.append(
            _f(
                "header_tls.disclosure",
                category="HTTP_HEADERS",
                status=FindingStatus.DETECTED,
                evidence=disclosed,
                headers=text,
            )
        )
    return out


def _names(items: list[dict[str, Any]]) -> str:
    return ", ".join(sorted({str(c["name"]) for c in items}))


def _cookie_findings(cookies: list[dict[str, Any]], https: bool) -> list[Finding]:
    if not cookies:
        return []
    out: list[Finding] = []
    not_secure = [c for c in cookies if not c["secure"]] if https else []
    not_httponly = [c for c in cookies if not c["http_only"]]
    no_samesite = [c for c in cookies if not c["same_site"]]
    none_insecure = [
        c for c in cookies if (c["same_site"] or "").lower() == "none" and not c["secure"]
    ]
    if not_secure:
        out.append(
            _f(
                "header_tls.cookie_not_secure",
                category="COOKIES",
                status=FindingStatus.FAIL,
                evidence={"cookies": [c["name"] for c in not_secure]},
                names=_names(not_secure),
            )
        )
    if not_httponly:
        sessions = [c for c in not_httponly if SESSION_NAME.search(c["name"])]
        out.append(
            _f(
                "header_tls.cookie_not_httponly",
                category="COOKIES",
                status=FindingStatus.FAIL,
                severity=Severity.MEDIUM if sessions else None,
                evidence={"cookies": [c["name"] for c in not_httponly]},
                names=_names(not_httponly),
                session_names=_names(sessions) or "none",
            )
        )
    if no_samesite:
        out.append(
            _f(
                "header_tls.cookie_no_samesite",
                category="COOKIES",
                status=FindingStatus.WEAK,
                evidence={"cookies": [c["name"] for c in no_samesite]},
                names=_names(no_samesite),
            )
        )
    if none_insecure:
        out.append(
            _f(
                "header_tls.cookie_samesite_none_insecure",
                category="COOKIES",
                status=FindingStatus.FAIL,
                names=_names(none_insecure),
            )
        )
    if not out:
        out.append(
            _f(
                "header_tls.cookies_ok",
                category="COOKIES",
                status=FindingStatus.PASS,
                count=len(cookies),
                names=_names(cookies),
            )
        )
    return out


def _tls_findings(tls: dict[str, Any], host: str) -> list[Finding]:
    out: list[Finding] = []
    cert = tls.get("cert") or {}
    days = cert.get("days_remaining")
    names = ", ".join(cert.get("san_dns") or cert.get("san_ip") or [cert.get("common_name") or "?"])
    evidence = {
        k: cert.get(k)
        for k in (
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "san_dns",
            "key_type",
            "key_bits",
            "signature_hash",
        )
    }
    evidence.update(
        {
            "protocol": tls.get("protocol"),
            "cipher": tls.get("cipher"),
            "verify_message": tls.get("verify_message"),
        }
    )
    reason = tls.get("verify_reason")

    if reason == "expired" or (days is not None and days < 0):
        out.append(
            _f(
                "header_tls.expired",
                category="TLS",
                status=FindingStatus.FAIL,
                evidence=evidence,
                host=host,
                not_after=cert.get("not_after", "?"),
                days_ago=abs(days or 0),
            )
        )
    elif reason == "not_yet_valid":
        out.append(
            _f(
                "header_tls.not_yet_valid",
                category="TLS",
                status=FindingStatus.FAIL,
                evidence=evidence,
                host=host,
                not_before=cert.get("not_before", "?"),
            )
        )
    if reason in ("self_signed",) or (cert.get("self_signed") and not tls.get("verified")):
        out.append(
            _f(
                "header_tls.self_signed",
                category="TLS",
                status=FindingStatus.FAIL,
                evidence=evidence,
                host=host,
            )
        )
    elif reason in ("self_signed_chain", "unknown_issuer", "verification_failed"):
        out.append(
            _f(
                "header_tls.untrusted",
                category="TLS",
                status=FindingStatus.FAIL,
                evidence=evidence,
                message=tls.get("verify_message") or "unknown reason",
            )
        )
    if tls.get("hostname_match") is False or reason == "hostname_mismatch":
        out.append(
            _f(
                "header_tls.hostname_mismatch",
                category="TLS",
                status=FindingStatus.FAIL,
                evidence=evidence,
                host=host,
                names=names,
            )
        )
    if days is not None and 0 <= days < 30 and not out:
        out.append(
            _f(
                "header_tls.expiring_soon",
                category="TLS",
                status=FindingStatus.WEAK,
                evidence=evidence,
                severity=Severity.MEDIUM if days < 14 else Severity.LOW,
                host=host,
                days=days,
                not_after=cert.get("not_after", "?"),
            )
        )
    if tls.get("legacy_protocols_accepted"):
        out.append(
            _f(
                "header_tls.legacy_protocols",
                category="TLS",
                status=FindingStatus.FAIL,
                evidence=evidence,
            )
        )
    key_type, bits = cert.get("key_type") or "", cert.get("key_bits")
    if bits and ((key_type == "RSA" and bits < 2048) or (key_type.startswith("EC") and bits < 224)):
        out.append(
            _f(
                "header_tls.weak_key",
                category="TLS",
                status=FindingStatus.WEAK,
                evidence=evidence,
                key_type=key_type,
                key_bits=bits,
            )
        )
    if (cert.get("signature_hash") or "").lower() in ("sha1", "md5"):
        out.append(
            _f(
                "header_tls.sha1_signature",
                category="TLS",
                status=FindingStatus.WEAK,
                evidence=evidence,
            )
        )
    if not out and tls.get("verified"):
        out.append(
            _f(
                "header_tls.tls_ok",
                category="TLS",
                status=FindingStatus.PASS,
                evidence=evidence,
                host=host,
                protocol=tls.get("protocol") or "TLS",
                cipher=tls.get("cipher") or "?",
                days=days if days is not None else "?",
                issuer=cert.get("issuer", "?"),
            )
        )
    return out


def translate(raw: RawOutput, params: HeaderTlsParams) -> list[Finding]:
    host = raw["host"]
    findings: list[Finding] = []
    for hop in raw.get("hops", []):
        if hop.get("note") and not hop.get("followed"):
            findings.append(
                _f(
                    "header_tls.redirect_not_followed",
                    category="HTTP",
                    status=FindingStatus.INFO,
                    evidence=hop,
                    url=hop["url"],
                    location=hop.get("location") or "?",
                    note=hop["note"],
                )
            )

    final = raw.get("final")
    if final is None:
        last = (raw.get("hops") or [{}])[-1]
        if not findings:
            findings.append(
                _f(
                    "header_tls.unreachable",
                    category="HTTP",
                    status=FindingStatus.ERROR,
                    url=last.get("url", raw.get("url")),
                    reason=last.get("error") or "no response",
                )
            )
        return sort_by_severity(findings)

    https = final["url"].startswith("https://")
    if raw.get("tls"):
        findings.extend(_tls_findings(raw["tls"], str(raw.get("final_host") or host)))

    if not https:
        https_probe = raw.get("https_probe") or {}
        if not https_probe.get("available"):
            findings.append(
                _f(
                    "header_tls.no_https",
                    category="TRANSPORT",
                    status=FindingStatus.FAIL,
                    host=host,
                )
            )

    http_probe = raw.get("http_probe")
    if http_probe and http_probe.get("status") is not None:
        if http_probe.get("redirects_to_https"):
            findings.append(
                _f(
                    "header_tls.http_redirects",
                    category="TRANSPORT",
                    status=FindingStatus.PASS,
                    host=host,
                    location=http_probe.get("location", ""),
                )
            )
        elif https:
            findings.append(
                _f(
                    "header_tls.http_not_redirected",
                    category="TRANSPORT",
                    status=FindingStatus.FAIL,
                    evidence=http_probe,
                    host=host,
                    http_status=http_probe["status"],
                )
            )

    headers = header_map(final["headers"])
    findings.extend(_header_findings(headers, https, host))
    findings.extend(_cookie_findings(final.get("cookies", []), https))
    return sort_by_severity(findings)
