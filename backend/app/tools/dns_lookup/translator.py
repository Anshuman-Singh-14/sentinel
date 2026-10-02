"""Raw DNS data -> educational findings. Pure functions over the raw output.

The record parsers (SPF, DMARC) are deliberately small and conservative: they
read only what the findings need and never evaluate SPF includes (that would
mean further network lookups from the translator, which must stay pure).
"""

import ipaddress
import re
from typing import Any

from app.engine.base_tool import RawOutput
from app.engine.knowledge import get_knowledge_base
from app.engine.schemas import Confidence, Finding, FindingStatus
from app.engine.severity import sort_by_severity
from app.tools.dns_lookup.schemas import DnsLookupParams

_SPF_ALL_RE = re.compile(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", re.IGNORECASE)


def _finding(
    key: str,
    *,
    category: str,
    status: FindingStatus,
    evidence: dict[str, Any] | None = None,
    confidence: Confidence = Confidence.HIGH,
    **values: object,
) -> Finding:
    entry = get_knowledge_base().get(key)
    return Finding(
        item=entry.render("title", **values),
        category=category,
        status=status,
        severity=entry.severity,
        severity_rationale=entry.render("severity_rationale", **values),
        confidence=confidence,
        explanation=entry.render("explanation", **values),
        remediation=entry.render("remediation", **values),
        evidence=evidence or {},
        references=list(entry.references),
    )


# --- record parsers ----------------------------------------------------------------------


def spf_records(txt: list[str]) -> list[str]:
    return [t for t in txt if t.strip().lower().startswith("v=spf1")]


def spf_all_qualifier(record: str) -> str | None:
    """The qualifier of the final "all" mechanism: "+", "-", "~", "?" or None."""
    match = _SPF_ALL_RE.search(record)
    if not match:
        return None
    return match.group(1) or "+"  # a bare "all" means "+all" (RFC 7208 section 4.6.2)


def parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def provider_of(nameserver: str) -> str:
    """Approximate the operator from the name server's last two labels.

    Imperfect for multi-part public suffixes (co.uk), which is why the related
    finding carries medium confidence.
    """
    labels = nameserver.rstrip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else nameserver


def _is_internal(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


# --- checks ------------------------------------------------------------------------------------


def _email_findings(
    domain: str, records: dict[str, list[Any]], dmarc_txt: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    has_mx = bool(records.get("MX"))
    spf = spf_records(records.get("TXT", []))
    if not spf:
        findings.append(
            _finding(
                "dns.spf_missing" if has_mx else "dns.spf_missing_no_mail",
                category="EMAIL_SECURITY",
                status=FindingStatus.MISSING,
                evidence={"txt_records": records.get("TXT", [])[:10], "has_mx": has_mx},
                domain=domain,
            )
        )
    elif len(spf) > 1:
        findings.append(
            _finding(
                "dns.spf_multiple",
                category="EMAIL_SECURITY",
                status=FindingStatus.FAIL,
                evidence={"spf_records": spf},
                domain=domain,
                count=len(spf),
            )
        )
    else:
        record = spf[0]
        qualifier = spf_all_qualifier(record)
        if qualifier == "+":
            key, status = "dns.spf_pass_all", FindingStatus.FAIL
        elif qualifier in ("-", "~"):
            key, status = "dns.spf_ok", FindingStatus.PASS
        else:
            key, status = "dns.spf_neutral", FindingStatus.WEAK
        findings.append(
            _finding(
                key,
                category="EMAIL_SECURITY",
                status=status,
                evidence={"spf_record": record},
                domain=domain,
                record=record,
                qualifier=f"{qualifier}all" if qualifier else "no all term",
            )
        )

    dmarc = [t for t in dmarc_txt if t.strip().lower().startswith("v=dmarc1")]
    if not dmarc_txt:
        findings.append(
            _finding(
                "dns.dmarc_missing",
                category="EMAIL_SECURITY",
                status=FindingStatus.MISSING,
                domain=domain,
            )
        )
        return findings
    if len(dmarc) != 1:
        reason = "no record starts with v=DMARC1" if not dmarc else f"{len(dmarc)} records found"
        findings.append(
            _finding(
                "dns.dmarc_invalid",
                category="EMAIL_SECURITY",
                status=FindingStatus.FAIL,
                evidence={"dmarc_records": dmarc_txt[:5]},
                domain=domain,
                reason=reason,
            )
        )
        return findings
    tags = parse_dmarc(dmarc[0])
    policy = tags.get("p", "").lower()
    evidence = {"dmarc_record": dmarc[0], "tags": tags}
    if policy not in ("none", "quarantine", "reject"):
        findings.append(
            _finding(
                "dns.dmarc_invalid",
                category="EMAIL_SECURITY",
                status=FindingStatus.FAIL,
                evidence=evidence,
                domain=domain,
                reason="missing or unknown p= policy",
            )
        )
    elif policy == "none":
        findings.append(
            _finding(
                "dns.dmarc_none",
                category="EMAIL_SECURITY",
                status=FindingStatus.WEAK,
                evidence=evidence,
                domain=domain,
            )
        )
    else:
        findings.append(
            _finding(
                "dns.dmarc_enforced",
                category="EMAIL_SECURITY",
                status=FindingStatus.PASS,
                evidence=evidence,
                domain=domain,
                policy=policy,
                record=dmarc[0],
                action="quarantined (sent to spam)" if policy == "quarantine" else "rejected",
            )
        )
        pct = tags.get("pct", "100")
        if pct.isdigit() and int(pct) < 100:
            findings.append(
                _finding(
                    "dns.dmarc_partial",
                    category="EMAIL_SECURITY",
                    status=FindingStatus.WEAK,
                    evidence=evidence,
                    policy=policy,
                    pct=int(pct),
                )
            )
    return findings


def _nameserver_findings(domain: str, nameservers: list[str]) -> list[Finding]:
    if not nameservers:
        return []
    providers = sorted({provider_of(ns) for ns in nameservers})
    evidence = {"nameservers": nameservers, "providers": providers}
    if len(nameservers) == 1:
        return [
            _finding(
                "dns.ns_single",
                category="DNS_RESILIENCE",
                status=FindingStatus.FAIL,
                evidence=evidence,
                domain=domain,
                nameservers=nameservers[0],
            )
        ]
    if len(providers) == 1:
        return [
            _finding(
                "dns.ns_single_provider",
                category="DNS_RESILIENCE",
                status=FindingStatus.WEAK,
                evidence=evidence,
                confidence=Confidence.MEDIUM,
                provider=providers[0],
            )
        ]
    return [
        _finding(
            "dns.ns_redundant",
            category="DNS_RESILIENCE",
            status=FindingStatus.PASS,
            evidence=evidence,
            domain=domain,
            count=len(nameservers),
            providers=len(providers),
        )
    ]


def translate(raw: RawOutput, params: DnsLookupParams) -> list[Finding]:
    domain = raw["domain"]
    if raw.get("nxdomain"):
        return [_finding("dns.nxdomain", category="DNS", status=FindingStatus.ERROR, domain=domain)]

    records: dict[str, list[Any]] = raw["records"]
    ips: list[str] = raw.get("resolved_ips", [])
    findings: list[Finding] = []

    record_count = sum(len(v) for v in records.values())
    findings.append(
        _finding(
            "dns.records_summary",
            category="DNS",
            status=FindingStatus.INFO,
            evidence={"resolved_ips": ips, "counts": {k: len(v) for k, v in records.items()}},
            domain=domain,
            ip_count=len(ips),
            ips=", ".join(ips[:5]) + (" …" if len(ips) > 5 else "") if ips else "none",
            record_count=record_count,
        )
    )
    if not ips:
        findings.append(
            _finding("dns.no_address", category="DNS", status=FindingStatus.INFO, domain=domain)
        )
    internal = [ip for ip in ips if _is_internal(ip)]
    if internal:
        findings.append(
            _finding(
                "dns.private_address",
                category="DNS",
                status=FindingStatus.DETECTED,
                evidence={"internal_ips": internal},
                domain=domain,
                ips=", ".join(internal),
            )
        )

    findings.extend(_email_findings(domain, records, raw.get("dmarc", [])))

    caa = records.get("CAA", [])
    if "CAA" not in raw.get("record_errors", {}):
        issuers = sorted({c["value"] for c in caa if c.get("tag") in ("issue", "issuewild")})
        if caa:
            findings.append(
                _finding(
                    "dns.caa_present",
                    category="CERTIFICATES",
                    status=FindingStatus.PASS,
                    evidence={"caa": caa},
                    issuers=", ".join(issuers) or "none (issuance forbidden)",
                )
            )
        else:
            findings.append(
                _finding(
                    "dns.caa_missing",
                    category="CERTIFICATES",
                    status=FindingStatus.MISSING,
                    domain=domain,
                )
            )

    for check in raw.get("cname_checks", []):
        if check.get("dangling"):
            findings.append(
                _finding(
                    "dns.cname_dangling",
                    category="DNS",
                    status=FindingStatus.DETECTED,
                    confidence=Confidence.MEDIUM,
                    evidence=check,
                    name=check["name"],
                    target=check["target"],
                )
            )

    findings.extend(_nameserver_findings(domain, records.get("NS", [])))
    return sort_by_severity(findings)
