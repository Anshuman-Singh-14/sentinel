"""Raw scan data -> educational findings. Pure functions over the raw output."""

from typing import Any

from app.engine.base_tool import RawOutput
from app.engine.knowledge import get_knowledge_base
from app.engine.schemas import Confidence, Finding, FindingStatus, Severity
from app.engine.severity import cvss_rationale, severity_from_cvss, sort_by_severity
from app.tools.port_scanner.schemas import PortScanParams

MAX_CVE_FINDINGS_PER_PRODUCT = 5


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
        item=entry.render("title", **values)[:300],
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


def _cve_finding(port: dict[str, Any], product: dict[str, Any], cve: dict[str, Any]) -> Finding:
    base = _finding(
        "port_scanner.cve_match",
        category="VULNERABILITY",
        status=FindingStatus.DETECTED,
        confidence=Confidence(product["confidence"]),
        evidence={
            "port": port["port"],
            "banner": port["banner"],
            "cpe": product["cpe_candidates"][0] if product["cpe_candidates"] else None,
            "cvss_version": cve.get("cvss_version"),
            "cvss_vector": cve.get("vector"),
            "published": cve.get("published"),
        },
        cve_id=cve["cve_id"],
        product=product["name"],
        version=product["version"],
        port=port["port"],
        description=cve.get("description") or "No description in the NVD.",
        url=cve["url"],
    )
    score = cve.get("score")
    if isinstance(score, (int, float)):
        severity = severity_from_cvss(float(score))
        rationale = cvss_rationale(float(score), cve["cve_id"])
        if cve.get("cvss_version") == "2.0":
            rationale += " (Only a CVSS v2 score is published; it is mapped onto the same bands.)"
    else:
        severity, rationale = (
            Severity.MEDIUM,
            (f"{cve['cve_id']} has no CVSS score in the NVD yet; rated MEDIUM pending analysis."),
        )
    rationale += f" Confidence {product['confidence']}: {product['confidence_reason']}"
    return base.model_copy(
        update={
            "severity": severity,
            "severity_rationale": rationale,
            "references": [cve["url"], cve["cve_id"]],
        }
    )


def translate(raw: RawOutput, params: PortScanParams) -> list[Finding]:
    open_ports: list[dict[str, Any]] = raw.get("open", [])
    counts = {
        "target": raw.get("target", params.target),
        "address": raw.get("address", ""),
        "ports_scanned": raw.get("ports_scanned", 0),
        "open_count": len(open_ports),
        "closed_count": raw.get("closed_count", 0),
        "filtered_count": raw.get("filtered_count", 0),
    }
    if not open_ports:
        return [
            _finding(
                "port_scanner.none_open", category="NETWORK", status=FindingStatus.PASS, **counts
            )
        ]

    findings: list[Finding] = [
        _finding(
            "port_scanner.summary",
            category="NETWORK",
            status=FindingStatus.INFO,
            evidence={"open_ports": [p["port"] for p in open_ports], **counts},
            **counts,
        )
    ]
    cves: dict[str, list[dict[str, Any]]] = raw.get("cves", {})
    lookup_ran = bool(raw.get("cve_lookup", {}).get("enabled")) and not raw.get(
        "cve_lookup", {}
    ).get("errors")

    for port in open_ports:
        exposure = port.get("exposure", "unknown")
        banner = port.get("banner") or ""
        findings.append(
            _finding(
                f"port_scanner.{exposure}",
                category="NETWORK",
                status=FindingStatus.DETECTED,
                evidence={"port": port["port"], "service": port["service"], "banner": banner},
                service=port["service"],
                port=port["port"],
                banner_note=f'; it announced: "{banner[:120]}"' if banner else "",
            )
        )
        product = port.get("product")
        if not product or not product.get("version"):
            continue
        matched = next((cves[c] for c in product["cpe_candidates"] if c in cves), [])
        for cve in matched[:MAX_CVE_FINDINGS_PER_PRODUCT]:
            findings.append(_cve_finding(port, product, cve))
        if not matched and lookup_ran:
            findings.append(
                _finding(
                    "port_scanner.product_no_cves",
                    category="VULNERABILITY",
                    status=FindingStatus.INFO,
                    confidence=Confidence(product["confidence"]),
                    evidence={"banner": banner, "cpe_candidates": product["cpe_candidates"]},
                    product=product["name"],
                    version=product["version"],
                    port=port["port"],
                )
            )
    return sort_by_severity(findings)
