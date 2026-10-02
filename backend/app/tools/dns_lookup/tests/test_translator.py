from typing import Any

import pytest

from app.engine.schemas import Confidence, FindingStatus, Severity
from app.tools.dns_lookup.schemas import DnsLookupParams
from app.tools.dns_lookup.translator import (
    parse_dmarc,
    provider_of,
    spf_all_qualifier,
    spf_records,
    translate,
)

PARAMS = DnsLookupParams(domain="example.com")


def raw(**overrides: Any) -> dict[str, Any]:
    """A healthy baseline zone; tests override one aspect at a time."""
    records: dict[str, list[Any]] = {
        "A": ["93.184.216.34"],
        "AAAA": [],
        "CNAME": [],
        "MX": [{"preference": 10, "exchange": "mx.example.com"}],
        "NS": ["a.iana-servers.net", "b.other-dns.org"],
        "TXT": ["v=spf1 include:_spf.example.net -all"],
        "SOA": [],
        "CAA": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}],
    }
    records.update(overrides.pop("records", {}))
    base: dict[str, Any] = {
        "domain": "example.com",
        "nxdomain": False,
        "records": records,
        "record_errors": {},
        "dmarc": ["v=DMARC1; p=reject; rua=mailto:d@example.com"],
        "resolved_ips": records["A"] + records["AAAA"],
        "ptr": {},
        "cname_checks": [],
    }
    base.update(overrides)
    return base


def by_item(findings: list[Any]) -> dict[str, Any]:
    return {f.item: f for f in findings}


def severities(findings: list[Any]) -> dict[str, Severity]:
    return {f.item: f.severity for f in findings}


def test_healthy_zone_has_only_info_findings() -> None:
    findings = translate(raw(), PARAMS)
    assert all(f.severity is Severity.INFO for f in findings), severities(findings)
    items = by_item(findings)
    assert "DNS records collected" in items
    assert "SPF record restricts senders" in items
    assert "DMARC policy enforced (p=reject)" in items
    assert "CAA restricts certificate issuance" in items
    assert "Name servers are redundant" in items


def test_every_finding_is_fully_explained() -> None:
    for finding in translate(
        raw(records={"TXT": [], "CAA": [], "NS": ["ns1.x.com"]}, dmarc=[]), PARAMS
    ):
        assert finding.severity_rationale and finding.explanation and finding.remediation
        assert "$" not in finding.explanation + finding.item + finding.remediation  # all rendered


def test_nxdomain_short_circuits() -> None:
    findings = translate(raw(nxdomain=True), PARAMS)
    assert len(findings) == 1
    assert findings[0].item == "Domain does not exist"
    assert findings[0].status is FindingStatus.ERROR


@pytest.mark.parametrize(
    ("txt", "mx", "expected_item", "severity"),
    [
        ([], [{"preference": 1, "exchange": "mx"}], "No SPF record", Severity.MEDIUM),
        ([], [], "No SPF record (domain does not appear to send mail)", Severity.LOW),
        (["v=spf1 -all", "v=spf1 ~all"], [], "More than one SPF record", Severity.MEDIUM),
        (["v=spf1 +all"], [], "SPF allows every server (+all)", Severity.HIGH),
        (["v=spf1 all"], [], "SPF allows every server (+all)", Severity.HIGH),
        (["v=spf1 ip4:1.2.3.4 ?all"], [], "SPF does not reject unlisted senders", Severity.LOW),
        (["v=spf1 ip4:1.2.3.4"], [], "SPF does not reject unlisted senders", Severity.LOW),
        (["v=spf1 mx ~all"], [], "SPF record restricts senders", Severity.INFO),
    ],
)
def test_spf(txt: list[str], mx: list[Any], expected_item: str, severity: Severity) -> None:
    findings = by_item(translate(raw(records={"TXT": txt, "MX": mx}), PARAMS))
    assert findings[expected_item].severity is severity


def test_spf_ignores_unrelated_txt_records() -> None:
    txt = ["google-site-verification=abc", "v=spf1 -all"]
    assert spf_records(txt) == ["v=spf1 -all"]


@pytest.mark.parametrize(
    ("record", "qualifier"),
    [
        ("v=spf1 -all", "-"),
        ("v=spf1 a mx ~all", "~"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 +all", "+"),
        ("v=spf1 all", "+"),
        ("v=spf1 include:allowed.example.com", None),  # "all" inside a word is not the mechanism
    ],
)
def test_spf_qualifier(record: str, qualifier: str | None) -> None:
    assert spf_all_qualifier(record) == qualifier


@pytest.mark.parametrize(
    ("dmarc", "expected_item", "severity"),
    [
        ([], "No DMARC policy", Severity.MEDIUM),
        (["v=spf1 -all"], "DMARC record is invalid", Severity.MEDIUM),
        (["v=DMARC1; p=none", "v=DMARC1; p=reject"], "DMARC record is invalid", Severity.MEDIUM),
        (["v=DMARC1; rua=mailto:x@y"], "DMARC record is invalid", Severity.MEDIUM),
        (
            ["v=DMARC1; p=none; rua=mailto:x@y"],
            "DMARC is in monitoring mode only (p=none)",
            Severity.LOW,
        ),
        (["v=DMARC1; p=quarantine"], "DMARC policy enforced (p=quarantine)", Severity.INFO),
    ],
)
def test_dmarc(dmarc: list[str], expected_item: str, severity: Severity) -> None:
    findings = by_item(translate(raw(dmarc=dmarc), PARAMS))
    assert findings[expected_item].severity is severity


def test_dmarc_partial_enforcement() -> None:
    findings = by_item(translate(raw(dmarc=["v=DMARC1; p=reject; pct=25"]), PARAMS))
    assert findings["DMARC applies to only part of the mail"].severity is Severity.LOW
    assert "25%" in findings["DMARC applies to only part of the mail"].explanation


def test_parse_dmarc_tags() -> None:
    assert parse_dmarc("v=DMARC1; p=Reject ; pct=50;") == {
        "v": "DMARC1",
        "p": "Reject",
        "pct": "50",
    }


def test_caa_missing_and_unknown() -> None:
    assert (
        by_item(translate(raw(records={"CAA": []}), PARAMS))["No CAA record"].severity
        is Severity.LOW
    )
    # If the CAA query failed we do not claim CAA is missing.
    findings = by_item(
        translate(raw(records={"CAA": []}, record_errors={"CAA": "timeout"}), PARAMS)
    )
    assert "No CAA record" not in findings


def test_dangling_cname_is_high_with_medium_confidence() -> None:
    check = {"name": "www.example.com", "target": "gone.s3.amazonaws.com", "dangling": True}
    findings = by_item(translate(raw(cname_checks=[check]), PARAMS))
    finding = findings["Dangling CNAME (possible subdomain takeover)"]
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert "gone.s3.amazonaws.com" in finding.explanation


def test_nameserver_redundancy() -> None:
    single = by_item(translate(raw(records={"NS": ["ns1.example.com"]}), PARAMS))
    assert single["Only one name server"].severity is Severity.MEDIUM
    one_provider = by_item(
        translate(raw(records={"NS": ["ns1.cloudflare.com", "ns2.cloudflare.com"]}), PARAMS)
    )
    assert one_provider["All name servers belong to one provider"].severity is Severity.LOW


def test_provider_of() -> None:
    assert provider_of("ns-123.awsdns-45.org.") == "awsdns-45.org"
    assert provider_of("NS1.Example.COM") == "example.com"


def test_private_address_is_flagged() -> None:
    findings = by_item(translate(raw(records={"A": ["10.0.0.5", "93.184.216.34"]}), PARAMS))
    finding = findings["Public DNS publishes a private IP address"]
    assert finding.severity is Severity.LOW
    assert finding.evidence == {"internal_ips": ["10.0.0.5"]}


def test_no_address() -> None:
    findings = by_item(translate(raw(records={"A": []}), PARAMS))
    assert "No IPv4 or IPv6 address" in findings


def test_findings_sorted_most_severe_first() -> None:
    findings = translate(raw(records={"TXT": ["v=spf1 +all"], "CAA": []}, dmarc=[]), PARAMS)
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    ranks = [order.index(f.severity) for f in findings]
    assert ranks == sorted(ranks)
