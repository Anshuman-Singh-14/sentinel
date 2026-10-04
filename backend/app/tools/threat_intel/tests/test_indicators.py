import pytest
from pydantic import ValidationError

from app.tools.threat_intel.indicators import IndicatorKind, classify
from app.tools.threat_intel.schemas import ThreatIntelParams

SHA256 = "a" * 64


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("45.33.32.156", IndicatorKind.IP, "45.33.32.156"),
        ("2001:4860:4860::8888", IndicatorKind.IP, "2001:4860:4860::8888"),
        ("Example.COM.", IndicatorKind.DOMAIN, "example.com"),
        ("bücher.example", IndicatorKind.DOMAIN, "xn--bcher-kva.example"),
        (SHA256.upper(), IndicatorKind.HASH, SHA256),
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            IndicatorKind.HASH,
            "d41d8cd98f00b204e9800998ecf8427e",
        ),
    ],
)
def test_classify(raw: str, kind: IndicatorKind, value: str) -> None:
    indicator = classify(raw)
    assert (indicator.kind, indicator.value, indicator.lookup) == (kind, value, True)


@pytest.mark.parametrize(
    "raw", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.169.254", "::1", "::ffff:10.1.2.3"]
)
def test_private_addresses_are_kept_but_never_looked_up(raw: str) -> None:
    indicator = classify(raw)
    assert indicator.kind is IndicatorKind.IP and not indicator.lookup
    assert "never sent" in (indicator.skip_reason or "")


@pytest.mark.parametrize(
    "raw", ["postgres.internal", "printer.local", "http://evil.example/x", "not a thing", "x" * 300]
)
def test_invalid_or_internal_indicators_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        classify(raw)


def test_params_accept_text_or_list_and_deduplicate() -> None:
    from_text = ThreatIntelParams.model_validate(
        {"indicators": "45.33.32.156, example.com\n45.33.32.156;EXAMPLE.com"}
    )
    assert from_text.indicators == ["45.33.32.156", "example.com"]
    from_list = ThreatIntelParams.model_validate({"indicators": ["45.33.32.156", "10.0.0.1"]})
    assert [i.lookup for i in from_list.parsed()] == [True, False]


def test_params_limits_and_schema() -> None:
    with pytest.raises(ValidationError):
        ThreatIntelParams.model_validate({"indicators": []})
    with pytest.raises(ValidationError):
        ThreatIntelParams.model_validate({"indicators": [f"45.33.32.{i}" for i in range(21)]})
    with pytest.raises(ValidationError):
        ThreatIntelParams.model_validate({"indicators": "45.33.32.156", "extra": 1})
    schema = ThreatIntelParams.model_json_schema()
    # The generated form renders a text field; the API still takes lists.
    assert schema["properties"]["indicators"]["type"] == "string"
