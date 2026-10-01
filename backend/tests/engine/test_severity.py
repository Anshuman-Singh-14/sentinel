import math

import pytest

from app.engine.schemas import Severity
from app.engine.severity import (
    cvss_rationale,
    highest_severity,
    severity_from_cvss,
    sort_by_severity,
)
from tests.engine.test_schemas import make_finding


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_cvss_v31_band_boundaries(score: float, expected: Severity) -> None:
    assert severity_from_cvss(score) == expected


@pytest.mark.parametrize("score", [-0.1, 10.1, math.nan, math.inf])
def test_invalid_cvss_rejected(score: float) -> None:
    with pytest.raises(ValueError, match="CVSS"):
        severity_from_cvss(score)


def test_rationale_names_score_band_and_standard() -> None:
    text = cvss_rationale(7.5, "CVE-2024-6387")
    assert "CVE-2024-6387" in text
    assert "7.5" in text
    assert "HIGH" in text
    assert "7.0-8.9" in text
    assert "FIRST CVSS v3.1" in text


def test_highest_severity() -> None:
    assert highest_severity([Severity.LOW, Severity.CRITICAL, Severity.INFO]) == Severity.CRITICAL
    assert highest_severity([]) is None


def test_sort_most_severe_first_and_stable() -> None:
    low_a = make_finding(Severity.LOW, item="a")
    high = make_finding(Severity.HIGH, item="h")
    low_b = make_finding(Severity.LOW, item="b")

    assert [f.item for f in sort_by_severity([low_a, high, low_b])] == ["h", "a", "b"]
