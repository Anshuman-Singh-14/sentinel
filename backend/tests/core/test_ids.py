import time
import uuid

import pytest

from app.core.ids import new_request_id, sanitize_request_id, uuid7, uuid7_timestamp_ms


def test_uuid7_version_and_variant() -> None:
    value = uuid7()
    assert value.version == 7
    assert value.variant == uuid.RFC_4122


def test_uuid7_embeds_current_time() -> None:
    now_ms = time.time_ns() // 1_000_000
    assert abs(uuid7_timestamp_ms(uuid7()) - now_ms) < 1000


def test_uuid7_sorts_by_creation_time() -> None:
    first = uuid7()
    time.sleep(0.002)
    second = uuid7()
    assert first < second
    assert str(first) < str(second)


def test_uuid7_is_unique() -> None:
    assert len({uuid7() for _ in range(10_000)}) == 10_000


def test_new_request_id_is_uuid7_string() -> None:
    assert uuid.UUID(new_request_id()).version == 7


@pytest.mark.parametrize("value", ["abc", "trace_1-2", str(uuid.uuid4()), "x" * 64])
def test_sanitize_accepts_safe_ids(value: str) -> None:
    assert sanitize_request_id(value) == value


@pytest.mark.parametrize(
    "value", [None, "", "x" * 65, "a b", "line\nbreak", "a/b", "ü", "\x1b[0m", "a\x00b"]
)
def test_sanitize_rejects_unsafe_ids(value: str | None) -> None:
    assert sanitize_request_id(value) is None
