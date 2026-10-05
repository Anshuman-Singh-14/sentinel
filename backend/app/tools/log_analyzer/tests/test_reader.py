import gzip
import io

from app.tools.log_analyzer.reader import ReadStats, iter_lines, open_stream


def read(data: bytes, **limits: int) -> tuple[list[str], ReadStats]:
    stats = ReadStats()
    options = {"max_lines": 1000, "max_line_bytes": 64, "max_total_bytes": 10_000} | limits
    stream = open_stream(io.BufferedReader(io.BytesIO(data)), stats)
    return list(iter_lines(stream, stats, **options)), stats


def test_lines_crlf_and_last_line_without_newline() -> None:
    lines, stats = read(b"a\r\nb\nc")
    assert lines == ["a", "b", "c"] and stats.lines == 3 and stats.stopped_early is None


def test_long_lines_are_cut_and_skipped_in_bounded_chunks() -> None:
    lines, stats = read(b"x" * 500 + b"\nshort\n", max_line_bytes=64)
    assert lines == ["x" * 64, "short"]
    assert stats.truncated_lines == 1


def test_a_file_without_newlines_does_not_get_buffered_whole() -> None:
    lines, stats = read(b"y" * 5000, max_line_bytes=64)
    assert lines == ["y" * 64] and stats.truncated_lines == 1


def test_line_limit_stops_early_and_says_so() -> None:
    lines, stats = read(b"l\n" * 50, max_lines=10)
    assert len(lines) == 10 and stats.stopped_early is not None
    assert "line limit" in stats.stopped_early


def test_invalid_utf8_and_nul_bytes_do_not_abort() -> None:
    lines, _ = read(b"ok \xff\xfe bad\nnul \x00 byte\n")
    assert lines[0] == "ok �� bad" and lines[1] == "nul \x00 byte"


def test_gzip_is_detected_by_magic_bytes() -> None:
    lines, stats = read(gzip.compress(b"one\ntwo\n"))
    assert lines == ["one", "two"] and stats.compressed


def test_gzip_bomb_is_capped() -> None:
    bomb = gzip.compress(b"A" * 63 + b"\n" * 1 + (b"A" * 63 + b"\n") * 20_000)
    assert len(bomb) < 5000  # tiny on disk...
    lines, stats = read(bomb, max_total_bytes=4096, max_lines=10**6)
    # ...but reading stops at the decompressed-size cap.
    assert stats.bytes_read <= 4096 and len(lines) <= 64
    assert stats.stopped_early is not None and "size limit" in stats.stopped_early


def test_truncated_gzip_reports_corruption() -> None:
    lines, stats = read(gzip.compress(b"line\n" * 1000)[:40])
    assert stats.stopped_early is not None and "corrupt" in stats.stopped_early
    assert isinstance(lines, list)


def test_empty_file() -> None:
    assert read(b"") == ([], ReadStats())
