"""Bounded, streaming line reader (02-modules.md: "never loads huge files fully").

Memory use is independent of file size: the file is read one line at a time,
and every dimension has a cap.

* **Line length:** a line longer than ``max_line_bytes`` is cut, and the rest
  of it is skipped in bounded chunks. A file with no newlines (or a hostile
  one) cannot make us buffer it whole.
* **Line count:** reading stops at ``max_lines``; the result says so.
* **gzip:** recognised by its magic bytes, not the file name. Decompressed
  output is capped as well, so a small "zip bomb" cannot expand without limit.
* **Encoding:** decoded as UTF-8 with replacement characters. Logs are not
  guaranteed to be valid text, and a bad byte must not abort the analysis.
"""

import gzip
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

GZIP_MAGIC = b"\x1f\x8b"
_SKIP_CHUNK = 65_536


@dataclass(slots=True)
class ReadStats:
    lines: int = 0
    bytes_read: int = 0
    truncated_lines: int = 0
    stopped_early: str | None = None  # why reading stopped before the end, if it did
    compressed: bool = False
    notes: list[str] = field(default_factory=list)


class _CappedStream:
    """Wraps a stream and refuses to yield more than ``limit`` bytes in total."""

    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self._stream = stream
        self._left = limit
        self.exhausted = False

    def readline(self, size: int) -> bytes:
        if self._left <= 0:
            self.exhausted = True
            return b""
        data = self._stream.readline(min(size, self._left))
        self._left -= len(data)
        return data


def open_stream(raw: BinaryIO, stats: ReadStats) -> BinaryIO:
    """Return a decompressing stream for gzip input, or the stream itself."""
    head = raw.peek(2)[:2] if hasattr(raw, "peek") else b""
    if not head:
        head = raw.read(2)
        raw.seek(0)
    if head == GZIP_MAGIC:
        stats.compressed = True
        return gzip.GzipFile(fileobj=raw, mode="rb")  # type: ignore[return-value]
    return raw


def iter_lines(
    stream: BinaryIO,
    stats: ReadStats,
    *,
    max_lines: int,
    max_line_bytes: int,
    max_total_bytes: int,
) -> Iterator[str]:
    """Yield decoded lines without trailing newlines, updating ``stats``."""
    capped = _CappedStream(stream, max_total_bytes)
    while True:
        if stats.lines >= max_lines:
            stats.stopped_early = f"line limit reached ({max_lines:,} lines)"
            return
        try:
            chunk = capped.readline(max_line_bytes + 1)
        except (OSError, EOFError, gzip.BadGzipFile):
            stats.stopped_early = "the file is corrupt or not a complete gzip archive"
            return
        if not chunk:
            if capped.exhausted:
                stats.stopped_early = f"size limit reached ({max_total_bytes:,} bytes)"
            return
        stats.bytes_read += len(chunk)
        if len(chunk) > max_line_bytes and not chunk.endswith(b"\n"):
            # Too long: keep the first part and skip to the next newline.
            stats.truncated_lines += 1
            chunk = chunk[:max_line_bytes]
            while True:
                rest = capped.readline(_SKIP_CHUNK)
                stats.bytes_read += len(rest)
                if not rest or rest.endswith(b"\n"):
                    break
        stats.lines += 1
        yield chunk.rstrip(b"\r\n").decode("utf-8", errors="replace")
