"""Path traversal protection (04-security.md sections 5 and 9).

Covers ``../``, encoded variants, absolute paths, null bytes, symlink escapes
and non-regular files. Encoded input stays literal: PathGuard never URL-decodes,
so ``..%2f`` is just an odd file name that does not exist.
"""

import os
from pathlib import Path

import pytest

from app.core.errors import NotFound
from app.core.security.paths import PathGuard, PathRejected, check_relative_path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "logs"
    (base / "nginx").mkdir(parents=True)
    (base / "auth.log").write_text("ok\n", encoding="utf-8")
    (base / "nginx" / "access.log").write_text("ok\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("secret\n", encoding="utf-8")
    return base


def symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError:  # pragma: no cover - Windows without the symlink privilege
        pytest.skip("symlinks unavailable")


def test_files_inside_the_root_resolve(root: Path) -> None:
    guard = PathGuard([root])
    found = guard.resolve("nginx/access.log")
    assert found.relative == "nginx/access.log" and found.size == 3
    with guard.open(found) as handle:
        assert handle.read() == b"ok\n"


def test_redundant_segments_are_normalised(root: Path) -> None:
    assert PathGuard([root]).resolve("./nginx//access.log").relative == "nginx/access.log"


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("../secret.txt", "'..'"),
        ("nginx/../../secret.txt", "'..'"),
        ("..", "'..'"),
        ("/etc/passwd", "absolute"),
        ("C:/Windows/win.ini", "absolute"),
        ("..\\secret.txt", "forward slashes"),
        ("auth.log\x00.png", "null byte"),
        ("auth\x1b.log", "control"),
        ("", "1-255"),
        ("a" * 256, "1-255"),
    ],
)
def test_syntactic_rejections(root: Path, path: str, message: str) -> None:
    with pytest.raises(PathRejected, match=message):
        PathGuard([root]).resolve(path)
    with pytest.raises(PathRejected):
        check_relative_path(path)


@pytest.mark.parametrize("path", ["..%2fsecret.txt", "%2e%2e/secret.txt", "..%252fsecret.txt"])
def test_encoded_traversal_is_a_literal_missing_file(root: Path, path: str) -> None:
    with pytest.raises(NotFound):
        PathGuard([root]).resolve(path)


def test_symlink_out_of_the_root_is_refused(root: Path) -> None:
    symlink(root / "escape.log", root.parent / "secret.txt")
    with pytest.raises(PathRejected, match="outside"):
        PathGuard([root]).resolve("escape.log")


def test_symlinked_directory_out_of_the_root_is_refused(root: Path) -> None:
    outside = root.parent / "elsewhere"
    outside.mkdir()
    (outside / "x.log").write_text("x", encoding="utf-8")
    symlink(root / "dir", outside)
    with pytest.raises(PathRejected, match="outside"):
        PathGuard([root]).resolve("dir/x.log")


def test_symlink_inside_the_root_is_allowed(root: Path) -> None:
    symlink(root / "current.log", root / "auth.log")
    assert PathGuard([root]).resolve("current.log").path == (root / "auth.log").resolve()


def test_swapped_for_a_symlink_after_resolve_is_refused_at_open(root: Path) -> None:
    guard = PathGuard([root])
    found = guard.resolve("auth.log")
    os.remove(root / "auth.log")
    symlink(root / "auth.log", root.parent / "secret.txt")
    with pytest.raises(PathRejected):
        guard.open(found)


def test_directories_and_missing_files(root: Path) -> None:
    guard = PathGuard([root])
    with pytest.raises(PathRejected, match="regular file"):
        guard.resolve("nginx")
    with pytest.raises(NotFound):
        guard.resolve("missing.log")


def test_missing_root_allows_nothing(tmp_path: Path) -> None:
    with pytest.raises(NotFound):
        PathGuard([tmp_path / "absent"]).resolve("auth.log")
