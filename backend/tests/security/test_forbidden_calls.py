"""Static check that forbidden execution primitives never appear in app code.

Enforces CLAUDE.md rule 1 and 04-security.md section 1 from day one. bandit
catches most of these too, but this test runs with every ``pytest`` and fails
loudly instead of producing a warning someone might skim past.
"""

import ast
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[2] / "app"

FORBIDDEN_MODULES = {"subprocess", "pickle", "marshal", "shelve", "pty", "commands"}
FORBIDDEN_BUILTINS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_ATTR_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("yaml", "load"),
    ("yaml", "unsafe_load"),
    ("yaml", "full_load"),
}
FORBIDDEN_OS_PREFIXES = ("exec", "spawn", "posix_spawn")


def _violations(source: str, filename: str) -> list[str]:
    tree = ast.parse(source, filename=filename)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    found.append(f"{filename}:{node.lineno} import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".")[0]
            if module in FORBIDDEN_MODULES:
                found.append(f"{filename}:{node.lineno} from {node.module} import")
            if module == "os" and any(
                a.name in {"system", "popen"} or a.name.startswith(FORBIDDEN_OS_PREFIXES)
                for a in node.names
            ):
                found.append(f"{filename}:{node.lineno} from os import <exec primitive>")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
                found.append(f"{filename}:{node.lineno} call {func.id}()")
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                pair = (func.value.id, func.attr)
                if pair in FORBIDDEN_ATTR_CALLS or (
                    func.value.id == "os" and func.attr.startswith(FORBIDDEN_OS_PREFIXES)
                ):
                    found.append(f"{filename}:{node.lineno} call {pair[0]}.{pair[1]}()")
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    found.append(f"{filename}:{node.lineno} shell=True")
    return found


def test_app_code_has_no_forbidden_calls() -> None:
    files = sorted(APP_DIR.rglob("*.py"))
    assert files, f"no Python files found under {APP_DIR}"
    violations = [
        v for path in files for v in _violations(path.read_text(encoding="utf-8"), str(path))
    ]
    assert violations == [], "Forbidden constructs found:\n" + "\n".join(violations)


@pytest.mark.parametrize(
    "snippet",
    [
        "import subprocess",
        "import pickle",
        "from subprocess import run",
        "from os import system",
        "os.system('ls')",
        "os.popen('ls')",
        "os.execv('/bin/sh', [])",
        "eval('1')",
        "exec('x=1')",
        "yaml.load(data)",
        "run(cmd, shell=True)",
    ],
)
def test_detector_catches_known_bad_patterns(snippet: str) -> None:
    """Prove the checker itself works, so a passing scan means something."""
    assert _violations(snippet, "<snippet>")


def test_detector_allows_safe_patterns() -> None:
    safe = "import os\nos.path.join('a', 'b')\nyaml.safe_load(data)\nrun(cmd, shell=False)"
    assert _violations(safe, "<snippet>") == []
