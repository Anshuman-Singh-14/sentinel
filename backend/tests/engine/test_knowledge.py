from pathlib import Path

import pytest

from app.engine.knowledge import KnowledgeError, get_knowledge_base, load_knowledge
from app.engine.schemas import Severity

VALID = """\
schema_version: 1
namespace: demo
version: "1.2.0"
entries:
  demo.open_port:
    title: Port $port is open
    explanation: Port $port accepts connections. Not $missing.
    remediation: Close it.
    severity: MEDIUM
    severity_rationale: Exposed service increases attack surface (CWE-1327).
    references: [CWE-1327]
"""


def write(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    return path


def test_bundled_knowledge_loads() -> None:
    kb = get_knowledge_base()
    assert "echo.message_received" in kb
    assert kb.versions["echo"] == "1.0.0"
    assert kb.get("echo.message_received").severity == Severity.INFO


def test_valid_file(tmp_path: Path) -> None:
    write(tmp_path, "demo.yaml", VALID)
    kb = load_knowledge(tmp_path)

    entry = kb.get("demo.open_port")
    assert entry.references == ("CWE-1327",)
    assert kb.versions == {"demo": "1.2.0"}


def test_render_substitutes_known_and_keeps_unknown_placeholders(tmp_path: Path) -> None:
    write(tmp_path, "demo.yaml", VALID)
    entry = load_knowledge(tmp_path).get("demo.open_port")

    assert entry.render("explanation", port=23) == "Port 23 accepts connections. Not $missing."


def test_render_cannot_reach_attributes(tmp_path: Path) -> None:
    content = VALID.replace("Close it.", "${port.__class__} ${port}")
    write(tmp_path, "demo.yaml", content)
    entry = load_knowledge(tmp_path).get("demo.open_port")

    # Template only substitutes plain identifiers, so the dotted form is left
    # untouched and nothing about the object leaks.
    rendered = entry.render("remediation", port=22)
    assert "class" not in rendered.replace("${port.__class__}", "")
    assert rendered.endswith(" 22")


def test_unknown_entry(tmp_path: Path) -> None:
    write(tmp_path, "demo.yaml", VALID)
    with pytest.raises(KnowledgeError, match="Unknown"):
        load_knowledge(tmp_path).get("demo.nope")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        # Arbitrary Python object construction must be refused (safe_load only).
        ("!!python/object/apply:os.system ['echo pwned']", "invalid"),
        ("entries: [unclosed", "invalid"),
        (VALID.replace("severity: MEDIUM", "severity: SEVERE"), "invalid"),
        (VALID.replace("    references:", "    unexpected: 1\n    references:"), "invalid"),
        (VALID.replace("schema_version: 1", "schema_version: 2"), "invalid"),
        (VALID.replace("demo.open_port:", "other.open_port:"), "must start with"),
    ],
)
def test_bad_files_are_rejected(tmp_path: Path, content: str, message: str) -> None:
    write(tmp_path, "demo.yaml", content)
    with pytest.raises(KnowledgeError, match=message):
        load_knowledge(tmp_path)


def test_duplicate_namespace_rejected(tmp_path: Path) -> None:
    write(tmp_path, "a.yaml", VALID)
    write(tmp_path, "b.yaml", VALID)
    with pytest.raises(KnowledgeError, match="duplicate namespace"):
        load_knowledge(tmp_path)
