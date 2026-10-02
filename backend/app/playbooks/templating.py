"""Safe references between playbook steps (02-modules.md: "no Jinja eval").

A parameter value may contain ``{{ reference }}`` placeholders, where a
reference is a dotted path with optional list indexes, rooted at ``inputs``
or ``steps``:

    {{ inputs.target }}
    {{ steps.dns.resolved_ips[0] }}
    https://{{ inputs.target }}/

What this deliberately is *not*: a template language. There are no filters,
no function calls, no arithmetic and no attribute access on Python objects.
Paths walk plain JSON data (dicts by key, lists by index) and nothing else,
so a playbook definition cannot execute code or reach into the interpreter.

* A value that is exactly one placeholder keeps the referenced value's type
  (a list stays a list).
* A placeholder inside a longer string must resolve to a scalar, which is
  then interpolated.
"""

import re
from collections.abc import Mapping
from typing import Any

PLACEHOLDER = re.compile(r"\{\{\s*([^{}]*?)\s*\}\}")
_PATH = re.compile(r"^(inputs|steps)(?:\.[a-z_][a-z0-9_]*|\[\d{1,4}\])+$")
_TOKEN = re.compile(r"\.([a-z_][a-z0-9_]*)|\[(\d{1,4})\]")
MAX_RENDERED_LENGTH = 4096


class TemplateReferenceError(Exception):
    """A reference is malformed or points at data that does not exist."""


def parse_reference(expression: str) -> tuple[str, list[str | int]]:
    expression = expression.strip()
    if not _PATH.fullmatch(expression):
        raise TemplateReferenceError(
            f"'{{{{ {expression} }}}}' is not a valid reference "
            "(use inputs.name or steps.step_id.field[0])."
        )
    root = "inputs" if expression.startswith("inputs") else "steps"
    rest = expression[len(root) :]  # e.g. ".dns.resolved_ips[0]"; fully validated above
    tokens: list[str | int] = [key if key else int(index) for key, index in _TOKEN.findall(rest)]
    return root, tokens


def references_in(value: Any) -> list[tuple[str, list[str | int]]]:
    """Every reference in a (possibly nested) parameter value, for load-time validation."""
    found: list[tuple[str, list[str | int]]] = []
    if isinstance(value, str):
        found.extend(parse_reference(m.group(1)) for m in PLACEHOLDER.finditer(value))
    elif isinstance(value, Mapping):
        for item in value.values():
            found.extend(references_in(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(references_in(item))
    return found


def _lookup(context: Mapping[str, Any], root: str, path: list[str | int], text: str) -> Any:
    current: Any = context.get(root)
    walked = root
    for token in path:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise TemplateReferenceError(f"'{text}': {walked} has no item [{token}].")
            current = current[token]
            walked += f"[{token}]"
        else:
            if not isinstance(current, Mapping) or token not in current:
                raise TemplateReferenceError(f"'{text}': {walked} has no field '{token}'.")
            current = current[token]
            walked += f".{token}"
    return current


def render(value: Any, context: Mapping[str, Any]) -> Any:
    """Resolve every placeholder in ``value`` against ``context`` (inputs, steps)."""
    if isinstance(value, Mapping):
        return {k: render(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, context) for v in value]
    if not isinstance(value, str) or "{{" not in value:
        return value

    whole = PLACEHOLDER.fullmatch(value.strip())
    if whole:
        root, path = parse_reference(whole.group(1))
        return _lookup(context, root, path, whole.group(0))

    def substitute(match: re.Match[str]) -> str:
        root, path = parse_reference(match.group(1))
        resolved = _lookup(context, root, path, match.group(0))
        if isinstance(resolved, (dict, list)) or resolved is None:
            raise TemplateReferenceError(
                f"'{match.group(0)}' is not a single value and cannot be placed inside text."
            )
        return str(resolved)

    rendered = PLACEHOLDER.sub(substitute, value)
    if len(rendered) > MAX_RENDERED_LENGTH:
        raise TemplateReferenceError("A parameter became too long after references were resolved.")
    return rendered
