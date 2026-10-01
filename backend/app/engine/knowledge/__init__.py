"""Versioned explanation and remediation text (YAML)."""

from app.engine.knowledge.loader import (
    KnowledgeBase,
    KnowledgeEntry,
    KnowledgeError,
    get_knowledge_base,
    load_knowledge,
)

__all__ = [
    "KnowledgeBase",
    "KnowledgeEntry",
    "KnowledgeError",
    "get_knowledge_base",
    "load_knowledge",
]
