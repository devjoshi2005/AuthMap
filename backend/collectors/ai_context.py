"""Model policy and context-budget helpers for the AuthMap AI assistant.

Dependency-free so the behaviour can be unit-tested without Groq/Neo4j.

Policy (per product decision):
* Text/consultant/remediation -> openai/gpt-oss-120b, always.
* Image questions             -> qwen vision model, only when an image is sent.
* 20b is never used for user-facing answers (it returned blank completions).
"""

from typing import Any, Dict, Iterable, List, Optional

MODEL_TEXT = "openai/gpt-oss-120b"
MODEL_VISION = "qwen/qwen3.6-27b"

# Groq's 120b tier allows ~8k tokens per minute (prompt + completion).
# ~4 chars/token keeps a 16k-char context around 4k tokens, leaving room to answer.
MAX_CONTEXT_CHARS = 16000
MEMORY_LIMIT = 15
MEMORY_ITEM_CHARS = 300


def resolve_text_model(requested: Optional[str] = None) -> str:
    """Any text request maps to the 120b consultant model (constant)."""
    return MODEL_TEXT


def select_model(has_image: bool) -> str:
    return MODEL_VISION if has_image else MODEL_TEXT


def truncate_text(text: Any, limit: int) -> str:
    value = str(text or "")
    if limit <= 0 or len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def _sort_key(memory: Dict[str, Any]) -> str:
    return str(memory.get("updated_at") or memory.get("created_at") or "")


def format_memory_lines(
    memories: Optional[Iterable[Dict[str, Any]]],
    limit: int = MEMORY_LIMIT,
    max_chars: int = MEMORY_ITEM_CHARS,
) -> List[str]:
    """Most-recent-first, one line per memory key, hard-truncated.

    The SQL query returns DESC by updated_at; sorting defensively keeps this
    correct even if a caller passes an unordered list.
    """
    if not memories:
        return []

    ordered = sorted(list(memories), key=_sort_key, reverse=True)
    seen_keys = set()
    lines: List[str] = []

    for memory in ordered:
        if len(lines) >= limit:
            break
        key = str(memory.get("key") or "").strip()
        identity = key.lower() or str(memory.get("id") or "")
        if identity and identity in seen_keys:
            continue
        content = truncate_text(memory.get("content"), max_chars).strip()
        if not content:
            continue
        if identity:
            seen_keys.add(identity)
        category = str(memory.get("category") or "general").replace("_", " ").title()
        label = key.replace("_", " ").title() if key else "Note"
        lines.append(f"- **{category}** ({label}): {content}")

    return lines


def budget_context(parts: Iterable[str], max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """Join context blocks and cap the total size, preserving priority order."""
    joined = "\n\n".join(part for part in parts if part)
    if len(joined) <= max_chars:
        return joined
    return joined[: max(0, max_chars - 40)].rstrip() + "\n\n[context truncated to token budget]"
