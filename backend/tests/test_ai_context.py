"""Tests for model policy and context budgeting (no Groq/DB required)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.ai_context import (  # noqa: E402
    MAX_CONTEXT_CHARS,
    MODEL_TEXT,
    MODEL_VISION,
    budget_context,
    format_memory_lines,
    resolve_text_model,
    select_model,
    truncate_text,
)


def test_text_model_is_always_120b():
    assert MODEL_TEXT == "openai/gpt-oss-120b"
    for requested in (None, "balanced", "complex", "openai/gpt-oss-20b", "whatever", ""):
        assert resolve_text_model(requested) == "openai/gpt-oss-120b"


def test_vision_model_only_for_images():
    assert select_model(True) == MODEL_VISION
    assert select_model(False) == "openai/gpt-oss-120b"
    assert "qwen" in select_model(True).lower()


def test_memory_is_recent_first_and_deduped():
    memories = [
        {"key": "target", "content": "newest value", "category": "cloud", "updated_at": "2026-11-26T10:00:00"},
        {"key": "target", "content": "stale value", "category": "cloud", "updated_at": "2026-11-20T10:00:00"},
        {"key": "goal", "content": "SOC2 and DPDP", "category": "compliance", "updated_at": "2026-11-25T10:00:00"},
    ]
    lines = format_memory_lines(memories)
    assert len(lines) == 2
    assert "newest value" in lines[0]
    assert not any("stale value" in line for line in lines)


def test_memory_limit_and_truncation():
    memories = [
        {"key": f"k{i}", "content": "x" * 1000, "updated_at": f"2026-11-{26 - (i % 20):02d}T10:00:00"}
        for i in range(30)
    ]
    lines = format_memory_lines(memories, limit=15, max_chars=100)
    assert len(lines) == 15
    assert all(len(line) < 260 for line in lines)


def test_empty_memories():
    assert format_memory_lines([]) == []
    assert format_memory_lines(None) == []


def test_context_budget_is_enforced():
    parts = ["A" * 9000, "B" * 9000, "C" * 1000]
    out = budget_context(parts)
    assert len(out) <= MAX_CONTEXT_CHARS
    assert "context truncated" in out


def test_context_budget_keeps_priority_order():
    out = budget_context(["primary-telemetry", "graph", "web"])
    assert out.startswith("primary-telemetry")


def test_truncate_text():
    assert truncate_text("abcdef", 10) == "abcdef"
    assert truncate_text("abcdef", 4).endswith("…")
    assert truncate_text(None, 5) == ""


def test_remediation_uses_120b():
    from collectors.authmap_reporter import REMEDIATION_MODEL

    assert REMEDIATION_MODEL == "openai/gpt-oss-120b"
