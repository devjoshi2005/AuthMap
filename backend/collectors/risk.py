"""SGTC hybrid risk scoring.

Kept dependency-free so the formula can be unit-tested without the scanner
stack. ``None`` means "telemetry unavailable" and is excluded from the
calculation instead of silently scoring zero (which used to penalise every
path when CloudTrail was empty).
"""

import math
from typing import Optional

WEIGHTS = {"static": 0.40, "graph": 0.30, "temporal": 0.20, "cost": 0.10}


def hybrid_risk(
    static: Optional[float] = None,
    graph: Optional[float] = None,
    temporal: Optional[float] = None,
    cost: Optional[float] = None,
    weights: Optional[dict] = None,
) -> int:
    """Return a 0-100 hybrid risk score.

    Components are clamped to 0-100. Unavailable (``None``) components are
    dropped and the remaining weights are renormalised, so missing telemetry
    neither inflates nor deflates the result.
    """
    active_weights = dict(weights or WEIGHTS)
    values = {
        "static": None if static is None else _clamp(static),
        "graph": None if graph is None else _clamp(graph),
        "temporal": None if temporal is None else _clamp(temporal),
        "cost": None if cost is None else _clamp(cost),
    }

    available = {
        name: (values[name], weight)
        for name, weight in active_weights.items()
        if values.get(name) is not None and weight > 0
    }
    total_weight = sum(weight for _, weight in available.values())
    if not available or total_weight <= 0:
        return 0

    weighted = {name: value * (weight / total_weight) for name, (value, weight) in available.items()}
    max_floor = max(weighted.values()) * 0.6
    euclidean = math.sqrt(sum(value * value for value in weighted.values())) * 0.4
    raw = max_floor + euclidean

    ceiling = {name: 100.0 * (weight / total_weight) for name, (_, weight) in available.items()}
    max_possible = max(ceiling.values()) * 0.6 + math.sqrt(
        sum(value * value for value in ceiling.values())
    ) * 0.4
    if max_possible <= 0:
        return 0

    return int(round(min(100.0, max(0.0, (raw / max_possible) * 100))))


def severity_for_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _clamp(value: float) -> float:
    try:
        return max(0.0, min(100.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
