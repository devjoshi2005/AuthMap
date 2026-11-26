"""Unit tests for the SGTC hybrid risk formula."""

from collectors.risk import hybrid_risk, severity_for_score


def test_full_component_score_matches_reference():
    # static 67.5, graph 86.8, temporal 0, cost 92.47 -> historically 69
    assert hybrid_risk(67.5, 86.8, 0.0, 92.47) == 69


def test_missing_temporal_does_not_penalise():
    with_zero = hybrid_risk(67.5, 86.8, 0.0, 92.47)
    without_telemetry = hybrid_risk(67.5, 86.8, None, 92.47)
    assert without_telemetry > with_zero


def test_score_is_monotonic_in_static_risk():
    low = hybrid_risk(20, 50, 10, 40)
    high = hybrid_risk(90, 50, 10, 40)
    assert high > low


def test_weights_are_renormalised_when_components_missing():
    only_static = hybrid_risk(100, None, None, None)  # type: ignore[arg-type]
    assert only_static == 100


def test_score_bounds():
    assert hybrid_risk(-50, 500, 0, 0) == hybrid_risk(0, 100, 0, 0)
    assert 0 <= hybrid_risk(-50, 500, -5, 200) <= 100


def test_severity_thresholds():
    assert severity_for_score(80) == "critical"
    assert severity_for_score(79.9) == "high"
    assert severity_for_score(60) == "high"
    assert severity_for_score(40) == "medium"
    assert severity_for_score(39.9) == "low"
