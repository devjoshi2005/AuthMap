"""Regression tests for the report overhaul.

These exercise the pure data layer and both Jinja templates. They deliberately
avoid the database, Groq and WeasyPrint so they can run in CI without external
services.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.report_utils import (  # noqa: E402
    build_violation_groups,
    compute_cc6_controls,
    compute_control_matrix,
    humanize_text,
    is_human_identity,
    is_service_linked_identity,
    normalize_framework,
    normalize_path,
    resource_type_from_arn,
    short_name,
    wrap_long_id,
)


# ---------------------------------------------------------------------------
# Identity classification
# ---------------------------------------------------------------------------

def test_service_linked_roles_are_not_human():
    assert not is_human_identity(
        {"entity_arn": "arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS", "entity_type": "role"}
    )
    assert not is_human_identity(
        {"entity_arn": "arn:aws:iam::aws:policy/AdministratorAccess", "entity_type": "policy"}
    )


def test_custom_role_is_human():
    assert is_human_identity(
        {"entity_arn": "arn:aws:iam::123456789012:role/Admin_Manager", "entity_type": "role"}
    )
    assert is_human_identity(
        {"entity_arn": "arn:aws:iam::123456789012:user/alice", "entity_type": "user"}
    )


def test_service_linked_helper_matches_aws_managed_policies():
    assert is_service_linked_identity({"entity_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
    assert is_service_linked_identity({"entity_arn": "arn:aws:iam::1:role/x/AWSServiceRoleForX"})


# ---------------------------------------------------------------------------
# Violation grouping (the "30 identical pages" bug)
# ---------------------------------------------------------------------------

def test_identical_violations_group_into_one_entry():
    violations = [
        {"violation_type": "SOC2 CC6.1", "compliance_framework": "SOC2", "resource_id": f"arn:aws:iam::1:role/r{i}", "severity": "high"}
        for i in range(20)
    ]
    groups = build_violation_groups(violations)
    assert len(groups) == 1, "identical rule/framework must collapse to one group"
    assert groups[0]["count"] == 20


def test_different_frameworks_stay_separate():
    violations = [
        {"violation_type": "SOC2 CC6.3", "compliance_framework": "SOC2", "resource_id": "arn:a", "severity": "critical"},
        {"violation_type": "SOC2 CC6.3", "compliance_framework": "DPDP", "resource_id": "arn:b", "severity": "high"},
    ]
    groups = build_violation_groups(violations)
    assert len(groups) == 2


def test_group_severity_is_the_worst_member():
    violations = [
        {"violation_type": "R", "compliance_framework": "SOC2", "resource_id": "arn:a", "severity": "low"},
        {"violation_type": "R", "compliance_framework": "SOC2", "resource_id": "arn:b", "severity": "critical"},
    ]
    assert build_violation_groups(violations)[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# CC6 posture matrix
# ---------------------------------------------------------------------------

def _entity(arn, kind="role"):
    return {"entity_arn": arn, "entity_type": kind}


def test_cc6_pass_when_no_violations():
    controls = compute_cc6_controls([])
    assert {c["status"] for c in controls} == {"PASS"}


def test_cc6_fails_when_human_identity_affected():
    entities = {"arn:aws:iam::1:role/human": _entity("arn:aws:iam::1:role/human")}
    violations = [{"violation_type": "SOC2 CC6.3", "resource_id": "arn:aws:iam::1:role/human"}]
    controls = {c["id"]: c for c in compute_cc6_controls(violations, entities)}
    assert controls["CC6.3"]["status"] == "FAIL"
    assert controls["CC6.3"]["human_count"] == 1


def test_cc6_partial_when_only_workload_affected():
    entities = {"arn:aws:iam::1:role/AWSServiceRoleForX": _entity("arn:aws:iam::1:role/AWSServiceRoleForX")}
    violations = [{"violation_type": "SOC2 CC6.1", "resource_id": "arn:aws:iam::1:role/AWSServiceRoleForX"}]
    controls = {c["id"]: c for c in compute_cc6_controls(violations, entities)}
    assert controls["CC6.1"]["status"] == "PARTIAL"
    assert controls["CC6.1"]["human_count"] == 0


# ---------------------------------------------------------------------------
# Path normalisation / typography helpers
# ---------------------------------------------------------------------------

def test_path_normalisation_builds_chain():
    path = {
        "path_name": "alice → Admin",
        "path_nodes": {"nodes": ["arn:aws:iam::1:user/alice", "arn:aws:iam::1:role/Admin"]},
        "hybrid_risk_score": 92,
        "risk_severity": "critical",
        "estimated_cost_impact": 1000,
    }
    normalised = normalize_path(path)
    assert normalised["chain"] == "alice → Admin"
    assert normalised["score"] == 92
    assert normalised["severity"] == "critical"


def test_wrap_long_id_adds_break_opportunities():
    arn = "arn:aws:iam::123456789012:role/AuthMap-Scanner-authmap"
    wrapped = wrap_long_id(arn)
    assert "\u200b" in wrapped
    assert wrapped.replace("\u200b", "") == arn


def test_short_name():
    assert short_name("arn:aws:iam::1:role/Admin_Manager") == "Admin_Manager"


# ---------------------------------------------------------------------------
# Executive summary assembly (no DB, no LLM)
# ---------------------------------------------------------------------------

def _bundle():
    human = {
        "arn:aws:iam::1:user/alice": {
            "arn": "arn:aws:iam::1:user/alice", "name": "alice", "type": "user",
            "is_admin": True, "has_mfa": False, "is_dormant": True,
            "is_overprivileged": True, "risk_score": 88,
        },
        "arn:aws:iam::1:role/Admin": {
            "arn": "arn:aws:iam::1:role/Admin", "name": "Admin", "type": "role",
            "is_admin": True, "has_mfa": False, "is_dormant": False,
            "is_overprivileged": False, "risk_score": 70,
        },
    }
    index = dict(human)
    index["arn:aws:iam::1:role/AWSServiceRoleForX"] = {
        "arn": "arn:aws:iam::1:role/AWSServiceRoleForX", "name": "AWSServiceRoleForX",
        "type": "role", "is_admin": True, "has_mfa": False, "is_dormant": False,
        "is_overprivileged": False, "risk_score": 0,
    }
    return {
        "scan": {"id": "scan-1", "scan_name": "AWS Scan - Operator", "csp_target": "aws",
                 "created_at": "2026-11-26T02:40:00+00:00"},
        "paths": [
            {"path_nodes": {"nodes": ["arn:aws:iam::1:user/alice", "arn:aws:iam::1:role/Admin"]},
             "hybrid_risk_score": 92, "risk_severity": "critical",
             "estimated_cost_impact": 250000, "path_length": 1, "path_description": "escalation"},
        ],
        "violations": [
            {"violation_type": "SOC2 CC6.3", "compliance_framework": "SOC2",
             "resource_id": "arn:aws:iam::1:user/alice", "severity": "critical", "resource_type": "user"},
            {"violation_type": "SOC2 CC6.1", "compliance_framework": "SOC2",
             "resource_id": "arn:aws:iam::1:role/AWSServiceRoleForX", "severity": "medium", "resource_type": "role"},
        ],
        "index": index,
        "human": human,
        "workload_count": 1,
        "frameworks_in_scope": ["SOC2", "DPDP"],
    }


def test_executive_summary_identity_count_is_nonzero():
    from collectors.authmap_reporter import build_executive_summary

    summary = build_executive_summary(_bundle())
    assert summary["total_identities"] == 2
    assert summary["critical_paths"] == 1
    assert len(summary["top_3_risks"]) <= 3
    assert summary["breach_cost"] == 250000
    assert summary["cc6_controls"][2]["id"] == "CC6.3"
    assert summary["cc6_controls"][2]["status"] == "FAIL"


def test_executive_actions_are_generated():
    from collectors.authmap_reporter import build_executive_summary

    summary = build_executive_summary(_bundle())
    assert summary["actions"]
    assert any("MFA" in action["action"] for action in summary["actions"])


# ---------------------------------------------------------------------------
# Template distinctness (rendered HTML, no WeasyPrint needed)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("template_name", ["EXECUTIVE_TEMPLATE", "TECHNICAL_TEMPLATE"])
def test_templates_render_without_error(template_name):
    pytest.importorskip("jinja2")
    from jinja2 import Environment

    from collectors import authmap_reporter as reporter

    env = Environment(autoescape=True)
    env.filters["money"] = lambda v: f"{float(v or 0):,.0f}"
    env.filters["short"] = short_name
    env.filters["wrap"] = wrap_long_id
    env.filters["yn"] = lambda v: "Yes" if v else "No"
    env.filters["humanize"] = humanize_text

    data = _template_data()
    html = env.from_string(getattr(reporter, template_name)).render(**data)
    assert "AuthMap" in html or "AUTHMAP" in html


def test_executive_and_technical_content_are_distinct():
    pytest.importorskip("jinja2")
    from jinja2 import Environment

    from collectors import authmap_reporter as reporter

    env = Environment(autoescape=True)
    env.filters["money"] = lambda v: f"{float(v or 0):,.0f}"
    env.filters["short"] = short_name
    env.filters["wrap"] = wrap_long_id
    env.filters["yn"] = lambda v: "Yes" if v else "No"
    env.filters["humanize"] = humanize_text

    data = _template_data()
    executive = env.from_string(reporter.EXECUTIVE_TEMPLATE).render(**data)
    technical = env.from_string(reporter.TECHNICAL_TEMPLATE).render(**data)

    assert executive != technical
    assert "Executive Security Briefing" in executive
    assert "Identities evaluated" in executive
    assert "<pre>" not in executive  # no code walls in the ministerial dossier

    assert "Engineering Remediation Runbook" in technical
    assert "AI-recommended remediation" in technical
    assert "<pre>" in technical


def _template_data():
    path = {
        "chain": "alice → Admin", "target": "Admin", "source": "alice", "score": 92,
        "severity": "critical", "cost": 250000, "hops": 1, "description": "escalation",
        "name": "alice → Admin", "nodes": ["arn:a", "arn:b"], "id": "p1",
    }
    return {
        "scan_id": "scan-1", "scan_name": "AWS Scan - Operator", "csp_target": "AWS",
        "audit_date": "26 Nov 2026", "aws_account_id": "123456789012",
        "total_identities": 2, "human_count": 2, "workload_count": 1,
        "total_paths": 1, "critical_paths": 1, "actionable_paths": 1,
        "breakdown": {"critical": 1, "high": 0, "medium": 0, "low": 0},
        "max_risk_score": 92, "breach_cost": 250000,
        "top_3_risks": [{"title": "alice → Admin", "plain_english": "x", "severity": "CRITICAL",
                         "score": 92, "impact": "$250,000"}],
        "cc6_controls": [{"id": "CC6.3", "status": "FAIL", "human_count": 1,
                          "workload_count": 0, "impact": "y", "owner": "Security Engineering"}],
        "controls": [{"framework": "SOC2", "control": "CC6.3", "status": "FAIL",
                      "human_count": 1, "workload_count": 0, "impact": "y",
                      "owner": "Security Engineering", "severity": "critical", "count": 1}],
        "controls_total": 1,
        "frameworks": ["SOC2"],
        "frameworks_in_scope": ["SOC2"],
        "top_paths": [path],
        "actions": [{"priority": "P0", "action": "Enforce MFA", "owner": "Security Engineering",
                     "window": "7 days", "decision": "Approve"}],
        "violation_count": 2, "group_count": 1,
        "total_violations": 2, "violation_groups_total": 1,
        "attack_paths": [path], "attack_paths_total": 1,
        "violation_groups": [{
            "violation_type": "SOC2 CC6.3", "framework": "SOC2", "severity": "critical",
            "count": 1, "resources": [{"arn": "arn:aws:iam::1:user/alice", "name": "alice",
                                       "type": "user", "severity": "critical"}],
            "iam_policy_diff": "{}", "terraform_snippet": "resource \"x\" {}",
            "verification_cli": "aws iam get-user --user-name alice",
        }],
        "human_identities": [{"arn": "arn:aws:iam::1:user/alice", "name": "alice", "type": "user",
                              "is_admin": True, "has_mfa": False, "is_dormant": True,
                              "is_overprivileged": True, "risk_score": 88}],
        "human_identities_total": 1,
    }


# ---------------------------------------------------------------------------
# Framework-agnostic posture matrix (no hard-coded control list)
# ---------------------------------------------------------------------------

def test_matrix_handles_non_soc2_frameworks():
    entities = {
        "arn:aws:iam::1:user/alice": {"entity_arn": "arn:aws:iam::1:user/alice", "entity_type": "user"},
        "arn:aws:iam::1:role/AWSServiceRoleForX": {"entity_arn": "arn:aws:iam::1:role/AWSServiceRoleForX", "entity_type": "role"},
    }
    violations = [
        {"violation_type": "[Tier 1] DPDP Sec 8(4)", "compliance_framework": "DPDP",
         "resource_id": "arn:aws:iam::1:user/alice", "severity": "high",
         "actual_state": "Admin without MFA fails reasonable security safeguards."},
        {"violation_type": "[Tier 1] RBI Cyber Security Sec 2.1", "compliance_framework": "RBI",
         "resource_id": "arn:aws:iam::1:role/AWSServiceRoleForX", "severity": "medium"},
    ]
    matrix = compute_control_matrix(violations, entities, ["DPDP", "RBI", "PCIDSS"])
    rows = {(r["framework"], r["control"]): r for r in matrix["rows"]}

    assert rows[("DPDP", "Sec 8(4)")]["status"] == "FAIL"
    assert rows[("DPDP", "Sec 8(4)")]["owner"] == "Data Protection Officer"
    assert rows[("RBI", "Cyber Security Sec 2.1")]["status"] == "PARTIAL"
    assert rows[("PCI-DSS", "No violations recorded")]["status"] == "PASS"
    assert set(matrix["frameworks_in_scope"]) == {"DPDP", "RBI", "PCI-DSS"}


def test_matrix_is_empty_without_scope_or_violations():
    matrix = compute_control_matrix([], {}, [])
    assert matrix["rows"] == []
    assert matrix["total"] == 0


def test_unknown_framework_still_renders():
    violations = [{"violation_type": "Custom Rule X", "compliance_framework": "MY_FRAMEWORK",
                   "resource_id": "arn:custom", "severity": "info"}]
    matrix = compute_control_matrix(violations, {}, ["MY_FRAMEWORK"])
    assert matrix["rows"][0]["framework"] == "MY FRAMEWORK"
    assert matrix["rows"][0]["owner"] == "Compliance Office"


def test_framework_normalisation_aliases():
    assert normalize_framework("pcidss") == "PCI-DSS"
    assert normalize_framework("soc_2_type_ii") == "SOC2"
    assert normalize_framework("") == "UNSPECIFIED"


def test_severity_breakdown_keeps_unknown_severities():
    from collectors.report_utils import severity_breakdown

    counts = severity_breakdown([
        {"risk_severity": "critical"},
        {"risk_severity": "informational"},
    ])
    assert counts["critical"] == 1
    assert counts["other"] == 1


def test_mfa_noise_filtered_for_historical_service_linked_rows():
    entities = {
        "arn:aws:iam::1:role/AWSServiceRoleForECS": {"entity_arn": "arn:aws:iam::1:role/AWSServiceRoleForECS", "entity_type": "role"},
        "arn:aws:iam::1:user/alice": {"entity_arn": "arn:aws:iam::1:user/alice", "entity_type": "user"},
    }
    violations = [
        {"violation_type": "SOC2 CC6.3", "compliance_framework": "SOC2",
         "resource_id": "arn:aws:iam::1:role/AWSServiceRoleForECS", "severity": "critical"},
        {"violation_type": "SOC2 CC6.3", "compliance_framework": "SOC2",
         "resource_id": "arn:aws:iam::1:user/alice", "severity": "critical"},
        {"violation_type": "SOC2 CC6.1", "compliance_framework": "SOC2",
         "resource_id": "arn:aws:iam::1:role/AWSServiceRoleForECS", "severity": "medium"},
    ]
    groups = build_violation_groups(violations, entities)
    cc63 = [g for g in groups if "CC6.3" in g["violation_type"]][0]
    assert cc63["count"] == 1
    assert cc63["resources"][0]["arn"] == "arn:aws:iam::1:user/alice"
    # Non-MFA findings for service-linked resources are still reported (workload risk).
    cc61 = [g for g in groups if "CC6.1" in g["violation_type"]][0]
    assert cc61["count"] == 1


# ---------------------------------------------------------------------------
# Executive typography: no ARN walls, correct resource typing, clean labels
# ---------------------------------------------------------------------------

def test_humanize_text_removes_arns():
    raw = "Entity arn:aws:iam::869935106430:user/Admin_Manager violates least privilege."
    clean = humanize_text(raw)
    assert "arn:aws" not in clean
    assert "Admin_Manager" in clean


def test_resource_type_inferred_from_arn():
    assert resource_type_from_arn("arn:aws:iam::1:policy/Foo") == "Policy"
    assert resource_type_from_arn("arn:aws:iam::1:group/Developers") == "Group"
    assert resource_type_from_arn("arn:aws:iam::aws:policy/AdministratorAccess") == "Policy"
    assert resource_type_from_arn("arn:aws:iam::1:user/bob", "user") == "User"


def test_group_labels_are_cleaned_and_merged():
    violations = [
        {"violation_type": "soc_2_type_ii CC6.1", "compliance_framework": "SOC2", "resource_id": "arn:a", "severity": "critical"},
        {"violation_type": "SOC2 CC6.1", "compliance_framework": "SOC2", "resource_id": "arn:b", "severity": "high"},
    ]
    groups = build_violation_groups(violations)
    assert len(groups) == 1
    assert groups[0]["violation_type"] == "CC6.1"


def test_fallback_is_rule_aware():
    from collectors.authmap_reporter import _fallback_remediation

    mfa = _fallback_remediation("SOC2 CC6.3", "Admin missing MFA")
    assert "MultiFactorAuthPresent" in mfa["iam_policy_diff"]
    over = _fallback_remediation("soc_2_type_ii CC6.1", "violates principle of least privilege")
    assert "DenyPrivilegeEscalationActions" in over["iam_policy_diff"]
    generic = _fallback_remediation("Unmapped framework rule", "")
    assert "No automated policy" in generic["iam_policy_diff"]
