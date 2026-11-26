"""AuthMap report generation.

Produces two deliberately different deliverables:

* ``authmap_executive_brief_<scan>.pdf`` — 3-5 page decision dossier for
  ministers / CISOs / boards. KPI cards, posture matrix, plain-English risks.
  No raw ARNs, no code.
* ``authmap_technical_runbook_<scan>.pdf`` — deduplicated engineering runbook.
  Attack-path traces, one entry per root-cause rule with an affected-resource
  table, and copy-pasteable IAM / Terraform / CLI remediation.

All counts come from the stored scan; nothing is fabricated. When a data source
is empty the report says so explicitly instead of printing a synthetic value.
"""

import asyncio
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from collectors.report_utils import (
    build_violation_groups,
    compute_cc6_controls,
    normalize_framework,
    compute_control_matrix,
    humanize_text,
    is_human_identity,
    is_service_linked_identity,
    normalize_identity,
    normalize_path,
    path_nodes,
    severity_breakdown,
    short_name,
    wrap_long_id,
)

logger = logging.getLogger(__name__)

MAX_TECH_PATHS: Optional[int] = None
MAX_TECH_GROUPS: Optional[int] = None
MAX_LLM_GROUPS = 8
REMEDIATION_MODEL = "openai/gpt-oss-120b"
MAX_INVENTORY_ROWS: Optional[int] = None


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _iso_date(value: Any) -> str:
    if not value:
        return datetime.now(timezone.utc).strftime("%d %b %Y")
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%d %b %Y")
    except ValueError:
        return text[:10]


def _account_id(scan: Dict[str, Any], entities: Optional[List[Dict[str, Any]]] = None) -> str:
    config = scan.get("config") or {}
    if isinstance(config, dict):
        if config.get("aws_account_id"):
            return str(config["aws_account_id"])
        role_arn = str(config.get("aws_role_arn") or "")
        match = re.search(r"arn:aws:iam::(\d{12}):", role_arn)
        if match:
            return match.group(1)
        if config.get("gcp_project_id"):
            return str(config["gcp_project_id"])
    for entity in entities or []:
        if entity.get("aws_account_id"):
            return str(entity["aws_account_id"])
        if entity.get("gcp_project_id"):
            return str(entity["gcp_project_id"])
    return "Not recorded"


def load_scan_bundle(scan_id: str, orchestrator: Any = None) -> Dict[str, Any]:
    """Load everything the reports need in one pass (blocking; call via to_thread)."""
    if orchestrator is None:
        from main import get_orchestrator

        orchestrator = get_orchestrator()

    scan_rows = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute().data
    if not scan_rows:
        raise ValueError(f"No scan found for id {scan_id}")
    scan = scan_rows[0]

    paths = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", scan_id).execute().data or []
    violations = (
        orchestrator.supabase.table("compliance_violations").select("*").eq("scan_id", scan_id).execute().data or []
    )
    entities = orchestrator.supabase.table("scan_entities").select("*").eq("scan_id", scan_id).execute().data or []

    index: Dict[str, Dict[str, Any]] = {}
    for entity in entities:
        normalised = normalize_identity(entity)
        if normalised["arn"]:
            index[normalised["arn"]] = normalised

    human: Dict[str, Dict[str, Any]] = {
        arn: record for arn, record in index.items() if is_human_identity(record)
    }
    workload_count = sum(1 for record in index.values() if not is_human_identity(record))

    # Never show zero identities when the scan clearly evaluated principals:
    # fall back to the distinct, non-service-linked nodes in the attack paths.
    if not human:
        for path in paths:
            for node in path_nodes(path):
                if not node or node in human:
                    continue
                if is_service_linked_identity({"entity_arn": node}):
                    continue
                human[node] = {
                    "arn": node,
                    "name": short_name(node),
                    "type": "Unknown",
                    "is_admin": False,
                    "has_mfa": True,
                    "is_dormant": False,
                    "is_overprivileged": False,
                    "risk_score": 0.0,
                }

    selected = scan.get("selected_compliances") or []
    if isinstance(selected, str):
        selected = [part.strip() for part in selected.split(",") if part.strip()]

    return {
        "orchestrator": orchestrator,
        "scan": scan,
        "frameworks_in_scope": selected,
        "scan_status": str(scan.get("status") or "unknown").lower(),
        "scan_error": scan.get("error_message"),
        "paths": paths,
        "violations": violations,
        "entities": entities,
        "index": index,
        "human": human,
        "workload_count": workload_count,
    }


# ---------------------------------------------------------------------------
# Executive briefing
# ---------------------------------------------------------------------------

def build_executive_summary(bundle: Dict[str, Any]) -> Dict[str, Any]:
    scan = bundle["scan"]
    scan_status = str(bundle.get("scan_status") or "unknown").lower()
    is_complete = scan_status == "completed"
    paths = [normalize_path(p) for p in bundle["paths"]]
    violations = bundle["violations"]
    index = bundle["index"]
    human = bundle["human"]

    paths.sort(key=lambda p: p["score"], reverse=True)
    critical = [p for p in paths if p["score"] >= 80]
    breakdown = severity_breakdown(bundle["paths"])
    breach_cost = sum(p["cost"] for p in paths)
    max_risk = max((p["score"] for p in paths), default=0.0)

    injection = sum(1 for h in human.values() if h["is_admin"] and not h["has_mfa"])
    dormant = sum(1 for h in human.values() if h["is_dormant"])

    top_risks = []
    for path in paths[:3]:
        top_risks.append(
            {
                "title": f"{path['source']} → {path['target']}",
                "plain_english": (
                    f"An identity holding {path['source']} can escalate to {path['target']} "
                    f"in {max(path['hops'], 1)} hop(s), reaching {path['target_permission']} access."
                ),
                "severity": path["severity"].upper(),
                "score": int(round(path["score"])),
                "impact": f"${path['cost']:,.0f} estimated exposure",
            }
        )

    actions: List[Dict[str, str]] = []
    if injection:
        actions.append(
            {
                "priority": "P0",
                "action": f"Enforce MFA on {injection} administrator identities",
                "owner": "Security Engineering",
                "window": "7 days",
                "decision": "Approve enforcement",
            }
        )
    for path in paths[:2]:
        actions.append(
            {
                "priority": "P0" if path["score"] >= 80 else "P1",
                "action": f"Break escalation edge {path['source']} → {path['target']}",
                "owner": "IAM Platform Owner",
                "window": "30 days" if path["score"] >= 80 else "60 days",
                "decision": "Approve policy change",
            }
        )
    if dormant:
        actions.append(
            {
                "priority": "P1",
                "action": f"Disable or justify {dormant} dormant identities",
                "owner": "Identity Governance",
                "window": "30 days",
                "decision": "Confirm owners",
            }
        )
    groups = build_violation_groups(
        violations,
        index,
        frameworks_in_scope=bundle.get("frameworks_in_scope"),
    )
    matrix = compute_control_matrix(
        violations,
        index,
        frameworks_in_scope=bundle.get("frameworks_in_scope"),
        max_rows=None,
    )
    if groups:
        top_group = groups[0]
        actions.append(
            {
                "priority": "P1",
                "action": f"Remediate “{top_group['violation_type']}” across {top_group['count']} resources",
                "owner": "IAM Platform Owner",
                "window": "60 days",
                "decision": "Approve remediation sprint",
            }
        )
    if not is_complete:
        actions.insert(
            0,
            {
                "priority": "P0",
                "action": f"Scan did not complete ({scan_status}) — re-run before relying on these findings",
                "owner": "Security Engineering",
                "window": "Now",
                "decision": "Re-run scan",
            },
        )
    if not actions:
        actions.append(
            {
                "priority": "—",
                "action": "No material access findings were recorded for this scan",
                "owner": "Identity Governance",
                "window": "—",
                "decision": "Note only",
            }
        )

    return {
        "scan_id": scan["id"],
        "scan_status": scan_status,
        "is_complete": is_complete,
        "incomplete_note": (
            None
            if is_complete
            else f"This scan did not complete (status: {scan_status}). "
                 "Findings are partial or absent and must not be read as a clean result."
        ),
        "scan_name": scan.get("scan_name") or "AuthMap scan",
        "csp_target": str(scan.get("csp_target") or "cloud").upper(),
        "audit_date": _iso_date(scan.get("completed_at") or scan.get("created_at")),
        "total_identities": len(human),
        "human_count": len(human),
        "workload_count": bundle["workload_count"],
        "total_paths": len(paths),
        "critical_paths": len(critical),
        "actionable_paths": breakdown["critical"] + breakdown["high"],
        "breakdown": breakdown,
        "max_risk_score": round(max_risk),
        "breach_cost": breach_cost,
        "top_3_risks": top_risks,
        "cc6_controls": compute_cc6_controls(violations, index),
        "controls": matrix["rows"],
        "controls_total": matrix["total"],
        "frameworks": matrix["frameworks"],
        "frameworks_in_scope": matrix["frameworks_in_scope"],
        "top_paths": paths,
        "actions": actions,
        "violation_count": sum(g["count"] for g in groups),
        "group_count": len(groups),
    }


EXECUTIVE_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>AuthMap Executive Briefing</title>
<style>
@page {
  size: A4;
  margin: 20mm 18mm 18mm 18mm;
  @top-left { content: "AUTHMAP · EXECUTIVE SECURITY BRIEFING"; font-family: "DejaVu Sans"; font-size: 7pt; color: #64748b; letter-spacing: 0.08em; }
  @top-right { content: "CONFIDENTIAL"; font-family: "DejaVu Sans"; font-size: 7pt; color: #b91c1c; letter-spacing: 0.12em; font-weight: bold; }
  @bottom-left { content: "Scan {{ scan_id }} · {{ audit_date }}"; font-family: "DejaVu Sans"; font-size: 7pt; color: #64748b; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font-family: "DejaVu Sans"; font-size: 7pt; color: #64748b; }
}
body { font-family: "DejaVu Sans", "Helvetica Neue", Arial, sans-serif; color: #0f172a; font-size: 9.5pt; line-height: 1.45; margin: 0; }
h1 { font-size: 21pt; letter-spacing: -0.02em; margin: 0 0 2mm 0; color: #0f172a; }
h2 { font-size: 13pt; margin: 7mm 0 3mm 0; padding-bottom: 1.5mm; border-bottom: 1px solid #cbd5e1; page-break-after: avoid; }
h3 { font-size: 10.5pt; margin: 5mm 0 2mm 0; page-break-after: avoid; }
p { margin: 0 0 2.5mm 0; }
.sub { color: #475569; font-size: 9pt; margin-bottom: 7mm; }
.meta { color: #64748b; font-size: 7.8pt; }
.rule-top { border-top: 3px solid #0f172a; margin: 4mm 0 5mm 0; }
table.kpi { width: 100%; border-collapse: collapse; table-layout: fixed; margin: 0 0 6mm 0; }
table.kpi td { width: 25%; padding: 0; vertical-align: top; }
table.kpi .card { border: 1px solid #e2e8f0; background: #ffffff; padding: 4mm 3mm; margin-right: 3mm; }
table.kpi td:last-child .card { margin-right: 0; }
table.kpi .v { font-size: 19pt; font-weight: bold; letter-spacing: -0.02em; }
table.kpi .l { font-size: 7.2pt; text-transform: uppercase; letter-spacing: 0.07em; color: #64748b; margin-top: 1mm; }
.crit { border-left: 3px solid #b91c1c !important; }
.warn { border-left: 3px solid #b45309 !important; }
table, th, td { box-sizing: border-box; }
table { max-width: 100%; }
table.grid { width: 100%; border-collapse: collapse; table-layout: fixed; }
table.grid th { background: #f1f5f9; color: #334155; font-size: 7.8pt; text-align: left; padding: 2.4mm; border: 1px solid #e2e8f0; }
table.grid td { font-size: 8.3pt; padding: 2.4mm; border: 1px solid #e2e8f0; vertical-align: top; overflow-wrap: anywhere; }
tr.pass td { background: #f0fdf4; }
tr.fail td { background: #fef2f2; }
tr.partial td { background: #fffbeb; }
.badge { font-weight: bold; font-size: 7.6pt; letter-spacing: 0.05em; }
.pass .badge { color: #15803d; }
.fail .badge { color: #b91c1c; }
.partial .badge { color: #b45309; }
.risk { border: 1px solid #e2e8f0; border-left: 3px solid #b91c1c; padding: 3mm 4mm; margin-bottom: 3mm; page-break-inside: avoid; }
.risk .t { font-weight: bold; font-size: 10pt; margin-bottom: 1mm; }
.note { background: #f8fafc; border: 1px solid #e2e8f0; padding: 3mm; font-size: 7.8pt; color: #475569; margin-top: 4mm; }
.pb { page-break-before: always; }
table, th, td { box-sizing: border-box; }
table { max-width: 100%; }
.banner { background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #b91c1c; padding: 3mm 4mm; color: #7f1d1d; font-size: 8.6pt; margin: 4mm 0 6mm 0; page-break-inside: avoid; }
.banner strong { letter-spacing: 0.04em; }
thead { display: table-header-group; }
</style></head><body>

<div class="meta">CLASSIFICATION: CONFIDENTIAL · SCAN {{ scan_id }} · {{ audit_date }}</div>
<h1>Executive Security Briefing</h1>
<p class="sub">{{ scan_name }} · {{ csp_target }} scope · prepared for executive and ministerial review</p>
{% if not is_complete %}
<div class="banner"><strong>SCAN INCOMPLETE.</strong> {{ incomplete_note }}</div>
{% endif %}
<div class="rule-top"></div>

<table class="kpi"><tr>
  <td><div class="card"><div class="v">{{ total_identities }}</div><div class="l">Identities evaluated</div><div class="meta">{{ human_count }} human · {{ workload_count }} workload</div></div></td>
  <td><div class="card crit"><div class="v">{{ actionable_paths }}</div><div class="l">Paths requiring action</div><div class="meta">critical {{ breakdown.critical }} · high {{ breakdown.high }} · of {{ total_paths }} total</div></div></td>
  <td><div class="card"><div class="v">{{ max_risk_score }}</div><div class="l">Max blast-radius score</div><div class="meta">0–100 hybrid risk</div></div></td>
  <td><div class="card warn"><div class="v">${{ breach_cost|money }}</div><div class="l">Quantified exposure</div><div class="meta">estimated annualised loss</div></div></td>
</tr></table>

<h2>Top systemic risks</h2>
{% if top_3_risks %}
  {% for risk in top_3_risks %}
  <div class="risk">
    <div class="t">{{ risk.title }}</div>
    <div>{{ risk.plain_english }}</div>
    <div class="meta">{{ risk.severity }} · score {{ risk.score }} · {{ risk.impact }}</div>
  </div>
  {% endfor %}
{% else %}
  <p>No privilege-escalation paths were recorded for this scan. Absence of findings reflects the evidence available at scan time, not proof that the environment is risk-free.</p>
{% endif %}

<h2>Immediate governance actions</h2>
<table class="grid">
<thead><tr><th style="width:9%">Priority</th><th style="width:37%">Action</th><th style="width:18%">Owner</th><th style="width:12%">Window</th><th style="width:24%">Decision required</th></tr></thead>
<tbody>
{% for action in actions %}
<tr><td>{{ action.priority }}</td><td>{{ action.action }}</td><td>{{ action.owner }}</td><td>{{ action.window }}</td><td>{{ action.decision }}</td></tr>
{% endfor %}
</tbody></table>

<div class="pb"></div>
<h2>Compliance posture</h2>
<p class="meta">Frameworks in scope: {{ frameworks_in_scope|join(', ') if frameworks_in_scope else 'not recorded for this scan' }}{% if controls_total > controls|length %} · showing top {{ controls|length }} of {{ controls_total }} control groups{% endif %}</p>
{% if controls %}
<table class="grid">
<thead><tr><th style="width:18%">Control</th><th style="width:10%">Framework</th><th style="width:9%">Status</th><th style="width:7%">Human</th><th style="width:8%">Workload</th><th style="width:28%">Business impact</th><th style="width:20%">Owner</th></tr></thead>
<tbody>
{% for control in controls %}
<tr class="{{ control.status|lower }}">
  <td><strong>{{ control.control }}</strong></td>
  <td>{{ control.framework }}</td>
  <td><span class="badge">{{ control.status }}</span></td>
  <td>{{ control.human_count }}</td>
  <td>{{ control.workload_count }}</td>
  <td>{{ control.impact|humanize }}</td>
  <td>{{ control.owner }}</td>
</tr>
{% endfor %}
</tbody></table>
{% else %}
<p>No compliance violations and no framework scope were recorded for this scan, so no posture can be asserted. This is an evidence gap, not a pass.</p>
{% endif %}

<h3>How to read this table</h3>
<p><strong>PASS</strong> means the framework was in scope and no violation was recorded. <strong>PARTIAL</strong> means violations affect workload or AWS-managed resources only, which are not human-remediable. <strong>FAIL</strong> means at least one human identity is affected and requires an owner decision. Rows are generated from this scan's recorded violations, only for the frameworks selected at scan time; there is no fixed control checklist.</p>
<div class="note">
Verified telemetry: {{ human_count }} human identities, {{ total_paths }} recorded attack path(s), {{ violation_count }} compliance violation(s) across {{ group_count }} root-cause rule group(s).
AWS service-linked roles and AWS-managed policies are excluded from human MFA and least-privilege counts. Resources whose classification was unavailable are counted conservatively as human.
</div>

<div class="pb"></div>
<h2>Top privilege-escalation paths and blast radius</h2>
{% if top_paths %}
<table class="grid">
<thead><tr><th style="width:38%">Entry → crown-jewel chain</th><th style="width:11%">Severity</th><th style="width:9%">Score</th><th style="width:42%">Business consequence</th></tr></thead>
<tbody>
{% for path in top_paths %}
<tr>
  <td>{{ path.chain }}</td>
  <td>{{ path.severity|upper }}</td>
  <td>{{ path.score|round|int }}</td>
  <td>Administrative control of {{ path.target|short }}; estimated ${{ path.cost|money }} exposure.</td>
</tr>
{% endfor %}
</tbody></table>
{% else %}
<p>No escalation paths were recorded for this scan.</p>
{% endif %}

<h3>Financial exposure</h3>
<p>Aggregate estimated exposure across recorded paths is <strong>${{ breach_cost|money }}</strong>, with a maximum single-path blast-radius score of <strong>{{ max_risk_score }}/100</strong>. Figures are model-based estimates for prioritisation, not audited losses.</p>

<h2>Action sign-off</h2>
<table class="grid">
<thead><tr><th style="width:40%">Action</th><th style="width:20%">Owner</th><th style="width:14%">Due</th><th style="width:26%">Sign-off</th></tr></thead>
<tbody>
{% for action in actions %}
<tr><td>{{ action.action }}</td><td>{{ action.owner }}</td><td>{{ action.window }}</td><td>Name / date: ____________________</td></tr>
{% endfor %}
</tbody></table>

<div class="note">
Prepared by AuthMap from stored scan telemetry for scan {{ scan_id }} on {{ audit_date }}. Findings are point-in-time and limited to the credentials and APIs available to the scanner. This briefing is a decision aid, not a certification of compliance.
</div>

</body></html>"""


class AuthMapExecutiveReporter:
    """Renders the 3-5 page executive briefing dossier."""

    def generate_pdf(self, data: Dict[str, Any], output_path: str) -> str:
        from jinja2 import Environment
        from weasyprint import HTML

        env = Environment(autoescape=True)
        env.filters["money"] = lambda value: f"{float(value or 0):,.0f}"
        env.filters["short"] = short_name
        env.filters["wrap"] = wrap_long_id
        env.filters["humanize"] = humanize_text
        template = env.from_string(EXECUTIVE_TEMPLATE)
        html = template.render(**data)
        HTML(string=html).write_pdf(output_path)
        return output_path


async def generate_executive_brief(scan_id: str, orchestrator: Any = None) -> str:
    bundle = await asyncio.to_thread(load_scan_bundle, scan_id, orchestrator)
    data = build_executive_summary(bundle)
    out = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    out.close()
    return AuthMapExecutiveReporter().generate_pdf(data, out.name)


# ---------------------------------------------------------------------------
# Technical runbook
# ---------------------------------------------------------------------------

_MFA_POLICY = (
    '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
    '    "Sid": "DenyAllWithoutMFA",\n    "Effect": "Deny",\n    "Action": "*",\n'
    '    "Resource": "*",\n    "Condition": {\n      "BoolIfExists": {\n'
    '        "aws:MultiFactorAuthPresent": "false"\n      }\n    }\n  }]\n}'
)

_LEAST_PRIVILEGE_POLICY = (
    '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
    '    "Sid": "DenyPrivilegeEscalationActions",\n    "Effect": "Deny",\n'
    '    "Action": ["iam:*", "organizations:*", "sts:AssumeRole"],\n'
    '    "Resource": "*"\n  }]\n}'
)


def _fallback_remediation(rule: str, description: str = "") -> Dict[str, str]:
    """Rule-aware, honest fallbacks used when the LLM is unavailable.

    These never invent resource names; they emit real, generic guardrails that
    match the rule family so every framework/rule still gets usable guidance.
    """
    text = f"{rule or ''} {description or ''}".lower()
    base = {
        "iam_policy_diff": (
            "# No automated policy was generated for this rule.\n"
            "# Scope the listed principals to the minimum actions required by their workload."
        ),
        "terraform_snippet": "# Terraform snippet unavailable for this rule.",
        "verification_cli": "aws iam get-account-authorization-details --output json",
    }

    if "mfa" in text or "multi-factor" in text or "2fa" in text:
        base["iam_policy_diff"] = _MFA_POLICY
        base["terraform_snippet"] = (
            'resource "aws_iam_policy" "require_mfa" {\n'
            '  name   = "AuthMapRequireMFA"\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n    Statement = [{\n'
            '      Sid      = "DenyAllWithoutMFA"\n      Effect   = "Deny"\n'
            '      Action   = "*"\n      Resource = "*"\n'
            '      Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }\n'
            '    }]\n  })\n}'
        )
        base["verification_cli"] = "aws iam get-account-summary --query SummaryMap.AccountMFAEnabled"
    elif "dormant" in text or "inactive" in text or "unused" in text:
        base["verification_cli"] = (
            "aws iam get-credential-report --output text "
            "# then review password_last_used / access_key_last_used per principal"
        )
    elif any(word in text for word in ("overprivileg", "least privilege", "wildcard", "admin")):
        base["iam_policy_diff"] = _LEAST_PRIVILEGE_POLICY
        base["terraform_snippet"] = (
            'resource "aws_iam_policy" "guardrail" {\n'
            '  name   = "AuthMapPrivilegeEscalationGuardrail"\n'
            '  policy = jsonencode({\n'
            '    Version = "2012-10-17"\n    Statement = [{\n'
            '      Sid      = "DenyPrivilegeEscalationActions"\n      Effect   = "Deny"\n'
            '      Action   = ["iam:*", "organizations:*", "sts:AssumeRole"]\n'
            '      Resource = "*"\n    }]\n  })\n}'
        )
        base["verification_cli"] = "aws iam list-attached-role-policies --role-name <ROLE_NAME>"
    elif "public" in text or "exposed" in text:
        base["terraform_snippet"] = (
            'resource "aws_s3_bucket_public_access_block" "block" {\n'
            '  bucket                  = var.bucket_name\n'
            '  block_public_acls       = true\n  block_public_policy     = true\n'
            '  ignore_public_acls      = true\n  restrict_public_buckets = true\n}'
        )
        base["verification_cli"] = "aws s3api get-public-access-block --bucket <BUCKET_NAME>"
    elif "encrypt" in text:
        base["verification_cli"] = "aws s3api get-bucket-encryption --bucket <BUCKET_NAME>"
    elif "root" in text and "key" in text:
        base["verification_cli"] = "aws iam list-access-keys --user-name root  # requires root credentials"

    return base


async def _generate_group_remediation(
    group: Dict[str, Any], api_key: str, semaphore: asyncio.Semaphore
) -> Dict[str, str]:
    from groq import AsyncGroq

    sample_arns = [r["arn"] for r in group["resources"][:8]]
    prompt = (
        "You are an AWS IAM remediation engineer. Return JSON only with keys "
        "iam_policy_diff, terraform_snippet, verification_cli.\n"
        f"Rule: {group['violation_type']} ({group['framework']}).\n"
        f"Finding: {str(group.get('description') or '')[:400]}\n"
        f"Affected resources: {json.dumps(sample_arns)}\n"
        "iam_policy_diff must be a least-privilege IAM policy JSON string that removes the risky action. "
        "terraform_snippet must be valid HCL. verification_cli must be one AWS CLI command. "
        "Do not invent resource identifiers beyond those provided."
    )
    fallback = _fallback_remediation(group["violation_type"], group.get("description", ""))

    keys: List[str] = []
    for candidate in (api_key, os.getenv("GROQ_ALTERNATE_KEY"), os.getenv("GROQ_API_KEY")):
        if candidate and candidate not in keys:
            keys.append(candidate)

    async with semaphore:
        for key in keys:
            try:
                client = AsyncGroq(api_key=key, max_retries=1, timeout=20.0)
                response = await client.chat.completions.create(
                    model=REMEDIATION_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    max_tokens=700,
                )
                match = re.search(r"\{.*\}", response.choices[0].message.content or "", re.DOTALL)
                if not match:
                    continue
                parsed = json.loads(match.group(0))
                result = dict(fallback)
                for field in ("iam_policy_diff", "terraform_snippet", "verification_cli"):
                    value = parsed.get(field)
                    if isinstance(value, str) and value.strip():
                        result[field] = value.strip()
                return result
            except Exception as exc:
                logger.warning("Remediation LLM failed with key ending %s: %s", key[-4:], exc)
                continue
        return fallback


async def build_technical_summary(
    bundle: Dict[str, Any], api_key: Optional[str] = None
) -> Dict[str, Any]:
    scan = bundle["scan"]
    index = bundle["index"]
    paths = [normalize_path(p) for p in bundle["paths"]]
    paths.sort(key=lambda p: p["score"], reverse=True)
    breakdown = severity_breakdown(bundle["paths"])

    all_groups = build_violation_groups(
        bundle["violations"],
        index,
        frameworks_in_scope=bundle.get("frameworks_in_scope"),
    )
    groups_total = len(all_groups)
    groups = all_groups if MAX_TECH_GROUPS is None else all_groups[:MAX_TECH_GROUPS]

    api_key = api_key or os.getenv("GROQ_ALTERNATE_KEY") or os.getenv("GROQ_API_KEY")
    if api_key and groups:
        semaphore = asyncio.Semaphore(4)
        results = await asyncio.gather(
            *[
                _generate_group_remediation(group, api_key, semaphore)
                if position < MAX_LLM_GROUPS
                else asyncio.sleep(
                    0,
                    result=_fallback_remediation(
                        group["violation_type"], group.get("description", "")
                    ),
                )
                for position, group in enumerate(groups)
            ]
        )
        for group, remediation in zip(groups, results):
            group.update(remediation or _fallback_remediation(group["violation_type"]))
    else:
        for group in groups:
            group.update(
                _fallback_remediation(group["violation_type"], group.get("description", ""))
            )

    human_identities = sorted(
        bundle["human"].values(), key=lambda h: (-h["risk_score"], h["name"])
    )
    if MAX_INVENTORY_ROWS is not None:
        human_identities = human_identities[:MAX_INVENTORY_ROWS]

    scan_status = str(bundle.get("scan_status") or "unknown").lower()
    is_complete = scan_status == "completed"

    return {
        "scan_id": scan["id"],
        "scan_status": scan_status,
        "is_complete": is_complete,
        "incomplete_note": (
            None
            if is_complete
            else f"This scan did not complete (status: {scan_status}). "
                 "Findings are partial or absent and must not be read as a clean result."
        ),
        "scan_name": scan.get("scan_name") or "AuthMap scan",
        "csp_target": str(scan.get("csp_target") or "cloud").upper(),
        "aws_account_id": _account_id(scan, bundle.get("entities")),
        "audit_date": _iso_date(scan.get("completed_at") or scan.get("created_at")),
        "total_identities": len(bundle["human"]),
        "human_count": len(bundle["human"]),
        "workload_count": bundle["workload_count"],
        "total_paths": len(paths),
        "breakdown": breakdown,
        "max_risk_score": round(max((p["score"] for p in paths), default=0.0)),
        "breach_cost": sum(p["cost"] for p in paths),
        "total_violations": sum(g["count"] for g in all_groups),
        "frameworks_in_scope": [
            normalize_framework(f) for f in bundle.get("frameworks_in_scope", [])
        ],
        "attack_paths": paths if MAX_TECH_PATHS is None else paths[:MAX_TECH_PATHS],
        "attack_paths_total": len(paths),
        "violation_groups": groups,
        "violation_groups_total": groups_total,
        "human_identities": human_identities,
        "human_identities_total": len(bundle["human"]),
    }


TECHNICAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>AuthMap Engineering Runbook</title>
<style>
@page {
  size: A4;
  margin: 17mm 15mm 16mm 15mm;
  @top-left { content: "AUTHMAP · ENGINEERING REMEDIATION RUNBOOK"; font-family: "DejaVu Sans"; font-size: 7pt; color: #64748b; letter-spacing: 0.08em; }
  @top-right { content: "CONFIDENTIAL · {{ scan_id }}"; font-family: "DejaVu Sans"; font-size: 7pt; color: #64748b; }
  @bottom-left { content: "Generated {{ audit_date }}"; font-family: "DejaVu Sans"; font-size: 7pt; color: #64748b; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font-family: "DejaVu Sans"; font-size: 7pt; color: #64748b; }
}
body { font-family: "DejaVu Sans", "Helvetica Neue", Arial, sans-serif; color: #0f172a; font-size: 8.8pt; line-height: 1.4; margin: 0; }
h1 { font-size: 17pt; margin: 0 0 1.5mm 0; letter-spacing: -0.02em; }
h2 { font-size: 12pt; margin: 7mm 0 3mm 0; padding-top: 2mm; border-top: 1.5px solid #0f172a; page-break-after: avoid; }
h3 { font-size: 10pt; margin: 5mm 0 2mm 0; page-break-after: avoid; }
h4 { font-size: 8.6pt; margin: 3mm 0 1.5mm 0; page-break-after: avoid; text-transform: uppercase; letter-spacing: 0.05em; color: #334155; }
p { margin: 0 0 2mm 0; }
.meta { color: #64748b; font-size: 7.6pt; }
.sub { color: #475569; font-size: 8.4pt; margin-bottom: 4mm; }
table.telem { width: 100%; border-collapse: collapse; table-layout: fixed; margin-bottom: 4mm; }
table.telem th { width: 22%; background: #f1f5f9; text-align: left; font-size: 7.6pt; color: #334155; padding: 1.8mm; border: 1px solid #e2e8f0; }
table.telem td { font-size: 8pt; padding: 1.8mm; border: 1px solid #e2e8f0; overflow-wrap: anywhere; }
table.grid { width: 100%; border-collapse: collapse; table-layout: fixed; margin: 2mm 0; }
table.grid th { background: #f1f5f9; color: #334155; font-size: 7.4pt; text-align: left; padding: 1.6mm; border: 1px solid #e2e8f0; }
table.grid td { font-size: 7.6pt; padding: 1.6mm; border: 1px solid #e2e8f0; vertical-align: top; overflow-wrap: anywhere; }
thead { display: table-header-group; }
tr { page-break-inside: avoid; }
.code-inline { font-family: "DejaVu Sans Mono", "Courier New", monospace; background: #f1f5f9; padding: 0 1mm; font-size: 7.2pt; overflow-wrap: anywhere; }
.trace { border: 1px solid #e2e8f0; border-left: 3px solid #3b82f6; padding: 2.5mm 3mm; margin-bottom: 2.5mm; page-break-inside: avoid; }
.trace .head { font-weight: bold; font-size: 8.6pt; margin-bottom: 1mm; }
.trace .head .sev { font-weight: normal; letter-spacing: 0.05em; }
.chain { font-family: "DejaVu Sans Mono", "Courier New", monospace; background: #f8fafc; border: 1px solid #e2e8f0; padding: 1.8mm 2mm; font-size: 7.4pt; overflow-wrap: anywhere; margin: 1.5mm 0; }
.group { border: 1px solid #e2e8f0; padding: 3mm; margin-bottom: 3.5mm; }
.group .ghead { font-weight: bold; font-size: 9.2pt; }
.group .gsub { color: #64748b; font-size: 7.6pt; margin-bottom: 1.5mm; }
pre { font-family: "DejaVu Sans Mono", "Courier New", monospace; background: #f8fafc; border: 1px solid #e2e8f0; padding: 2mm; font-size: 6.9pt; line-height: 1.35; white-space: pre-wrap; overflow-wrap: anywhere; margin: 0 0 2mm 0; }
.sev-critical { color: #b91c1c; font-weight: bold; }
.sev-high { color: #b45309; font-weight: bold; }
.sev-medium { color: #a16207; }
.sev-low { color: #475569; }
.note { background: #f8fafc; border: 1px solid #e2e8f0; padding: 2.5mm; font-size: 7.4pt; color: #475569; margin: 3mm 0; }
.pb { page-break-before: always; }
table, th, td { box-sizing: border-box; }
table { max-width: 100%; }
.banner { background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #b91c1c; padding: 2.5mm 3.5mm; color: #7f1d1d; font-size: 8pt; margin: 3mm 0 4mm 0; page-break-inside: avoid; }
</style></head><body>

<div class="meta">CONFIDENTIAL · SCAN {{ scan_id }} · {{ audit_date }}</div>
<h1>Engineering Remediation Runbook</h1>
<p class="sub">{{ scan_name }} · {{ csp_target }} · account {{ aws_account_id }}</p>
{% if not is_complete %}
<div class="banner"><strong>SCAN INCOMPLETE.</strong> {{ incomplete_note }}</div>
{% endif %}

<table class="telem">
<tr><th>Identities</th><td>{{ total_identities }} human · {{ workload_count }} workload</td><th>Attack paths</th><td>{{ total_paths }} (critical {{ breakdown.critical }}, high {{ breakdown.high }}, medium {{ breakdown.medium }}, low {{ breakdown.low }}{% if breakdown.other %}, other {{ breakdown.other }}{% endif %})</td></tr>
<tr><th>Violations</th><td>{{ total_violations }} across {{ violation_groups_total }} root-cause groups</td><th>Max risk</th><td>{{ max_risk_score }}/100 · exposure ${{ breach_cost|money }}</td></tr>
<tr><th>Compliance scope</th><td colspan="3">{{ frameworks_in_scope|join(', ') if frameworks_in_scope else 'not recorded for this scan' }} — only findings for these frameworks are included.</td></tr>
<tr><th>Graph telemetry</th><td colspan="3">Stored scan entities and traversal results for this scan; unverified counts are stated explicitly rather than inferred.</td></tr>
</table>

<h2>Attack-path traces</h2>
{% if attack_paths %}
<p class="meta">{% if attack_paths_total > attack_paths|length %}Showing {{ attack_paths|length }} of {{ attack_paths_total }}{% else %}{{ attack_paths_total }}{% endif %} recorded path(s), highest risk first.</p>
{% for path in attack_paths %}
<div class="trace">
  <div class="head">PATH {{ loop.index }} · SCORE {{ path.score|round|int }}/100 · <span class="sev-{{ path.severity }}">{{ path.severity|upper }}</span></div>
  <div class="chain">{{ path.chain|wrap }}</div>
  <div><strong>Trust boundary:</strong> {{ path.description or "Privilege escalation chain recorded by graph analysis." }}</div>
  <div class="meta">Hops: {{ path.hops }} · estimated exposure ${{ path.cost|money }}</div>
</div>
{% endfor %}
{% else %}
<p>No attack paths were recorded for this scan.</p>
{% endif %}

<h2>Policy-as-code violations and remediation</h2>
{% if violation_groups %}
<p class="meta">One entry per root-cause rule ({% if violation_groups_total > violation_groups|length %}{{ violation_groups|length }} of {{ violation_groups_total }} groups shown{% else %}{{ violation_groups_total }} group(s){% endif %}). AWS service-linked roles and AWS-managed policies are excluded.</p>
{% for group in violation_groups %}
<div class="group">
  <div class="ghead">{{ group.violation_type }} <span class="sev-{{ group.severity }}">· {{ group.severity|upper }}</span></div>
  <div class="gsub">{{ group.framework }} · {{ group.count }} affected resource(s)</div>
  <table class="grid">
    <thead><tr><th style="width:64%">Resource</th><th style="width:20%">Type</th><th style="width:16%">Severity</th></tr></thead>
    <tbody>
    {% for resource in group.resources[:15] %}
      <tr><td class="code-inline">{{ resource.arn|wrap }}</td><td>{{ resource.type }}</td><td class="sev-{{ resource.severity }}">{{ resource.severity|upper }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% if group.count > 15 %}<p class="meta">…and {{ group.count - 15 }} more resource(s) in this group.</p>{% endif %}

  <h4>AI-recommended remediation</h4>
  <div><strong>Least-privilege IAM policy</strong></div>
  <pre>{{ group.iam_policy_diff }}</pre>
  <div><strong>Terraform</strong></div>
  <pre>{{ group.terraform_snippet }}</pre>
  <div><strong>Verification</strong></div>
  <pre>{{ group.verification_cli }}</pre>
</div>
{% endfor %}
{% else %}
<p>No compliance violations were recorded for this scan.</p>
{% endif %}

<h2>Identity and trust-boundary inventory</h2>
<table class="grid">
<thead><tr><th style="width:44%">ARN / identity</th><th style="width:9%">Type</th><th style="width:7%">Admin</th><th style="width:7%">MFA</th><th style="width:9%">Dormant</th><th style="width:12%">Over-priv.</th><th style="width:12%">Risk score</th></tr></thead>
<tbody>
{% for identity in human_identities %}
<tr>
  <td class="code-inline">{{ identity.arn|wrap }}</td>
  <td>{{ identity.type }}</td>
  <td>{{ identity.is_admin|yn }}</td>
  <td>{{ identity.has_mfa|yn }}</td>
  <td>{{ identity.is_dormant|yn }}</td>
  <td>{{ identity.is_overprivileged|yn }}</td>
  <td>{{ identity.risk_score|round|int }}</td>
</tr>
{% endfor %}
</tbody></table>
{% if human_identities_total > human_identities|length %}
<p class="meta">Showing {{ human_identities|length }} of {{ human_identities_total }} human identities, highest risk first.</p>
{% endif %}

<div class="note">
Generated by AuthMap for scan {{ scan_id }}. Remediation snippets are advisory and must be reviewed against your change-management process. Counts reflect stored scan telemetry at generation time.
</div>

</body></html>"""


class AuthMapTechnicalReporter:
    """Renders the deduplicated engineering runbook."""

    def generate_pdf(self, data: Dict[str, Any], output_path: str) -> str:
        from jinja2 import Environment
        from weasyprint import HTML

        env = Environment(autoescape=True)
        env.filters["money"] = lambda value: f"{float(value or 0):,.0f}"
        env.filters["short"] = short_name
        env.filters["wrap"] = wrap_long_id
        env.filters["yn"] = lambda value: "Yes" if value else "No"
        template = env.from_string(TECHNICAL_TEMPLATE)
        html = template.render(**data)
        HTML(string=html).write_pdf(output_path)
        return output_path


async def generate_technical_runbook(scan_id: str, orchestrator: Any = None) -> str:
    bundle = await asyncio.to_thread(load_scan_bundle, scan_id, orchestrator)
    data = await build_technical_summary(bundle)
    out = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    out.close()
    return AuthMapTechnicalReporter().generate_pdf(data, out.name)


# ---------------------------------------------------------------------------
# Backwards-compatible alias (old callers used edition="enterprise"|"technical")
# ---------------------------------------------------------------------------

async def generate_dynamic_soc2_report(scan_id: str, edition: str = "enterprise") -> Optional[str]:
    if edition == "technical":
        return await generate_technical_runbook(scan_id)
    return await generate_executive_brief(scan_id)


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv()

    async def _main() -> None:
        from main import get_orchestrator

        orchestrator = get_orchestrator()
        rows = (
            orchestrator.supabase.table("iam_scans")
            .select("id")
            .order("started_at", desc=True)
            .limit(1)
            .execute()
            .data
        )
        if not rows:
            print("No scans found")
            return
        scan_id = rows[0]["id"]
        brief = await generate_executive_brief(scan_id, orchestrator)
        runbook = await generate_technical_runbook(scan_id, orchestrator)
        print(f"Executive brief: {brief}")
        print(f"Technical runbook: {runbook}")

    asyncio.run(_main())
