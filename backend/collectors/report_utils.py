"""Pure helpers shared by AuthMap report builders and rule evaluators.

Deliberately dependency-free (stdlib only) so it can be unit-tested anywhere.
"""

import re
from typing import Any, Dict, Iterable, List, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

CC6_CONTROLS = ("CC6.1", "CC6.2", "CC6.3", "CC6.6")

CC6_IMPACT = {
    "CC6.1": "Unauthorised access through dormant, over-privileged or untracked identities.",
    "CC6.2": "Uncontrolled provisioning or modification of privileged credentials.",
    "CC6.3": "Excessive permissions or missing MFA on administrator identities.",
    "CC6.6": "Lateral movement from an entry identity to a crown-jewel role.",
}

CC6_OWNER = {
    "CC6.1": "Identity Governance",
    "CC6.2": "IAM Platform Owner",
    "CC6.3": "Security Engineering",
    "CC6.6": "CISO Office",
}

# Fallback accountability owners for frameworks outside SOC 2. These are
# role placeholders, not named individuals, so no ownership is invented.
FRAMEWORK_OWNER = {
    "SOC2": "Security Engineering",
    "DPDP": "Data Protection Officer",
    "GDPR": "Data Protection Officer",
    "RBI": "Compliance Officer",
    "SEBI": "Compliance Officer",
    "IRDAI": "Compliance Officer",
    "PCI-DSS": "Payments Security Lead",
    "HIPAA": "Privacy Officer",
    "ISO 27001": "CISO Office",
    "IT ACT": "Compliance Officer",
    "CERT": "CISO Office",
    "UNSPECIFIED": "Compliance Office",
}

FRAMEWORK_IMPACT = {
    "SOC2": "Trust-services control gap affecting access governance.",
    "DPDP": "Personal-data safeguard gap under the DPDP Act.",
    "GDPR": "Data-protection processing gap under GDPR.",
    "RBI": "Regulatory control gap under RBI cyber-security directions.",
    "SEBI": "Regulatory control gap under SEBI cyber-security framework.",
    "IRDAI": "Regulatory control gap under IRDAI information-security guidelines.",
    "PCI-DSS": "Cardholder-data control gap under PCI-DSS.",
    "HIPAA": "Protected-health-information safeguard gap.",
    "ISO 27001": "Information-security control gap under ISO 27001.",
    "IT ACT": "Reasonable-security-practice gap under the IT Act.",
    "CERT": "National cyber-security guideline gap.",
    "UNSPECIFIED": "Compliance control gap recorded without a framework mapping.",
}

_FRAMEWORK_DISPLAY = {
    "PCIDSS": "PCI-DSS",
    "PCI": "PCI-DSS",
    "ISO27001": "ISO 27001",
    "ITACT": "IT ACT",
    "SOC2TYPEII": "SOC2",
    "SOC2": "SOC2",
}

_FRAMEWORK_PREFIX = re.compile(r"\b(soc\s*2|soc2|type\s*(ii|2)|soc_2_type_ii)\b", re.IGNORECASE)
_TIER_PREFIX = re.compile(r"^\s*\[[^\]]*\]\s*")

_SERVICE_LINKED_TYPES = {
    "service_account",
    "service-linked-role",
    "serviceaccount",
    "service_linked_role",
}

_HUMAN_TYPES = {"user", "role", "group", "iam_user", "iam_role"}


def identity_arn(entity: Dict[str, Any]) -> str:
    return str(entity.get("entity_arn") or entity.get("arn") or entity.get("id") or "")


def identity_type(entity: Dict[str, Any]) -> str:
    return str(entity.get("entity_type") or entity.get("type") or "").strip().lower()


def is_service_linked_identity(entity: Dict[str, Any]) -> bool:
    """True for AWS service-linked roles and AWS-managed policies.

    These are non-human, non-interactive and cannot be remediated by a customer,
    so they must never be counted as MFA/least-privilege violations.
    """
    arn = identity_arn(entity)
    if "AWSServiceRoleFor" in arn:
        return True
    if arn.startswith("arn:aws:iam::aws:policy/"):
        return True
    return identity_type(entity) in _SERVICE_LINKED_TYPES


def is_human_identity(entity: Dict[str, Any]) -> bool:
    """True only for interactive/human principals (users, roles, groups)."""
    if is_service_linked_identity(entity):
        return False
    return identity_type(entity) in _HUMAN_TYPES


_MFA_RULE_HINTS = ("mfa", "multi-factor", "multifactor", "2fa", "cc6.3")


def is_mfa_rule(rule: Any) -> bool:
    text = str(rule or "").lower()
    return any(hint in text for hint in _MFA_RULE_HINTS)


def violation_is_noise(
    violation: Dict[str, Any], entities_by_arn: Optional[Dict[str, Dict[str, Any]]] = None
) -> bool:
    """Drop MFA findings raised against non-human/service-linked principals.

    The scanner fix prevents new ones; this keeps historical scans honest too.
    Non-MFA findings are never dropped here.
    """
    if not is_mfa_rule(violation.get("violation_type")):
        return False
    arn = str(violation.get("resource_id") or "")
    entity = (entities_by_arn or {}).get(arn)
    if entity is not None:
        return not is_human_identity(entity)
    return is_service_linked_identity({"entity_arn": arn})


def severity_rank(severity: Optional[str]) -> int:
    return SEVERITY_ORDER.get(str(severity or "").strip().lower(), 99)


def wrap_long_id(value: Any) -> str:
    """Insert zero-width breaks after ARN separators so long IDs wrap cleanly.

    WeasyPrint honours U+200B for line breaking; this avoids the mid-ARN
    overflow seen in the old report while keeping the text copy-pasteable.
    """
    text = str(value or "")
    if len(text) <= 40:
        return text
    return text.replace("/", "/\u200b").replace(":", ":\u200b").replace("_", "_\u200b")


def short_name(value: Any) -> str:
    """Last meaningful segment of an ARN/URI for executive-facing summaries."""
    text = str(value or "")
    if not text:
        return "Unknown"
    if ":" in text or "/" in text:
        return re.split(r"[:/]", text.rstrip("/"))[-1] or text
    return text


_ARN_PATTERN = re.compile(r"arn:[A-Za-z0-9\-]+:[^\s,;)\]}]+")
_TYPE_BY_SEGMENT = (
    (":user/", "User"),
    (":role/", "Role"),
    (":group/", "Group"),
    (":policy/", "Policy"),
    (":instance-profile/", "Instance Profile"),
    (":access-key/", "Access Key"),
    (":mfa/", "MFA Device"),
)


def resource_type_from_arn(arn: Any, fallback: Any = None) -> str:
    """Derive a readable type from the ARN itself (scanner types can be wrong)."""
    text = str(arn or "")
    for segment, label in _TYPE_BY_SEGMENT:
        if segment in text:
            return label
    fallback_text = str(fallback or "").strip()
    return fallback_text.title() if fallback_text else "Unknown"


def humanize_text(text: Any, limit: int = 220) -> str:
    """Replace raw ARNs with their short names for executive-facing copy."""
    value = _ARN_PATTERN.sub(lambda match: short_name(match.group(0)), str(text or ""))
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def normalize_identity(entity: Dict[str, Any]) -> Dict[str, Any]:
    risk_factors = entity.get("static_risk_factors") or {}
    if not isinstance(risk_factors, dict):
        risk_factors = {}
    arn = identity_arn(entity)
    return {
        "arn": arn,
        "name": entity.get("entity_name") or short_name(arn),
        "type": entity.get("entity_type") or entity.get("type") or "Unknown",
        "is_admin": bool(risk_factors.get("is_admin", entity.get("is_admin", False))),
        "has_mfa": bool(risk_factors.get("has_mfa", entity.get("has_mfa", False))),
        "is_dormant": bool(risk_factors.get("is_dormant", entity.get("is_dormant", False))),
        "is_overprivileged": bool(
            risk_factors.get("is_overprivileged", entity.get("is_overprivileged", False))
        ),
        "risk_score": float(entity.get("static_risk_score") or entity.get("risk_score") or 0),
    }


def path_nodes(path: Dict[str, Any]) -> List[str]:
    nodes = path.get("path_nodes") or {}
    if isinstance(nodes, dict):
        nodes = nodes.get("nodes") or []
    if isinstance(nodes, str):
        return [nodes]
    return [str(n) for n in nodes if n]


def path_chain(path: Dict[str, Any]) -> str:
    nodes = path_nodes(path)
    if not nodes:
        return "Unknown → Unknown"
    return " → ".join(short_name(n) for n in nodes)


def normalize_path(path: Dict[str, Any]) -> Dict[str, Any]:
    nodes = path_nodes(path)
    score = float(path.get("hybrid_risk_score") or 0)
    return {
        "id": path.get("id"),
        "name": path.get("path_name") or path_chain(path),
        "chain": path_chain(path),
        "source": path.get("source_name") or (short_name(nodes[0]) if nodes else "Unknown"),
        "target": path.get("target_name") or (short_name(nodes[-1]) if len(nodes) > 1 else "Unknown"),
        "hops": int(path.get("path_length") or max(len(nodes) - 1, 0)),
        "score": score,
        "severity": str(path.get("risk_severity") or "low").lower(),
        "target_permission": str(path.get("target_permission") or "admin"),
        "cost": float(path.get("estimated_cost_impact") or 0),
        "description": path.get("path_description") or "",
        "nodes": nodes,
    }


def build_violation_groups(
    violations: Iterable[Dict[str, Any]],
    entities_by_arn: Optional[Dict[str, Dict[str, Any]]] = None,
    max_resources: int = 250,
    frameworks_in_scope: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Group identical rule/framework violations into one entry per root cause.

    This is the fix for pages 23-40 of the old PDF repeating the same
    ``soc_2_type_ii CC6.1`` paragraph for every resource.
    """
    entities_by_arn = entities_by_arn or {}
    grouped: Dict[tuple, Dict[str, Any]] = {}
    scoped = {
        normalize_framework(f)
        for f in (frameworks_in_scope or [])
        if str(f or "").strip()
    }

    for violation in violations:
        if violation_is_noise(violation, entities_by_arn):
            continue
        fw = normalize_framework(violation.get("compliance_framework"))
        # Respect the frameworks the user selected in the wizard. Unmapped
        # findings are retained and labelled explicitly rather than hidden.
        if scoped and fw not in scoped and fw != "UNSPECIFIED":
            continue
        raw_rule = str(violation.get("violation_type") or "Unclassified rule")
        rule = clean_control_label(raw_rule, fw)
        key = (rule.strip().lower(), fw)
        entry = grouped.setdefault(
            key,
            {
                "violation_type": rule,
                "framework": fw,
                "severity": str(violation.get("severity") or "high").lower(),
                "resources": [],
                "description": str(violation.get("actual_state") or ""),
            },
        )
        if severity_rank(violation.get("severity")) < severity_rank(entry["severity"]):
            entry["severity"] = str(violation.get("severity")).lower()

        resource_arn = str(violation.get("resource_id") or "Unknown")
        if any(r["arn"] == resource_arn for r in entry["resources"]):
            continue
        if len(entry["resources"]) >= max_resources:
            continue
        entity = entities_by_arn.get(resource_arn) or {}
        entry["resources"].append(
            {
                "arn": resource_arn,
                "name": short_name(resource_arn),
                "type": resource_type_from_arn(resource_arn, violation.get("resource_type") or entity.get("type")),
                "is_human": is_human_identity(entity) if entity else None,
                "severity": str(violation.get("severity") or entry["severity"]).lower(),
            }
        )

    groups = list(grouped.values())
    for group in groups:
        group["count"] = len(group["resources"])
    groups.sort(key=lambda g: (severity_rank(g["severity"]), -g["count"], g["violation_type"]))
    return groups


def normalize_framework(value: Any) -> str:
    """Canonical display name for any stored framework value."""
    raw = str(value or "").strip().upper()
    if not raw:
        return "UNSPECIFIED"
    compact = re.sub(r"[\s_\-]", "", raw)
    if compact in _FRAMEWORK_DISPLAY:
        return _FRAMEWORK_DISPLAY[compact]
    return raw.replace("_", " ")


def infer_framework(value: Any, rule: Any = "") -> str:
    """Normalise a framework; infer SOC 2 for legacy CC6 rows with no mapping."""
    framework = normalize_framework(value)
    if framework == "UNSPECIFIED" and "CC6" in str(rule or "").upper():
        return "SOC2"
    return framework


def clean_control_label(rule: Any, framework: str) -> str:
    """Strip framework/tier noise so one rule yields one stable label."""
    label = _TIER_PREFIX.sub("", str(rule or "")).strip()
    label = _FRAMEWORK_PREFIX.sub("", label).strip(" -:·")
    # Drop a leading framework name, e.g. "DPDP Sec 8(4)" -> "Sec 8(4)".
    candidates = {
        framework,
        framework.replace(" ", ""),
        framework.replace("-", ""),
        framework.replace(" ", "_"),
    }
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate and label.upper().startswith(candidate.upper()):
            label = label[len(candidate):].strip(" -:·")
            break
    label = re.sub(r"\s{2,}", " ", label)
    return label or str(rule or framework)


def compute_control_matrix(
    violations: Iterable[Dict[str, Any]],
    entities_by_arn: Optional[Dict[str, Dict[str, Any]]] = None,
    frameworks_in_scope: Optional[Iterable[str]] = None,
    max_rows: int = 12,
) -> Dict[str, Any]:
    """Build a framework-agnostic posture matrix from whatever is in the scan.

    Works for SOC 2, DPDP, RBI, PCI-DSS, GDPR, HIPAA, ISO 27001, SEBI, IRDAI,
    IT Act, CERT or any unmapped framework/rule combination. No control list is
    hard-coded: rows come from the violations themselves, and frameworks that
    were in scope but produced no violations appear as PASS.
    """
    entities_by_arn = entities_by_arn or {}
    scoped = [normalize_framework(f) for f in (frameworks_in_scope or []) if str(f or "").strip()]
    # de-duplicate, preserve order
    scoped = list(dict.fromkeys(scoped))

    groups: Dict[tuple, Dict[str, Any]] = {}
    scoped_set = set(scoped)
    for violation in violations:
        if violation_is_noise(violation, entities_by_arn):
            continue
        framework = infer_framework(
            violation.get("compliance_framework"), violation.get("violation_type")
        )
        if scoped_set and framework not in scoped_set and framework != "UNSPECIFIED":
            continue
        control = clean_control_label(violation.get("violation_type"), framework)
        key = (framework, control.strip().lower())
        entry = groups.setdefault(
            key,
            {
                "framework": framework,
                "control": control,
                "severity": str(violation.get("severity") or "high").lower(),
                "human": set(),
                "workload": set(),
                "description": str(violation.get("actual_state") or ""),
            },
        )
        if severity_rank(violation.get("severity")) < severity_rank(entry["severity"]):
            entry["severity"] = str(violation.get("severity")).lower()
        arn = str(violation.get("resource_id") or "Unknown")
        entity = entities_by_arn.get(arn)
        if entity and not is_human_identity(entity):
            entry["workload"].add(arn)
        else:
            entry["human"].add(arn)

    rows: List[Dict[str, Any]] = []
    for entry in groups.values():
        human = len(entry["human"])
        workload = len(entry["workload"])
        status = "FAIL" if human else ("PARTIAL" if workload else "PASS")
        impact = entry["description"].strip()
        if not impact:
            impact = FRAMEWORK_IMPACT.get(entry["framework"], FRAMEWORK_IMPACT["UNSPECIFIED"])
        rows.append(
            {
                "framework": entry["framework"],
                "control": entry["control"][:90],
                "status": status,
                "human_count": human,
                "workload_count": workload,
                "impact": humanize_text(impact),
                "owner": FRAMEWORK_OWNER.get(entry["framework"], FRAMEWORK_OWNER["UNSPECIFIED"]),
                "severity": entry["severity"],
                "count": human + workload,
            }
        )

    covered = {row["framework"] for row in rows}
    for framework in scoped:
        if framework in covered:
            continue
        rows.append(
            {
                "framework": framework,
                "control": "No violations recorded",
                "status": "PASS",
                "human_count": 0,
                "workload_count": 0,
                "impact": FRAMEWORK_IMPACT.get(framework, FRAMEWORK_IMPACT["UNSPECIFIED"]),
                "owner": FRAMEWORK_OWNER.get(framework, FRAMEWORK_OWNER["UNSPECIFIED"]),
                "severity": "none",
                "count": 0,
            }
        )

    rows.sort(key=lambda r: (severity_rank(r["severity"]), -r["count"], r["framework"], r["control"]))
    return {
        "rows": rows[:max_rows],
        "total": len(rows),
        "frameworks": sorted({row["framework"] for row in rows}),
        "frameworks_in_scope": scoped,
    }


def compute_cc6_controls(
    violations: Iterable[Dict[str, Any]],
    entities_by_arn: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """SOC 2 CC6 projection of the framework-agnostic control matrix.

    Retained for backwards compatibility; new code should call
    :func:`compute_control_matrix`, which supports every framework.
    """
    matrix = compute_control_matrix(violations, entities_by_arn)
    rows = {
        str(row["control"]).upper(): row
        for row in matrix["rows"]
        if row["framework"] == "SOC2"
    }

    controls: List[Dict[str, Any]] = []
    for control in CC6_CONTROLS:
        row = rows.get(control)
        controls.append(
            {
                "id": control,
                "status": row["status"] if row else "PASS",
                "human_count": row["human_count"] if row else 0,
                "workload_count": row["workload_count"] if row else 0,
                "impact": CC6_IMPACT[control],
                "owner": CC6_OWNER[control],
            }
        )
    return controls


def severity_breakdown(paths: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    for path in paths:
        severity = str(path.get("risk_severity") or "other").strip().lower()
        counts[severity if severity in counts else "other"] += 1
    return counts
