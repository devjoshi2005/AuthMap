import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

FRAMEWORK_FRIENDLY_NAMES = {
    "SOC2": "SOC 2 Type II (Trust Services Criteria CC6.1 - CC6.8)",
    "SOC_2": "SOC 2 Type II (Trust Services Criteria CC6.1 - CC6.8)",
    "DPDP": "Digital Personal Data Protection (DPDP) Act 2023 (Section 8(5))",
    "DPDP_ACT": "Digital Personal Data Protection (DPDP) Act 2023 (Section 8(5))",
    "ISO27001": "ISO/IEC 27001:2022 (Annex A.9 / Control 5.15 Access Rights)",
    "ISO_27001": "ISO/IEC 27001:2022 (Annex A.9 / Control 5.15 Access Rights)",
    "PCI_DSS": "PCI-DSS v4.0 (Requirements 7 & 8 Identity & Access)",
    "PCIDSS": "PCI-DSS v4.0 (Requirements 7 & 8 Identity & Access)",
    "RBI_CSF": "RBI Master Directions on Cybersecurity (Annexure G PAM)",
    "RBI": "RBI Master Directions on Cybersecurity (Annexure G PAM)",
    "GDPR": "General Data Protection Regulation (GDPR Article 32 Security of Processing)",
    "HIPAA": "HIPAA Security Rule (45 CFR § 164.312 Access Control)",
    "IRDAI": "IRDAI Guidelines on Information and Cyber Security",
    "SEBI": "SEBI Cybersecurity and Cyber Resilience Framework",
    "IT_ACT": "Information Technology Act 2000 (Section 43A)",
    "CIS_AWS": "CIS AWS Foundations Benchmark v3.0",
    "CIS_GCP": "CIS GCP Foundations Benchmark v3.0",
}

def build_ground_truth_telemetry(
    scan_context: Optional[Dict[str, Any]] = None,
    graph_data: Optional[Dict[str, Any]] = None,
    entities: Optional[List[Dict[str, Any]]] = None,
    attack_paths: Optional[List[Dict[str, Any]]] = None,
    compliance_violations: Optional[List[Dict[str, Any]]] = None,
    cost_analysis: Optional[Dict[str, Any]] = None,
    user_memories: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Computes exact, deterministic ground-truth inventory & telemetry metrics
    directly from scan data, Supabase records, user wizard inputs, organization memories,
    and Neo4j graph topology.
    """
    nodes = []
    edges = []

    if graph_data:
        elements = graph_data.get("elements", {})
        raw_nodes = elements.get("nodes", [])
        raw_edges = elements.get("edges", [])
        nodes = [n.get("data", n) for n in raw_nodes if isinstance(n, dict)]
        edges = [e.get("data", e) for e in raw_edges if isinstance(e, dict)]

    if not nodes and entities:
        nodes = entities

    total_nodes = len(nodes)
    total_edges = len(edges)

    # 1. Node Types Breakdown
    node_types: Dict[str, int] = {}
    provider_counts: Dict[str, int] = {}
    admin_principals = []
    overprivileged_principals = []
    dormant_principals = []
    mfa_missing_users = []
    highest_risk_nodes = []

    for n in nodes:
        ntype = str(n.get("type", n.get("entity_type", "unknown"))).lower()
        node_types[ntype] = node_types.get(ntype, 0) + 1

        prov = str(n.get("provider", "Unknown")).upper()
        if prov and prov != "UNKNOWN":
            provider_counts[prov] = provider_counts.get(prov, 0) + 1

        name = n.get("label") or n.get("name") or n.get("id") or "unnamed"
        risk = float(n.get("risk_score") or 0)

        if n.get("is_admin"):
            admin_principals.append({"name": name, "type": ntype, "risk": risk})
        if n.get("is_overprivileged"):
            overprivileged_principals.append({"name": name, "type": ntype, "risk": risk})
        if n.get("is_dormant"):
            dormant_principals.append({"name": name, "type": ntype, "risk": risk})
        if ntype == "user" and not n.get("has_mfa", True):
            mfa_missing_users.append(name)

        highest_risk_nodes.append({"name": name, "type": ntype, "risk": risk})

    highest_risk_nodes.sort(key=lambda x: x["risk"], reverse=True)
    top_5_risk_nodes = highest_risk_nodes[:5]

    # 2. Edge / Relationship Types Breakdown
    edge_types: Dict[str, int] = {}
    for e in edges:
        etype = str(e.get("type", e.get("label", "RELATED_TO"))).upper()
        edge_types[etype] = edge_types.get(etype, 0) + 1

    # 3. Attack Paths Metrics
    paths_list = attack_paths or []
    total_attack_paths = len(paths_list)
    paths_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    max_path_risk = 0.0
    top_paths_summary = []

    for p in paths_list:
        sev = str(p.get("risk_severity", "medium")).lower()
        if sev in paths_by_severity:
            paths_by_severity[sev] += 1
        score = float(p.get("hybrid_risk_score", 0))
        if score > max_path_risk:
            max_path_risk = score
        pname = p.get("path_name") or p.get("id") or "Unnamed Path"
        top_paths_summary.append({
            "name": pname,
            "risk_score": score,
            "severity": sev,
            "cost": float(p.get("estimated_cost_impact", 0)),
            "entry": p.get("entry_node") or p.get("start_node", "Unknown Entry"),
            "target": p.get("target_node") or p.get("end_node", "Admin Target"),
        })

    top_paths_summary.sort(key=lambda x: x["risk_score"], reverse=True)
    top_5_paths = top_paths_summary[:5]

    # 4. Compliance Violations Breakdown
    violations_list = compliance_violations or []
    total_violations = len(violations_list)
    violations_by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    violations_by_framework: Dict[str, List[Dict[str, Any]]] = {}

    for v in violations_list:
        sev = str(v.get("severity", "medium")).lower()
        if sev in violations_by_sev:
            violations_by_sev[sev] += 1
        fw_raw = str(v.get("framework") or v.get("compliance_framework") or "General Security").strip()
        fw_normalized = fw_raw.upper().replace("-", "_").replace(" ", "_")
        fw_display = FRAMEWORK_FRIENDLY_NAMES.get(fw_normalized, fw_raw)

        if fw_display not in violations_by_framework:
            violations_by_framework[fw_display] = []
        violations_by_framework[fw_display].append(v)

    # 5. Extract User Scan Wizard Inputs, Memory & Scope
    scan_cfg = {}
    if scan_context:
        scan_cfg = scan_context.get("config") or {}
        if isinstance(scan_cfg, str):
            try:
                import json
                scan_cfg = json.loads(scan_cfg)
            except Exception:
                scan_cfg = {}

    # Extract memories map if available
    mem_map = {}
    if user_memories:
        for m in user_memories:
            k = str(m.get("key", "")).strip().lower()
            if k:
                mem_map[k] = str(m.get("content", "")).strip()

    # Determine Provider
    raw_prov = scan_cfg.get("provider") or (scan_context.get("csp_target") if scan_context else None)
    if not raw_prov and "primary_cloud_target" in mem_map:
        if "GCP" in mem_map["primary_cloud_target"].upper():
            raw_prov = "gcp"
        elif "AWS" in mem_map["primary_cloud_target"].upper():
            raw_prov = "aws"
    
    if raw_prov and str(raw_prov).lower() not in ["none", "null", ""]:
        wizard_provider = str(raw_prov).upper()
    elif "GCP" in str(provider_counts):
        wizard_provider = "GCP"
    else:
        wizard_provider = "AWS"

    # Determine Region
    raw_region = scan_cfg.get("region") or (scan_context.get("region") if scan_context else None)
    if (not raw_region or str(raw_region).lower() in ["none", "null", ""]) and "primary_cloud_region" in mem_map:
        raw_region = mem_map["primary_cloud_region"]

    if not raw_region or str(raw_region).lower() in ["none", "null", ""]:
        if wizard_provider == "GCP":
            wizard_region = "asia-south1 (Mumbai) / Global GCP Multi-Region"
        else:
            wizard_region = "ap-south-1 (Mumbai)"
    else:
        wizard_region = str(raw_region)

    # Determine Cost Region
    raw_cost_region = (
        scan_cfg.get("cost_region")
        or (scan_context.get("cost_region") if scan_context else None)
        or (cost_analysis.get("cost_region") if cost_analysis else None)
    )
    if (not raw_cost_region or str(raw_cost_region).lower() in ["none", "null", ""]) and "economic_parameters" in mem_map:
        if "INDIA" in mem_map["economic_parameters"].upper():
            raw_cost_region = "INDIA"
        elif "US" in mem_map["economic_parameters"].upper():
            raw_cost_region = "UNITED_STATES"
        elif "EU" in mem_map["economic_parameters"].upper():
            raw_cost_region = "EUROPE"

    if not raw_cost_region or str(raw_cost_region).lower() in ["none", "null", ""]:
        wizard_cost_region = "INDIA (DPDP & Ponemon Regional Benchmark)"
    elif raw_cost_region.upper() == "INDIA":
        wizard_cost_region = "INDIA (DPDP & Ponemon Regional Benchmark)"
    elif raw_cost_region.upper() in ["US", "UNITED_STATES"]:
        wizard_cost_region = "UNITED STATES (SEC & NIST Benchmark)"
    elif raw_cost_region.upper() in ["EU", "EUROPE"]:
        wizard_cost_region = "EUROPE (GDPR Statutory Benchmark)"
    else:
        wizard_cost_region = f"{raw_cost_region.upper()} (Regional Scope)"

    # Determine Annual Revenue
    raw_revenue = scan_cfg.get("annual_revenue") or (scan_context.get("annual_revenue") if scan_context else None)
    if not raw_revenue and "economic_parameters" in mem_map:
        import re
        rev_match = re.search(r"\$([0-9,]+(?:\.[0-9]+)?)", mem_map["economic_parameters"])
        if rev_match:
            try:
                raw_revenue = float(rev_match.group(1).replace(",", ""))
            except Exception:
                raw_revenue = None

    if raw_revenue and float(raw_revenue) > 0:
        revenue_str = f"${float(raw_revenue):,.2f} USD"
    else:
        revenue_str = "$10,000,000.00 USD (Configured Baseline ARR)"

    # Determine Scanned Target / Identity
    wizard_role_arn = scan_cfg.get("aws_role_arn") or (scan_context.get("aws_role_arn") if scan_context else None)
    wizard_aws_acc = scan_cfg.get("aws_account_id") or (scan_context.get("aws_account_id") if scan_context else None)
    wizard_gcp_project = scan_cfg.get("gcp_project_id") or (scan_context.get("gcp_project_id") if scan_context else None)
    wizard_gcp_sa = scan_cfg.get("gcp_service_account_email") or (scan_context.get("gcp_service_account_email") if scan_context else None)

    # Check graph nodes or memories for project ID if not in config
    if not wizard_gcp_project and wizard_provider == "GCP":
        for n in nodes:
            nid = str(n.get("id") or "")
            nname = str(n.get("name") or "")
            if "project" in nid or "project" in str(n.get("type", "")).lower():
                wizard_gcp_project = nname or nid
                break
        if not wizard_gcp_project and "primary_cloud_target" in mem_map:
            import re
            m = re.search(r"\[GCP Project:\s*([^\]]+)\]", mem_map["primary_cloud_target"])
            if m:
                wizard_gcp_project = m.group(1).strip()

    identity_parts = []
    if wizard_gcp_project:
        sa_sub = f" (Service Account: `{wizard_gcp_sa}`)" if wizard_gcp_sa else ""
        identity_parts.append(f"GCP Project: `{wizard_gcp_project}`{sa_sub}")
    if wizard_role_arn:
        identity_parts.append(f"IAM Role: `{wizard_role_arn}`")
    if wizard_aws_acc:
        identity_parts.append(f"AWS Account ID: `{wizard_aws_acc}`")

    identity_target_str = ", ".join(identity_parts) if identity_parts else f"{wizard_provider} Organization Root & Scanned Principals"
    raw_acc = scan_cfg.get("account_name") or (scan_context.get("scan_name") if scan_context else None)
    wizard_account_name = str(raw_acc) if raw_acc and str(raw_acc).lower() not in ["none", "null", ""] else "Security Audit Target"
    
    raw_st = scan_cfg.get("scan_type") or (scan_context.get("scan_type") if scan_context else None)
    wizard_scan_type = str(raw_st).title() if raw_st and str(raw_st).lower() not in ["none", "null", ""] else "Full Deep Audit"

    # Determine Compliances
    raw_selected = (
        scan_cfg.get("selected_compliances")
        or (scan_context.get("selected_compliances") if scan_context else None)
        or (scan_context.get("compliance_frameworks") if scan_context else None)
        or []
    )
    if isinstance(raw_selected, str):
        try:
            import json
            raw_selected = json.loads(raw_selected)
        except Exception:
            raw_selected = [s.strip() for s in raw_selected.split(",") if s.strip()]

    if not raw_selected and "active_compliance_goals" in mem_map:
        raw_selected = [s.strip() for s in mem_map["active_compliance_goals"].split(",") if s.strip()]

    selected_compliances_display = []
    if raw_selected and isinstance(raw_selected, list):
        for s in raw_selected:
            s_norm = str(s).upper().replace("-", "_").replace(" ", "_")
            friendly = FRAMEWORK_FRIENDLY_NAMES.get(s_norm, str(s))
            if friendly not in selected_compliances_display:
                selected_compliances_display.append(friendly)
    elif violations_by_framework:
        selected_compliances_display = list(violations_by_framework.keys())
    else:
        selected_compliances_display = [
            FRAMEWORK_FRIENDLY_NAMES["SOC2"],
            FRAMEWORK_FRIENDLY_NAMES["DPDP"],
            FRAMEWORK_FRIENDLY_NAMES["RBI"],
            FRAMEWORK_FRIENDLY_NAMES["PCI_DSS"],
            FRAMEWORK_FRIENDLY_NAMES["GDPR"]
        ]

    # 6. Financial & Breach Cost Metrics
    total_breach_cost = 0.0
    max_regulatory_penalty = 0.0
    avg_record_cost = 165.0

    if cost_analysis:
        total_breach_cost = float(cost_analysis.get("total_estimated_cost", cost_analysis.get("total_estimated_breach_cost", 0)))
        max_regulatory_penalty = float(cost_analysis.get("regulatory_fine_cost", cost_analysis.get("max_regulatory_penalty", 0)))
        avg_record_cost = float(cost_analysis.get("avg_per_record_cost", 165.0))
    elif paths_list:
        total_breach_cost = sum(float(p.get("estimated_cost_impact", 0)) for p in paths_list)

    # 7. Overall Scan Risk Score
    overall_risk = 0.0
    scan_name = "Cloud IAM Security Scan"

    if scan_context:
        overall_risk = float(scan_context.get("overall_risk_score", 0))
        scan_name = scan_context.get("scan_name") or scan_name

    if overall_risk == 0 and max_path_risk > 0:
        overall_risk = round(max_path_risk, 1)

    # Format Human-Readable Ground Truth Markdown
    node_types_str = ", ".join([f"{k.title()}s: {v}" for k, v in sorted(node_types.items())]) if node_types else "None recorded"
    edge_types_str = ", ".join([f"{k}: {v}" for k, v in sorted(edge_types.items())]) if edge_types else "None recorded"
    providers_str = ", ".join([f"{k}: {v}" for k, v in sorted(provider_counts.items())]) if provider_counts else wizard_provider

    top_nodes_text = "\n".join([f"    - **{n['name']}** ({n['type'].upper()}): Risk Score {n['risk']}/100" for n in top_5_risk_nodes]) if top_5_risk_nodes else "    - No high risk nodes"
    top_paths_text = "\n".join([f"    - **{p['name']}**: Risk {p['risk_score']}/100 [{p['severity'].upper()}], Impact: ${p['cost']:,.2f} (Entry: `{p['entry']}` -> Target: `{p['target']}`)" for p in top_5_paths]) if top_5_paths else "    - No attack paths identified"

    compliance_breakdown_lines = []
    for fw in selected_compliances_display:
        matching_violations = violations_by_framework.get(fw, [])
        v_count = len(matching_violations)
        crit_count = sum(1 for v in matching_violations if str(v.get("severity")).lower() == "critical")
        high_count = sum(1 for v in matching_violations if str(v.get("severity")).lower() == "high")

        if v_count > 0:
            status_tag = f"FAIL ({v_count} Violations Detected)"
            compliance_breakdown_lines.append(f"  • **{fw}**: {status_tag}")
            compliance_breakdown_lines.append(f"    - Violation Severity: Critical: {crit_count}, High: {high_count}, Medium/Low: {v_count - crit_count - high_count}")
            compliance_breakdown_lines.append("    - Top Non-Compliant Findings:")
            for mv in matching_violations[:4]:
                rule = mv.get("violation_type") or mv.get("expected_state") or "Non-compliant control"
                res_id = mv.get("resource_id") or "Unknown resource"
                
                # Truncate massive raw JSON policy dumps
                raw_desc = str(mv.get("actual_state") or mv.get("description") or "Discrepancy detected")
                desc = raw_desc if len(raw_desc) < 120 else raw_desc[:120] + "... [TRUNCATED]"
                
                sev = str(mv.get("severity", "high")).upper()
                compliance_breakdown_lines.append(f"      * [{sev}] `{rule}` on Resource: `{res_id}` — Issue: {desc}")
        else:
            status_tag = "PASS (COMPLIANT — 0 Gaps Detected in Scanned Scope)"
            compliance_breakdown_lines.append(f"  • **{fw}**: {status_tag}")

    compliance_breakdown_text = "\n".join(compliance_breakdown_lines) if compliance_breakdown_lines else "  - No specific violations detected."
    selected_compliances_joined = ", ".join(selected_compliances_display)

    markdown_summary = f"""### AUTHORITATIVE LIVE ENVIRONMENT TELEMETRY & AUDIT GROUND-TRUTH:
================================================================================
• SCAN IDENTITY & USER SCOPE (from Scan Wizard):
  - Account / Environment: {wizard_account_name}
  - Target Cloud Provider: {wizard_provider} (Primary Region: {wizard_region})
  - Scanned Identity / Target: {identity_target_str}
  - Audit Depth Mode: {wizard_scan_type}
  - Financial & Benchmark Scope: Cost Region: {wizard_cost_region} | Annual Revenue: {revenue_str}
  - Selected Compliance Frameworks: {selected_compliances_joined}
  - Overall Multi-Cloud Risk Score: {overall_risk}/100

• USER-SELECTED COMPLIANCE GOALS & ACTIVE AUDIT STATUS:
{compliance_breakdown_text}

• GRAPH TOPOLOGY & IAM INVENTORY (Supabase + Neo4j AuraDB):
  - Total Graph Elements / Nodes: {total_nodes}
  - Element Types Breakdown: {node_types_str}
  - Cloud Providers: {providers_str}
  - Total Graph Relationships / Edges: {total_edges}
  - Relationship Types Breakdown: {edge_types_str}

• PRIVILEGED & HIGH-RISK PRINCIPALS:
  - Administrator Principals: {len(admin_principals)}
  - Overprivileged Principals: {len(overprivileged_principals)}
  - Dormant Principals: {len(dormant_principals)}
  - Users Missing MFA: {len(mfa_missing_users)} ({", ".join(mfa_missing_users[:5]) if mfa_missing_users else "None"})
  - Top Highest Risk Entities:
{top_nodes_text}

• ATTACK PATHS & ESCALATION VECTORS:
  - Total Attack Paths Identified: {total_attack_paths}
  - Severity Breakdown: Critical: {paths_by_severity['critical']}, High: {paths_by_severity['high']}, Medium: {paths_by_severity['medium']}, Low: {paths_by_severity['low']}
  - Highest Attack Path Score: {max_path_risk}/100
  - Notable Attack Paths Traversed:
{top_paths_text}

• FINANCIAL EXPOSURE & BREACH ECONOMICS:
  - Total Potential Breach Impact: ${total_breach_cost:,.2f} USD
  - Maximum Statutory / Regulatory Penalty: ${max_regulatory_penalty:,.2f} USD
  - Industry Avg Cost Per Compromised Record: ${avg_record_cost:.2f} USD
================================================================================
CRITICAL INSTRUCTION: When the user asks for last scan details, scan input details, chosen options, or compliance scope, you MUST report all parameters above: (1) Cloud Provider, (2) Scanned Project/Role/Identity, (3) Scanned Region, (4) Cost Region, (5) Annual Revenue, and (6) EVERY Selected Compliance Framework along with its PASS/FAIL status."""

    return {
        "markdown_summary": markdown_summary,
        "metrics": {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "node_types": node_types,
            "edge_types": edge_types,
            "provider_counts": provider_counts,
            "admin_count": len(admin_principals),
            "overprivileged_count": len(overprivileged_principals),
            "dormant_count": len(dormant_principals),
            "mfa_missing_count": len(mfa_missing_users),
            "total_attack_paths": total_attack_paths,
            "paths_by_severity": paths_by_severity,
            "total_violations": total_violations,
            "violations_by_severity": violations_by_sev,
            "violations_by_framework": {k: len(v) for k, v in violations_by_framework.items()},
            "selected_compliances": selected_compliances_display,
            "wizard_inputs": {
                "provider": wizard_provider,
                "region": wizard_region,
                "cost_region": wizard_cost_region,
                "annual_revenue": raw_revenue,
                "annual_revenue_formatted": revenue_str,
                "account_name": wizard_account_name,
                "target_identity": identity_target_str,
            },
            "total_breach_cost": total_breach_cost,
            "max_regulatory_penalty": max_regulatory_penalty,
            "avg_record_cost": avg_record_cost,
            "overall_risk_score": overall_risk,
        }
    }
