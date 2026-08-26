import os
import sys
import asyncio
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class IAMIdentity(BaseModel):
    identity_type: str = Field(..., description="User, Role, or ServiceAccount")
    arn: str = Field(..., description="The unique identifier (ARN or Email)")
    trust_policy: str = Field(..., description="The assume role policy document or authentication mechanism")

class PolicyEvaluationResult(BaseModel):
    rule_name: str = Field(..., description="Rego rule name")
    status: str = Field(..., description="COMPLIANT or VIOLATION")
    evaluated_context: str = Field(..., description="Description of the failure and exact remediation")

class PrivilegeEscalationPath(BaseModel):
    source_identity: str = Field(..., description="The entrypoint identity")
    hop: str = Field(..., description="The intermediary resource or role assumed")
    target_admin_role: str = Field(..., description="The destination highly privileged role")
    exploit_vector: str = Field(..., description="The toxic combination allowing lateral movement")
    cli_command: Optional[str] = Field(None, description="CLI remediation step")
    terraform_snippet: Optional[str] = Field(None, description="Terraform remediation block")
    risk_score: int = Field(..., description="The hybrid risk score of the path")

class CC6AuditSummary(BaseModel):
    scope_analyzed: str = Field(..., description="Scope of the IAM environments audited")
    total_identities: int
    blast_radius_summary: str
    audit_period: str
    cc6_1_status: str
    cc6_2_status: str
    cc6_3_status: str
    cc6_6_status: str
    identities: List[IAMIdentity]
    policy_evaluations: List[PolicyEvaluationResult]
    privilege_escalation_paths: List[PrivilegeEscalationPath]

class AuthMapSOC2Reporter:
    """Orchestrates the generation of professional SOC 2 CC6 Readiness PDF Reports."""
    
    def __init__(self):
        # We define a strict, professional SOC2 template without emojis or unnecessary colors
        self.html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SOC 2 CC6 Readiness Assessment Report</title>
            <style>
                @page {
                    size: A4;
                    margin: 20mm;
                    @top-center {
                        content: "CONFIDENTIAL - INTERNAL AUDIT USE ONLY";
                        font-size: 8pt;
                        color: #666666;
                        font-family: "Helvetica", sans-serif;
                    }
                    @bottom-right {
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 8pt;
                        color: #666666;
                        font-family: "Helvetica", sans-serif;
                    }
                }
                body {
                    font-family: "Helvetica", "Arial", sans-serif;
                    color: #333333;
                    line-height: 1.4;
                    font-size: 10pt;
                    margin: 0;
                    padding: 0;
                }
                .header-container {
                    display: flex;
                    align-items: center;
                    border-bottom: 2px solid #000000;
                    padding-bottom: 10px;
                    margin-top: 0px;
                    margin-bottom: 20px;
                }
                .logo {
                    width: 32px;
                    height: 32px;
                    background-color: #1a1a1a;
                    color: white;
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: bold;
                    font-size: 16px;
                    margin-right: 15px;
                }
                .title-container h1 {
                    margin: 0;
                    font-size: 18pt;
                    color: #000000;
                }
                .title-container h2 {
                    margin: 5px 0 0 0;
                    font-size: 12pt;
                    font-weight: normal;
                    color: #555555;
                }
                h3 {
                    border-bottom: 1px solid #cccccc;
                    padding-bottom: 5px;
                    margin-top: 30px;
                    font-size: 14pt;
                    color: #000000;
                    page-break-after: avoid;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 15px;
                    table-layout: fixed;
                }
                th, td {
                    border: 1px solid #dddddd;
                    padding: 8px;
                    vertical-align: top;
                    word-wrap: break-word;
                }
                th {
                    background-color: #f2f2f2;
                    font-weight: bold;
                    text-align: left;
                    font-size: 9pt;
                }
                td {
                    font-size: 9pt;
                }
                .status-pass {
                    color: #006600;
                    font-weight: bold;
                }
                .status-fail {
                    color: #cc0000;
                    font-weight: bold;
                }
                pre {
                    background-color: #f8f9fa;
                    border: 1px solid #e9ecef;
                    padding: 10px;
                    font-family: "Courier New", Courier, monospace;
                    font-size: 8.5pt;
                    white-space: pre-wrap;
                    overflow-x: hidden;
                }
                .code-inline {
                    font-family: "Courier New", Courier, monospace;
                    background-color: #f1f1f1;
                    padding: 2px 4px;
                    font-size: 8.5pt;
                }
                .summary-table {
                    width: 50%;
                }
                .summary-table th {
                    width: 40%;
                }
                .page-break {
                    page-break-before: always;
                }
                .toc-list {
                    list-style-type: none;
                    padding: 0;
                }
                .toc-list li {
                    margin-bottom: 10px;
                }
                .toc-list li a {
                    text-decoration: none;
                    color: #000000;
                    font-size: 11pt;
                }
                .toc-list li a::after {
                    content: leader('.') target-counter(attr(href), page);
                }
                .finding-card {
                    border: 1px solid #cccccc;
                    border-left: 4px solid #d9534f;
                    background-color: #fcfcfc;
                    margin-bottom: 25px;
                    padding: 15px;
                    page-break-inside: avoid;
                }
                .finding-header {
                    border-bottom: 1px solid #eeeeee;
                    padding-bottom: 10px;
                    margin-bottom: 15px;
                    font-size: 10.5pt;
                }
                .finding-body h4 {
                    margin-top: 0;
                    margin-bottom: 5px;
                    color: #333;
                    font-size: 10.5pt;
                }
                .finding-body pre {
                    font-size: 9pt;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    background-color: #f4f4f4;
                    padding: 12px;
                    border-radius: 4px;
                    border: 1px solid #e0e0e0;
                    margin-bottom: 15px;
                }
            </style>
        </head>
        <body>
            <div class="header-container">
                <div class="logo">AM</div>
                <div class="title-container">
                    <h1>AuthMap Enterprise Auditor</h1>
                    <h2>SOC 2 CC6 Readiness Assessment Report</h2>
                </div>
            </div>

            <div id="index-page"></div>
            <h2>Table of Contents</h2>
            <ul class="toc-list">
                <li><a href="#section-1">Section 1: Executive Access Posture & CC6 Alignment</a></li>
                <li><a href="#section-2">Section 2: Critical Privilege Escalation & Toxic Combinations</a></li>
                <li><a href="#section-3">Section 3: Detailed Policy-as-Code Violations</a></li>
                <li><a href="#section-4">Section 4: IAM Identity Trust Profiles</a></li>
            </ul>
            <div class="page-break"></div>

            <h3>Audit Scope & Executive Summary</h3>
            <table class="summary-table">
                <tr>
                    <th>Scope Analyzed</th>
                    <td>{{ summary.scope_analyzed }}</td>
                </tr>
                <tr>
                    <th>Audit Period</th>
                    <td>{{ summary.audit_period }}</td>
                </tr>
                <tr>
                    <th>Total Identities Evaluated</th>
                    <td>{{ summary.total_identities }}</td>
                </tr>
                <tr>
                    <th>Blast Radius Assessment</th>
                    <td>{{ summary.blast_radius_summary }}</td>
                </tr>
            </table>

            <h3 id="section-1">Section 1: Executive Access Posture & CC6 Alignment</h3>
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%">Criteria</th>
                        <th style="width: 15%">Status</th>
                        <th style="width: 60%">Assessment Notes</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>CC6.1 - Logical Access</td>
                        <td class="{% if summary.cc6_1_status == 'PASS' %}status-pass{% else %}status-fail{% endif %}">{{ summary.cc6_1_status }}</td>
                        <td>Evaluate implementation of Role-Based Access Control and authentication measures.</td>
                    </tr>
                    <tr>
                        <td>CC6.2 - User Registration</td>
                        <td class="{% if summary.cc6_2_status == 'PASS' %}status-pass{% else %}status-fail{% endif %}">{{ summary.cc6_2_status }}</td>
                        <td>Evaluate controls around provisioning and modification of privileged credentials.</td>
                    </tr>
                    <tr>
                        <td>CC6.3 - Least Privilege</td>
                        <td class="{% if summary.cc6_3_status == 'PASS' %}status-pass{% else %}status-fail{% endif %}">{{ summary.cc6_3_status }}</td>
                        <td>Evaluate excessive wildcard permissions and revocation mechanisms.</td>
                    </tr>
                    <tr>
                        <td>CC6.6 - Privilege Escalation</td>
                        <td class="{% if summary.cc6_6_status == 'PASS' %}status-pass{% else %}status-fail{% endif %}">{{ summary.cc6_6_status }}</td>
                        <td>Evaluate lateral movement vulnerabilities and toxic combinations.</td>
                    </tr>
                </tbody>
            </table>

            <div class="page-break"></div>
            
            <h3 id="section-2">Section 2: Critical Privilege Escalation & Toxic Combinations (CC6.6)</h3>
            {% if summary.privilege_escalation_paths %}
                <div class="findings-container">
                    {% for path in summary.privilege_escalation_paths %}
                    <div class="finding-card">
                        <div class="finding-header">
                            <p style="margin: 3px 0;"><strong>Source Identity:</strong> <span class="code-inline">{{ path.source_identity }}</span></p>
                            <p style="margin: 3px 0;"><strong>Target Admin Role:</strong> <span class="code-inline">{{ path.target_admin_role }}</span></p>
                            <p style="margin: 3px 0;"><strong>Risk Score:</strong> {{ path.risk_score }} | <strong>Hop:</strong> {{ path.hop }}</p>
                        </div>
                        <div class="finding-body">
                            {% if edition == 'technical' %}
                                <h4>CLI Remediation:</h4>
                                <pre>{{ path.cli_command or "No technical remediation available." }}</pre>
                                <h4>Terraform Remediation:</h4>
                                <pre>{{ path.terraform_snippet or "No technical remediation available." }}</pre>
                            {% else %}
                                <h4>Executive Risk Summary & Advisory:</h4>
                                <p style="margin-top: 5px;">{{ path.exploit_vector }}</p>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            {% else %}
                <p>No critical privilege escalation paths (Risk Score &gt;= 80) were detected.</p>
            {% endif %}

            <h3 id="section-3">Section 3: Detailed Policy-as-Code Violations (CC6.3)</h3>
            {% if summary.policy_evaluations %}
                {% for eval in summary.policy_evaluations %}
                <div style="margin-bottom: 20px; border: 1px solid #dddddd; padding: 15px; background-color: #fafafa;">
                    <p><strong>Rule:</strong> {{ eval.rule_name }} 
                    <span style="float: right;" class="{% if eval.status == 'COMPLIANT' %}status-pass{% else %}status-fail{% endif %}">{{ eval.status }}</span></p>
                    <p><strong>Context & Remediation:</strong></p>
                    <pre>{{ eval.evaluated_context }}</pre>
                </div>
                {% endfor %}
            {% else %}
                <p>No policy violations were detected.</p>
            {% endif %}
            
            <div class="page-break"></div>

            <h3 id="section-4">Section 4: IAM Identity Trust Profiles (CC6.1)</h3>
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%">Type</th>
                        <th style="width: 45%">ARN / Identity</th>
                        <th style="width: 40%">Trust Policy</th>
                    </tr>
                </thead>
                <tbody>
                    {% for identity in summary.identities %}
                    <tr>
                        <td>{{ identity.identity_type }}</td>
                        <td><span class="code-inline">{{ identity.arn }}</span></td>
                        <td><pre style="margin:0; padding:5px; font-size:7.5pt;">{{ identity.trust_policy }}</pre></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

        </body>
        </html>
        """

    def generate_pdf(self, summary_data: dict, output_path: str, edition: str = "enterprise") -> str:
        """Validates data through Pydantic, renders Jinja2, and generates WeasyPrint PDF."""
        # 1. Pydantic Strict Validation
        validated_summary = CC6AuditSummary(**summary_data)
        
        # 2. Jinja2 Render
        from jinja2 import Environment, BaseLoader
        env = Environment(loader=BaseLoader(), autoescape=True)
        template = env.from_string(self.html_template)
        html_out = template.render(summary=validated_summary, edition=edition)
        
        # 3. WeasyPrint Generate
        from weasyprint import HTML
        HTML(string=html_out).write_pdf(output_path)
        return output_path

async def generate_dynamic_soc2_report(scan_id: str, edition: str = "enterprise") -> str:
    """Generates realistic IAM scan data representing a SOC 2 audit dynamically from Supabase."""
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from main import get_orchestrator
    from groq import AsyncGroq
    import json
    import tempfile
    
    orchestrator = get_orchestrator()
    groq_api_key = os.getenv("GROQ_ALTERNATE_KEY")
    if not groq_api_key:
        print("GROQ_ALTERNATE_KEY not found in environment!")
        return None
        
    groq_client = AsyncGroq(api_key=groq_api_key, max_retries=1, timeout=45.0)
    
    # Get scan
    scan_record = orchestrator.supabase.table("iam_scans").select("*").eq("id", scan_id).execute().data
    if not scan_record:
        print(f"No scan found in database for id: {scan_id}")
        return None
        
    scan = scan_record[0]
    
    paths_res = orchestrator.supabase.table("attack_paths").select("*").eq("scan_id", scan_id).execute()
    paths = paths_res.data or []
    
    violations_res = orchestrator.supabase.table("compliance_violations").select("*").eq("scan_id", scan_id).execute()
    violations = violations_res.data or []
    
    dynamic_identities = []
    seen_nodes = set()
    for p in paths:
        nodes = p.get('path_nodes', {})
        node_list = nodes.get('nodes', []) if isinstance(nodes, dict) else (nodes if isinstance(nodes, list) else [])
        for node in node_list:
            if node not in seen_nodes:
                seen_nodes.add(node)
                dynamic_identities.append({
                    "identity_type": "CloudResource",
                    "arn": str(node),
                    "trust_policy": "Managed via IAM Bindings."
                })
    
    if not dynamic_identities:
        dynamic_identities.append({
            "identity_type": "Scope",
            "arn": f"Target: {scan.get('csp_target', 'Unknown')}",
            "trust_policy": "N/A"
        })

    dynamic_policy_evaluations = []
    for v in violations:
        dynamic_policy_evaluations.append({
            "rule_name": v.get("violation_type", "Unknown Rule"),
            "status": "VIOLATION",
            "evaluated_context": f"Resource: {v.get('resource_id', 'Unknown')}\n\nDetails:\n{v.get('actual_state', 'No details provided.')}"
        })

    dynamic_escalation_paths = []
    for i, p in enumerate(paths):
        nodes = p.get('path_nodes', {})
        node_list = nodes.get('nodes', []) if isinstance(nodes, dict) else (nodes if isinstance(nodes, list) else [])
        
        risk_score = p.get('hybrid_risk_score', 0)
        
        exec_sum = "No summary generated."
        cli = ""
        tf = ""
        
        if risk_score >= 80:
            try:
                from collectors.transit_encryption import TransitObfuscator
                obfuscator = TransitObfuscator(prefix="SEC_")
                
                # Extract ARNs or sensitive resource IDs and PII (like UUIDs/Emails) to mask
                terms_to_mask = TransitObfuscator.extract_sensitive_data(node_list)
                
                # Since node_list is a list, we can just mask its string representation
                node_list_str = obfuscator.mask_terms(json.dumps(node_list), terms_to_mask)
                
                # 1. Enterprise Advice via gpt-oss-20b
                prompt_ent = f"Analyze this specific IAM path and provide a unique 2-sentence executive summary of the risk. You MUST mention the specific resource names to make it dynamic. Return raw JSON: {{\"executive_summary\": \"<string>\"}}. Path: {node_list_str}"
                try:
                    res_ent = await groq_client.chat.completions.create(
                        model="openai/gpt-oss-20b",
                        messages=[{"role": "user", "content": prompt_ent}],
                        response_format={"type": "json_object"},
                        temperature=0.4
                    )
                except Exception as e:
                    if "json_validate_failed" in str(e):
                        res_ent = await groq_client.chat.completions.create(
                            model="openai/gpt-oss-20b",
                            messages=[{"role": "user", "content": prompt_ent}],
                            temperature=0.4
                        )
                    else:
                        raise e
                
                # 2. Technical Code via gpt-oss-120b
                prompt_tech = f"Analyze this specific IAM path and provide exact remediation code tailored to these exact ARN names. Return raw JSON: {{\"cli_command\": \"<string>\", \"terraform_snippet\": \"<string>\"}}. Path: {node_list_str}"
                try:
                    res_tech = await groq_client.chat.completions.create(
                        model="openai/gpt-oss-120b",
                        messages=[{"role": "user", "content": prompt_tech}],
                        response_format={"type": "json_object"},
                        temperature=0.3
                    )
                except Exception as e:
                    if "json_validate_failed" in str(e):
                        res_tech = await groq_client.chat.completions.create(
                            model="openai/gpt-oss-120b",
                            messages=[{"role": "user", "content": prompt_tech}],
                            temperature=0.3
                        )
                    else:
                        raise e
                
                import re
                import json
                
                # Parse Enterprise
                match_ent = re.search(r'\{.*\}', res_ent.choices[0].message.content, re.DOTALL)
                if match_ent:
                    ent_json = obfuscator.unmask_text(match_ent.group(0))
                    exec_sum = json.loads(ent_json).get("executive_summary", "")
                    
                # Parse Technical
                match_tech = re.search(r'\{.*\}', res_tech.choices[0].message.content, re.DOTALL)
                if match_tech:
                    tech_json = obfuscator.unmask_text(match_tech.group(0))
                    data = json.loads(tech_json)
                    cli = data.get("cli_command", "")
                    tf = data.get("terraform_snippet", "")
                    
            except Exception as e:
                print(f"Failed to generate dynamic LLM remediation for path: {e}")
        if risk_score >= 80:
            dynamic_escalation_paths.append({
                "source_identity": node_list[0] if len(node_list) > 0 else "Unknown Entry",
                "hop": f"Privilege Escalation Vector",
                "target_admin_role": node_list[-1] if len(node_list) > 1 else "Unknown Target",
                "exploit_vector": exec_sum,
                "cli_command": cli,
                "terraform_snippet": tf,
                "risk_score": risk_score
            })

        breach_cost = sum([p.get('estimated_cost_impact', 0) for p in paths])
        
    dynamic_summary = {
        "scope_analyzed": f"{str(scan.get('csp_target', '')).upper()} (Scan ID: {scan_id})",
        "total_identities": scan.get("total_entities", len(dynamic_identities)),
        "blast_radius_summary": f"Total Attack Paths: {len(paths)} | Max Risk: {max([p.get('hybrid_risk_score', 0) for p in paths] + [0])} | Est. Breach Cost: ${breach_cost:,.2f}",
        "audit_period": str(scan.get("created_at", datetime.now().strftime("%B %Y"))),
        "cc6_1_status": "FAIL" if violations else "PASS",
        "cc6_2_status": "FAIL" if paths else "PASS",
        "cc6_3_status": "FAIL" if violations else "PASS",
        "cc6_6_status": "FAIL" if paths else "PASS",
        "identities": dynamic_identities[:10],
        "policy_evaluations": dynamic_policy_evaluations,
        "privilege_escalation_paths": dynamic_escalation_paths
    }

    reporter = AuthMapSOC2Reporter()
    tmp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    output_path = tmp_pdf.name
    
    reporter.generate_pdf(dynamic_summary, output_path, edition=edition)
    return output_path

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    
    async def main():
        orchestrator = get_orchestrator()
        scan_record = orchestrator.supabase.table("iam_scans").select("*").order("started_at", desc=True).limit(1).execute().data
        if not scan_record:
            return
        test_scan_id = scan_record[0]["id"]
        out_ent = await generate_dynamic_soc2_report(test_scan_id, edition="enterprise")
        out_tech = await generate_dynamic_soc2_report(test_scan_id, edition="technical")
        
        if out_ent and out_tech:
            print(f"Dynamic SOC 2 Enterprise report generated at: {out_ent}")
            print(f"Dynamic SOC 2 Technical report generated at: {out_tech}")
            
    asyncio.run(main())
