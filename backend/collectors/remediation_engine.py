import os,json,logging
from typing import List, Dict, Any
import textwrap
from io import BytesIO
from jinja2 import Environment, FileSystemLoader, BaseLoader, select_autoescape
from weasyprint import HTML, CSS
from datetime import datetime
from groq import AsyncGroq
from collectors.breach_cost_estimator import ComplianceFramework

logger = logging.getLogger(__name__)

class ComplianceMapper:
    @staticmethod
    def map_node(node: Dict, frameworks: List[str]) -> List[Dict[str, str]]:
        violations = []
        node_id = node.get('id') or node.get('name') or 'Unknown'
        node_type = node.get('type', 'Unknown')
        
        is_dormant = node.get('is_dormant', False)
        has_mfa = node.get('has_mfa', False)
        is_overprivileged = node.get('is_overprivileged', False)
        is_admin = node.get('is_admin', False)
        
        props = node.get('props', {})
        risk_score = props.get('risk_score', 0)
        services = props.get('services', [])
        password_last_used = props.get('password_last_used', 'N/A')
        
        rule_mappings = []
        
        if is_dormant:
            rule_mappings.append({
                ComplianceFramework.SOC2: ("[Tier 1] SOC2 CC6.1", f"Dormant account {node_id} violates logical access security."),
                ComplianceFramework.PCI_DSS: ("[Tier 1] PCI-DSS 8.1.4", f"Inactive user {node_id} must be removed/disabled within 90 days."),
                ComplianceFramework.RBI: ("[Tier 1] RBI Cyber Security Sec 2.1", f"Dormant account {node_id} poses unauthorized access risk."),
                ComplianceFramework.IRDAI: ("[Tier 1] IRDAI InfoSec 3.2", f"Dormant account {node_id} violates access management."),
                ComplianceFramework.SEBI: ("[Tier 1] SEBI Cyber Sec Annexure 1", f"Dormant account {node_id} must be disabled."),
                ComplianceFramework.DPDP: ("[Tier 1] DPDP Sec 8(1)", f"Dormant account {node_id} violates data security safeguards."),
                ComplianceFramework.GDPR: ("[Tier 1] GDPR Art 5(1)(f)", f"Dormant account {node_id} compromises integrity and confidentiality."),
                ComplianceFramework.HIPAA: ("[Tier 1] HIPAA 164.308(a)(4)(i)", f"Inactive account {node_id} violates information access management."),
                ComplianceFramework.IT_ACT: ("[Tier 1] IT Act Sec 43A", f"Dormant account {node_id} fails to maintain reasonable security practices."),
            })

        if is_admin and not has_mfa:
            rule_mappings.append({
                ComplianceFramework.SOC2: ("[Tier 1] SOC2 CC6.3", f"Admin {node_id} missing MFA violates access control standards."),
                ComplianceFramework.PCI_DSS: ("[Tier 1] PCI-DSS 8.3", f"Multi-factor authentication required for admin {node_id}."),
                ComplianceFramework.HIPAA: ("[Tier 1] HIPAA 164.312(d)", f"Person or entity authentication missing MFA for admin {node_id}."),
                ComplianceFramework.GDPR: ("[Tier 1] GDPR Art 32", f"Admin {node_id} lacks MFA, violating security of processing."),
                ComplianceFramework.SEBI: ("[Tier 1] SEBI Cyber Sec Annexure 2", f"Admin {node_id} lacks 2FA."),
                ComplianceFramework.RBI: ("[Tier 1] RBI Cyber Security Sec 2.1", f"Admin {node_id} lacks MFA, violating RBI master direction."),
                ComplianceFramework.IRDAI: ("[Tier 1] IRDAI InfoSec 3.1", f"Admin {node_id} missing strong authentication (MFA)."),
                ComplianceFramework.DPDP: ("[Tier 1] DPDP Sec 8(4)", f"Admin {node_id} without MFA fails reasonable security safeguards."),
                ComplianceFramework.IT_ACT: ("[Tier 1] IT Act Sec 43A", f"Admin {node_id} lacks MFA, risking unauthorized data access."),
            })

        if is_overprivileged:
            rule_mappings.append({
                ComplianceFramework.SOC2: ("[Tier 1] SOC2 CC6.1", f"Entity {node_id} violates principle of least privilege."),
                ComplianceFramework.HIPAA: ("[Tier 1] HIPAA 164.308(a)(4)", f"Entity {node_id} violates information access management."),
                ComplianceFramework.DPDP: ("[Tier 1] DPDP Sec 8(4)", f"Overprivileged entity {node_id} violates reasonable security safeguards."),
                ComplianceFramework.RBI: ("[Tier 1] RBI Cyber Security Sec 2.1", f"Entity {node_id} violates least privilege access rules."),
                ComplianceFramework.PCI_DSS: ("[Tier 1] PCI-DSS 7.1.2", f"Entity {node_id} privileges exceed job requirements."),
                ComplianceFramework.GDPR: ("[Tier 1] GDPR Art 25(2)", f"Entity {node_id} violates data protection by default (least privilege)."),
                ComplianceFramework.SEBI: ("[Tier 1] SEBI Cyber Sec Annexure 1", f"Entity {node_id} has excessive privileges, needing restriction."),
                ComplianceFramework.IRDAI: ("[Tier 1] IRDAI InfoSec 3.2", f"Entity {node_id} has unauthorized excessive rights."),
                ComplianceFramework.IT_ACT: ("[Tier 1] IT Act Sec 43A", f"Overprivileged entity {node_id} violates access limitation requirements."),
            })

        if not is_overprivileged and risk_score >= 70:
            rule_mappings.append({
                ComplianceFramework.SOC2: ("[Tier 2 Heuristic] SOC2 CC6.1", f"Entity {node_id} has a high semantic risk score ({risk_score}/100), suggesting potential overprivilege."),
                ComplianceFramework.GDPR: ("[Tier 2 Heuristic] GDPR Art 32", f"High risk score ({risk_score}) on {node_id} flags potential data exposure risk."),
                ComplianceFramework.PCI_DSS: ("[Tier 2 Heuristic] PCI-DSS 7.1.1", f"High risk score ({risk_score}) on {node_id} requires role-based access review."),
                ComplianceFramework.RBI: ("[Tier 2 Heuristic] RBI Cyber Security Sec 2.1", f"Risk score ({risk_score}) on {node_id} warrants access re-certification."),
                ComplianceFramework.DPDP: ("[Tier 2 Heuristic] DPDP Sec 8(4)", f"Semantic risk ({risk_score}) on {node_id} indicates weak security safeguards."),
                ComplianceFramework.IT_ACT: ("[Tier 2 Heuristic] IT Act Sec 43A", f"High risk score ({risk_score}) on {node_id} suggests inadequate access control."),
            })
            
        if not is_dormant and password_last_used not in ('N/A', 'never', 'no_information', ''):
            from datetime import datetime, timezone
            try:
                last_used_date = datetime.strptime(password_last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                days_inactive = (datetime.now(timezone.utc) - last_used_date.replace(tzinfo=timezone.utc)).days
                if 45 <= days_inactive < 90:
                    rule_mappings.append({
                        ComplianceFramework.PCI_DSS: ("[Tier 2 Heuristic] PCI-DSS 8.1.4", f"Entity {node_id} has been inactive for {days_inactive} days (nearing 90-day dormant limit)."),
                        ComplianceFramework.IRDAI: ("[Tier 2 Heuristic] IRDAI InfoSec 3.2", f"Entity {node_id} inactive for {days_inactive} days, approaching dormant risk."),
                        ComplianceFramework.SOC2: ("[Tier 2 Heuristic] SOC2 CC6.2", f"Entity {node_id} inactive for {days_inactive} days, requires lifecycle review."),
                        ComplianceFramework.SEBI: ("[Tier 2 Heuristic] SEBI Cyber Sec Annexure 1", f"Entity {node_id} inactive for {days_inactive} days, review account status."),
                    })
            except Exception:
                pass

        if isinstance(services, list) and len(services) >= 5:
            rule_mappings.append({
                ComplianceFramework.SOC2: ("[Tier 2 Heuristic] SOC2 CC6.1", f"Entity {node_id} has access to {len(services)} distinct services, increasing blast radius."),
                ComplianceFramework.HIPAA: ("[Tier 2 Heuristic] HIPAA 164.312(a)(1)", f"Entity {node_id} wide service access ({len(services)} services) may violate access controls."),
                ComplianceFramework.SEBI: ("[Tier 2 Heuristic] SEBI Cyber Sec Annexure 1", f"Entity {node_id} broad access ({len(services)} services) requires review."),
                ComplianceFramework.GDPR: ("[Tier 2 Heuristic] GDPR Art 32", f"Entity {node_id} broad access ({len(services)} services) expands data exposure footprint."),
                ComplianceFramework.DPDP: ("[Tier 2 Heuristic] DPDP Sec 8(4)", f"Entity {node_id} broad access ({len(services)} services) increases data breach risk."),
                ComplianceFramework.IT_ACT: ("[Tier 2 Heuristic] IT Act Sec 43A", f"Entity {node_id} access to {len(services)} services indicates lack of granular controls."),
            })

        if not is_admin and not has_mfa and node_type == 'user':
            rule_mappings.append({
                ComplianceFramework.PCI_DSS: ("[Tier 2 Heuristic] PCI-DSS 8.3", f"Non-admin user {node_id} lacks MFA. PCI-DSS increasingly recommends MFA for all access."),
                ComplianceFramework.RBI: ("[Tier 2 Heuristic] RBI Cyber Security Sec 2.1", f"Non-admin user {node_id} lacks MFA. Consider enforcing 2FA globally."),
                ComplianceFramework.SOC2: ("[Tier 2 Heuristic] SOC2 CC6.3", f"Non-admin user {node_id} lacks MFA. Best practices suggest global MFA enforcement."),
                ComplianceFramework.GDPR: ("[Tier 2 Heuristic] GDPR Art 32", f"Non-admin user {node_id} lacks MFA. Consider global MFA to strengthen data protection."),
                ComplianceFramework.IT_ACT: ("[Tier 2 Heuristic] IT Act Sec 43A", f"Non-admin user {node_id} lacks MFA. Global MFA reduces unauthorized access risks."),
            })

        for mapping in rule_mappings:
            for fw, (control, desc) in mapping.items():
                if fw.value in frameworks:
                    violations.append({"entity": node_id, "control": control, "description": desc})

        return violations



class AIRemediationEngine:
    
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        if self.api_key:
            self.client = AsyncGroq(api_key=self.api_key)
        else:
            self.client = None
        self.model = "llama-3.3-70b-versatile"
        
    async def get_remediation(self, violation_context: Dict) -> Dict:
        """Call LLM to get remediation steps."""
        if not self.client:
            # Fallback dummy response if no API key provided
            return {
                "executive_summary": "Manual review required. AI remediation currently not working.",
                "cli_command": "# Ensure you have valid credentials before proceeding\\necho 'Remediation pending API configuration'",
                "terraform_snippet": "# Terraform remediation pending API configuration"
            }
            
        system_prompt = """You are an expert Cloud Security Architect and Compliance Auditor.
The user will provide a compliance violation context containing an attack path and a list of 'applicable_compliance_frameworks'.
Your primary duty is to cross-reference the exact attack path against the provided frameworks and explicitly cite the exact legal/regulatory control clauses (e.g., SOC2 CC6.1, GDPR Art 32, PCI-DSS Req 8.3) that this path violates.
Provide a JSON response with exactly these keys: 
1. 'executive_summary': A 1-2 sentence explanation of the risk that MUST include the exact compliance framework control clauses violated.
2. 'cli_command': The exact AWS/GCP command to fix the issue.
3. 'terraform_snippet': The HCL code required to enforce the fix globally.
Provide ONLY the JSON object, no markdown wrappers, no explanations.
"""
        
        user_prompt = f"Fix this compliance violation: {json.dumps(violation_context)}"
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            logger.error(f"LLM Remediation failed: {e}")
            
            # Static fallback correlation if API fails (rate limits, etc)
            path_name = violation_context.get('path_name', '').lower()
            if 'mfa' in path_name:
                return {
                    "executive_summary": "(Static Fallback) Enforce MFA to comply with SOC2 CC6.3, PCI-DSS 8.3.",
                    "cli_command": "# Fallback CLI\\naws iam enable-mfa-device --user-name <USER> --serial-number <ARN> --authentication-code1 <CODE1> --authentication-code2 <CODE2>",
                    "terraform_snippet": "# Fallback Terraform\\nresource \"aws_iam_policy\" \"enforce_mfa\" {\\n  name = \"EnforceMFA\"\\n  policy = data.aws_iam_policy_document.mfa.json\\n}"
                }
            elif 'admin' in path_name or 'privilege' in path_name:
                return {
                    "executive_summary": "(Static Fallback) Revoke overprivileged access to comply with SOC2 CC6.1, GDPR Art 32.",
                    "cli_command": "# Fallback CLI\\naws iam detach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                    "terraform_snippet": "# Fallback Terraform\\n# Remove AdministratorAccess policy attachment\\n# resource \"aws_iam_user_policy_attachment\" \"admin\" {}"
                }
            elif 'dormant' in path_name or 'inactive' in path_name:
                return {
                    "executive_summary": "(Static Fallback) Deactivate dormant accounts to comply with PCI-DSS 8.1.4, RBI Sec 2.1.",
                    "cli_command": "# Fallback CLI\\naws iam update-access-key --access-key-id <KEY> --status Inactive --user-name <USER>",
                    "terraform_snippet": "# Fallback Terraform\\nresource \"aws_iam_access_key\" \"key\" {\\n  user    = aws_iam_user.user.name\\n  status  = \"Inactive\"\\n}"
                }
            else:
                return {
                    "executive_summary": "(Static Fallback) Manual review required for this attack path to ensure compliance.",
                    "cli_command": "# Review IAM policies and remove unnecessary access",
                    "terraform_snippet": "# Review Terraform definitions for least privilege"
                }

class EnterpriseReportGenerator:
    """Generates professional PDF reports using Jinja2 and Weasyprint."""
    
    def __init__(self):
        self.html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                @page { margin: 1in; size: A4; }
                body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #1f2937; line-height: 1.5; }
                .cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; text-align: center; }
                .cover h1 { font-size: 3rem; color: #111827; margin-bottom: 0.5rem; }
                .cover p { font-size: 1.25rem; color: #4b5563; }
                .page-break { page-break-before: always; }
                h2 { color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; margin-top: 2rem; }
                h3 { color: #374151; margin-top: 1.5rem; }
                .card { border: 1px solid #e5e7eb; border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; background: #f9fafb; }
                .text-red { color: #dc2626; }
                .text-orange { color: #ea580c; }
                .text-green { color: #16a34a; }
                table { width: 100%; border-collapse: collapse; margin-top: 1rem; margin-bottom: 2rem; }
                th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #e5e7eb; }
                th { background-color: #f3f4f6; font-weight: 600; }
                pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 0.375rem; font-size: 0.875rem; white-space: pre-wrap; word-wrap: break-word; }
                .badge { display: inline-block; padding: 0.25rem 0.5rem; font-size: 0.75rem; font-weight: 600; border-radius: 9999px; }
                .badge-critical { background: #fee2e2; color: #991b1b; }
                .badge-high { background: #ffedd5; color: #9a3412; }
            </style>
        </head>
        <body>
            <div class="cover">
                <h1>IAM Graph Analyzer</h1>
                <p>Enterprise Compliance & Security Report</p>
                <br><br>
                <p><strong>Scan ID:</strong> {{ scan_id }}</p>
                <p><strong>Date:</strong> {{ date }}</p>
                <p><strong>Frameworks:</strong> {{ frameworks | join(', ') }}</p>
            </div>
            
            <div class="page-break"></div>
            
            <h2>Executive Summary</h2>
            <div class="card">
                <p><strong>Total Entities Scanned:</strong> {{ stats.total_nodes }}</p>
                <p><strong>Total Attack Paths Detected:</strong> {{ stats.total_paths }}</p>
                <p><strong>Highest Risk Score:</strong> <span class="{% if stats.max_risk > 80 %}text-red{% elif stats.max_risk > 50 %}text-orange{% else %}text-green{% endif %}">{{ stats.max_risk }} / 100</span></p>
                <p><strong>Estimated Breach Cost Exposure:</strong> <span class="text-red">${{ "{:,.2f}".format(stats.breach_cost) }}</span></p>
            </div>

            <h2>Compliance Violations</h2>
            {% if compliance_violations %}
                <table>
                    <thead>
                        <tr>
                            <th>Entity</th>
                            <th>Control</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for v in compliance_violations %}
                        <tr>
                            <td>{{ v.entity }}</td>
                            <td><span class="badge badge-high">{{ v.control }}</span></td>
                            <td>
                                {{ v.description }}
                                {% if v.remediation_json %}
                                    <div style="margin-top: 0.5rem; padding: 0.5rem; background-color: #f3f4f6; border-radius: 0.25rem;">
                                        <strong>AI Remediation:</strong> {{ v.remediation_json.executive_summary }}<br>
                                        <strong style="display: block; margin-top: 0.25rem;">CLI Fix:</strong>
                                        <pre style="margin: 0; padding: 0.5rem; font-size: 0.75rem;"><code>{{ v.remediation_json.cli_command }}</code></pre>
                                        <strong style="display: block; margin-top: 0.25rem;">Terraform Fix:</strong>
                                        <pre style="margin: 0; padding: 0.5rem; font-size: 0.75rem;"><code>{{ v.remediation_json.terraform_snippet }}</code></pre>
                                    </div>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p>No deterministic compliance violations found.</p>
            {% endif %}

            <div class="page-break"></div>
            
            <h2>Critical Attack Paths & Remediation</h2>
            {% if attack_paths %}
                {% for path in attack_paths %}
                <div class="card">
                    <h3>Path: {{ path.name }} (Risk: {{ path.risk_score }})</h3>
                    <p><strong>Impact Cost:</strong> ${{ "{:,.2f}".format(path.cost) }}</p>
                    <p><strong>Nodes Involved:</strong> {{ path.nodes | join(' -> ') }}</p>
                    
                    {% if path.remediation %}
                        <h4 style="margin-top: 1rem;">AI Executive Summary</h4>
                        <p>{{ path.remediation.executive_summary }}</p>
                        
                        <h4>CLI Remediation</h4>
                        <pre><code>{{ path.remediation.cli_command }}</code></pre>
                        
                        <h4>Terraform Enforcement</h4>
                        <pre><code>{{ path.remediation.terraform_snippet }}</code></pre>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p>No critical attack paths found.</p>
            {% endif %}
        </body>
        </html>
        """

    def generate_pdf(self, scan_id: str, report_data: Dict) -> str:
        """Renders HTML and converts to PDF using Weasyprint."""
        env = Environment(loader=BaseLoader())
        template = env.from_string(self.html_template)
        
        html_out = template.render(
            scan_id=scan_id,
            date=report_data.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            frameworks=report_data.get('frameworks', []),
            stats=report_data.get('stats', {}),
            compliance_violations=report_data.get('compliance_violations', []),
            attack_paths=report_data.get('attack_paths', [])
        )
        
        pdf_path = f"/tmp/authmap_report_{scan_id}.pdf"
        HTML(string=html_out).write_pdf(pdf_path)
        return pdf_path
