import os,json,logging
from typing import List, Dict, Any
import textwrap
from io import BytesIO
from jinja2 import Environment, FileSystemLoader, BaseLoader, select_autoescape
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

        for mapping in rule_mappings:
            for fw_key, (control, desc) in mapping.items():
                fw_clean = fw_key.value.lower().replace('-', '').replace('_', '').replace(' ', '')
                for f in frameworks:
                    f_clean = f.lower().replace('-', '').replace('_', '').replace(' ', '')
                    if fw_clean in f_clean or f_clean in fw_clean:
                        violations.append({"entity": node_id, "control": control, "description": desc})
                        break

        return violations

    @staticmethod
    async def map_nodes_batch_llm(nodes: List[Dict], frameworks: List[str]) -> List[Dict[str, str]]:
        if not frameworks or not nodes:
            return []
            
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            return []
            
        client = AsyncGroq(api_key=api_key, max_retries=1, timeout=45.0)
        
        # Sort nodes by risk score descending and cap at 50 to prevent massive payloads and rate limits
        sorted_nodes = sorted(nodes, key=lambda x: x.get('risk_score', 0), reverse=True)[:50]
        
        # Prepare a compressed payload
        compressed_nodes = []
        for n in sorted_nodes:
            compressed_nodes.append({
                "id": n.get("id"),
                "type": n.get("type"),
                "is_admin": n.get("is_admin", False),
                "is_overprivileged": n.get("is_overprivileged", False),
                "has_mfa": n.get("has_mfa", False),
                "is_dormant": n.get("is_dormant", False),
                "risk_score": n.get("risk_score", 0)
            })
            
        system_prompt = f"""You are an expert Cloud Compliance & Security Auditor. 
You will receive a list of cloud IAM identities/resources (nodes) and a list of target compliance frameworks.
Evaluate ONLY the nodes that exhibit complex or compound security risks (e.g. high risk_score, overprivileged, missing MFA on sensitive accounts) against the provided frameworks.
Your goal is to find complex compliance violations that simple static rules might miss.

Frameworks to evaluate against: {', '.join(frameworks)}

Respond ONLY with a JSON object containing a single key "violations" which maps to an array of violation objects. Each violation object MUST have:
- "entity": The exact ID of the node.
- "framework": The specific compliance framework this violates (MUST exactly match one from the list above, e.g. "SOC2", "GDPR").
- "control": The exact framework control clause violated (e.g., "SOC2 CC6.1", "GDPR Art 32").
- "description": A clear, crisp, and professional description of the violation. Ensure any referenced node types use exact Neo4j naming conventions (e.g. 'User', 'Role', 'S3Bucket', 'RDS', 'EC2').
- "severity": Must be exactly "critical", "high", or "medium".

If no complex violations are found, return {{"violations": []}}.
Output ONLY valid JSON. No markdown wrappers."""

        max_retries = 2
        for attempt in range(max_retries):
            current_model = "openai/gpt-oss-20b" if attempt == 0 else "openai/gpt-oss-120b"
            try:
                response = await client.chat.completions.create(
                    model=current_model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": json.dumps(compressed_nodes)}
                    ],
                    temperature=0.1
                )
                
                content = response.choices[0].message.content or ""
                content = content.strip()
                if not content:
                    raise ValueError(f"Model {current_model} returned empty content.")
                
                # Robust JSON extraction
                import re
                json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', content)
                if json_match:
                    content = json_match.group(1).strip()
                else:
                    start = content.find('{')
                    end = content.rfind('}')
                    if start != -1 and end != -1:
                        content = content[start:end+1]
                    elif content.strip().startswith('['):
                        start = content.find('[')
                        end = content.rfind(']')
                        if start != -1 and end != -1:
                            content = content[start:end+1]
                    
                # Handle potential {"violations": [...]} wrapper if the model adds one
                parsed = json.loads(content)
                if isinstance(parsed, dict) and "violations" in parsed:
                    return parsed["violations"]
                elif isinstance(parsed, list):
                    return parsed
                else:
                    return []
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.warning(f"LLM Compliance Mapping failed after {max_retries} attempts: {e}")
                    return []


class AIRemediationEngine:
    
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        if self.api_key:
            self.client = AsyncGroq(api_key=self.api_key, max_retries=1, timeout=45.0)
        else:
            self.client = None
        self.model = "openai/gpt-oss-20b"
        
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
        
        from collectors.transit_encryption import TransitObfuscator
        obfuscator = TransitObfuscator(prefix="SEC_")
        terms_to_mask = TransitObfuscator.extract_sensitive_data(violation_context)
        
        user_prompt_raw = f"Fix this compliance violation: {json.dumps(violation_context)}"
        user_prompt = obfuscator.mask_terms(user_prompt_raw, terms_to_mask)
        
        max_retries = 2
        for attempt in range(max_retries):
            current_model = "openai/gpt-oss-20b" if attempt == 0 else "openai/gpt-oss-120b"
            try:
                kwargs = {
                    "model": current_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.1
                }
                
                try:
                    response = await self.client.chat.completions.create(**kwargs)
                except Exception as api_e:
                    if "json_validate_failed" in str(api_e):
                        kwargs_no_json = kwargs.copy()
                        del kwargs_no_json["response_format"]
                        response = await self.client.chat.completions.create(**kwargs_no_json)
                    else:
                        raise api_e
                        
                content = response.choices[0].message.content or ""
                content = content.strip()
                if not content:
                    raise ValueError(f"Model {current_model} returned empty content.")
                    
                import re
                json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', content)
                if json_match:
                    content = json_match.group(1).strip()
                else:
                    start = content.find('{')
                    end = content.rfind('}')
                    if start != -1 and end != -1:
                        content = content[start:end+1]
                        
                content = obfuscator.unmask_text(content)
                    
                return json.loads(content)
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"LLM Remediation failed after {max_retries} attempts: {e}")
            
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

    async def get_batch_remediations(self, paths_contexts: list) -> Dict[str, Dict]:
        """Call LLM to get remediation steps for ALL paths in chunks to avoid TPM limits."""
        import json
        import re
        
        if not paths_contexts:
            return {}
            
        if not self.client:
            return {
                ctx.get("path_id", ""): {
                    "executive_summary": "Manual review required. AI remediation currently not working.",
                    "cli_command": "# Ensure you have valid credentials before proceeding\necho 'Remediation pending API configuration'",
                    "terraform_snippet": "# Terraform remediation pending API configuration"
                } for ctx in paths_contexts
            }

        final_remediations = {}
        
        # Sort paths by risk severity to prioritize critical ones if we fail later
        severity_map = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_contexts = sorted(paths_contexts, key=lambda x: severity_map.get(str(x.get("risk_severity")).lower(), 4))
        
        # Process in chunks of 1 to avoid exceeding max_tokens, TPM limits, or truncation
        chunk_size = 1
        for i in range(0, len(sorted_contexts), chunk_size):
            chunk = sorted_contexts[i:i + chunk_size]
            
            compressed_paths = []
            for ctx in chunk:
                nodes = ctx.get("nodes")
                if not isinstance(nodes, list):
                    nodes = []
                    
                nodes_involved = []
                for n in nodes[:3]:
                    if isinstance(n, dict):
                        nodes_involved.append(n.get("type", "Unknown"))
                    else:
                        nodes_involved.append(str(n))
                        
                compressed_paths.append({
                    "path_id": ctx.get("path_id"),
                    "path_name": ctx.get("path_name"),
                    "nodes_involved": nodes_involved,
                    "frameworks": ctx.get("applicable_compliance_frameworks", [])
                })

            system_prompt = """You are an expert Cloud Security Architect.
You are given a list of attack paths. For each path, provide remediation steps in STRICT JSON format.
You must return a valid JSON object where keys are the path_ids, and values are the remediation objects. Do not wrap it in markdown. Do not include any other text.
Format:
{
  "<path_id>": {
    "executive_summary": "Brief risk explanation citing frameworks.",
    "cli_command": "aws iam fix-command...",
    "terraform_snippet": "resource 'aws_iam' { ... }"
  }
}
"""

            from collectors.transit_encryption import TransitObfuscator
            obfuscator = TransitObfuscator(prefix="SEC_")
            terms_to_mask = TransitObfuscator.extract_sensitive_data(compressed_paths)
            
            user_prompt_raw = f"Paths to remediate: {json.dumps(compressed_paths)}"
            user_prompt = obfuscator.mask_terms(user_prompt_raw, terms_to_mask)

            import asyncio
            max_retries = 3
            
            for attempt in range(max_retries):
                # Upgrade to more powerful model on retries
                current_model = self.model if attempt == 0 else "openai/gpt-oss-120b"
                try:
                    kwargs = {
                        "model": current_model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.1,
                        "max_tokens": 2500
                    }
                    
                    try:
                        response = await self.client.chat.completions.create(**kwargs)
                    except Exception as api_e:
                        if "json_validate_failed" in str(api_e):
                            kwargs_no_json = kwargs.copy()
                            del kwargs_no_json["response_format"]
                            response = await self.client.chat.completions.create(**kwargs_no_json)
                        else:
                            raise api_e
                            
                    content = response.choices[0].message.content or ""
                    
                    # Strip markdown json wrappers
                    content = re.sub(r'^```(?:json)?\s*([\s\S]*?)\s*```$', r'\1', content.strip()).strip()
                    
                    # In case the model still puts extra text, extract the outermost JSON object
                    start_idx = content.find('{')
                    end_idx = content.rfind('}')
                    if start_idx != -1 and end_idx != -1:
                        content = content[start_idx:end_idx+1]
                        
                    content = obfuscator.unmask_text(content)
                    data = json.loads(content, strict=False)
                    
                    matches = []
                    for path_id, item in data.items():
                        if isinstance(item, dict) and "executive_summary" in item:
                            matches.append((
                                str(path_id),
                                str(item.get("executive_summary", "")),
                                str(item.get("cli_command", "")),
                                str(item.get("terraform_snippet", ""))
                            ))

                    
                    if not matches:
                        raise ValueError(f"No valid paths found in output. Raw output: {content[:100]}...")
                        
                    for match in matches:
                        path_id, summary, cli, tf = match
                        final_remediations[path_id.strip()] = {
                            "executive_summary": summary.strip(),
                            "cli_command": cli.strip(),
                            "terraform_snippet": tf.strip()
                        }
                    break # Break out of retry loop on success
                    
                except Exception as e:
                    error_str = str(e)
                    is_rate_limit = '429' in error_str or 'Rate limit' in error_str
                    
                    if is_rate_limit or attempt < max_retries - 1:
                        match = re.search(r'try again in (\d+\.?\d*)s', error_str) if is_rate_limit else None
                        sleep_time = float(match.group(1)) + 0.5 if match else (2 ** attempt) + 1.0
                        reason = "Rate limit hit" if is_rate_limit else f"Format parse error ({error_str})"
                        logger.warning(f"{reason}! Sleeping for {sleep_time}s (Attempt {attempt+1}/{max_retries})")
                        await asyncio.sleep(sleep_time)
                        continue
                    
                    # If not recoverable, or out of retries, fall back to static
                    logger.error(f"Batch LLM Remediation chunk failed permanently: {e}")
                    # Fallback for this specific chunk
                    for ctx in chunk:
                        path_id = ctx.get("path_id", "")
                        path_name = str(ctx.get("path_name", "")).lower()
                        
                        if 'mfa' in path_name:
                            final_remediations[path_id] = {
                                "executive_summary": "This path lacks sufficient Multi-Factor Authentication enforcement. MFA should be universally required for all privileged accounts.",
                                "cli_command": "# Enforce MFA for the identified identity.",
                                "terraform_snippet": "# Add MFA condition or MFA enforcement blocks to your Terraform identity resources."
                            }
                        elif 'admin' in path_name or 'privilege' in path_name:
                            final_remediations[path_id] = {
                                "executive_summary": "This identity possesses overprivileged access. Review and detach the excessively broad policies to strictly enforce the principle of least privilege.",
                                "cli_command": "# Detach the excessively permissive policies from the identity.",
                                "terraform_snippet": "# Remove the broad admin policy attachments from your Terraform configuration."
                            }
                        else:
                            final_remediations[path_id] = {
                                "executive_summary": "This path exposes potentially sensitive privileges. A manual security review of the associated IAM roles and bindings is highly recommended.",
                                "cli_command": "# Use cloud provider CLI tools to audit and restrict the excessive permissions identified in this path.",
                                "terraform_snippet": "# Adjust the corresponding IAM policies and resource bindings in your Terraform configuration to restrict access."
                            }
                    break # Don't retry if it fell back
                        
            # Sleep briefly between chunks to relieve TPM pressure
            await asyncio.sleep(3.0)
            
        return final_remediations

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
                table { width: 100%; border-collapse: collapse; margin-top: 1rem; margin-bottom: 2rem; table-layout: fixed; }
                th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; word-wrap: break-word; overflow-wrap: break-word; }
                tr { page-break-inside: avoid; }
                th { background-color: #f3f4f6; font-weight: 600; }
                pre { background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 0.375rem; font-size: 0.875rem; white-space: pre-wrap; word-wrap: break-word; }
                .badge { display: inline-block; padding: 0.25rem 0.5rem; font-size: 0.75rem; font-weight: 600; border-radius: 9999px; word-wrap: break-word; overflow-wrap: break-word; white-space: normal; }
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
                <table style="table-layout: fixed; width: 100%;">
                    <thead>
                        <tr>
                            <th style="width: 30%;">Entity</th>
                            <th style="width: 25%;">Control</th>
                            <th style="width: 45%;">Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for v in compliance_violations %}
                        <tr>
                            <td style="word-wrap: break-word; overflow-wrap: break-word; white-space: pre-wrap;">{{ v.resource_id }}</td>
                            <td><span class="badge badge-high">{{ v.violation_type }}</span></td>
                            <td style="word-wrap: break-word; overflow-wrap: break-word; white-space: pre-wrap;">
                                {{ v.actual_state }}
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
        from weasyprint import HTML
        env = Environment(loader=BaseLoader())
        template = env.from_string(self.html_template)
        
        def format_compliance_name(name):
            if not name: return "Unknown"
            if "digital_personal_data_protection" in name.lower() or "dpdp" in name.lower():
                return "DPDP Act 2023"
            return str(name).replace("_", " ").title()

        compliance_violations = report_data.get('compliance_violations', [])
        if compliance_violations:
            for v in compliance_violations:
                if 'violation_type' in v:
                    v['violation_type'] = format_compliance_name(v['violation_type'])
        
        html_out = template.render(
            scan_id=scan_id,
            date=report_data.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            frameworks=report_data.get('frameworks', []),
            stats=report_data.get('stats', {}),
            compliance_violations=compliance_violations,
            attack_paths=report_data.get('attack_paths', [])
        )
        
        pdf_path = f"/tmp/authmap_report_{scan_id}.pdf"
        HTML(string=html_out).write_pdf(pdf_path)
        return pdf_path
