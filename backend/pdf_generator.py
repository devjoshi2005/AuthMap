from fpdf import FPDF
from datetime import datetime
import json

class AITeamReport(FPDF):
    """Auditor-grade PDF generator for AI Agent Security & Policy Compliance"""

    def __init__(self):
        super().__init__()
        self.set_margins(15, 20, 15)

    def header(self):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 8, "CONFIDENTIAL AI AGENT CONTAINMENT REPORT NOT FOR EXTERNAL DISTRIBUTION", 0, 1, "R")
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100)
        page_info = f"Page {self.page_no()} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | Red Team Use Only"
        self.cell(0, 10, page_info, 0, 0, "C")

    def chapter_title(self, title: str, level: int = 1):
        if level == 1:
            self.set_font("Helvetica", "B", 14)
            self.set_fill_color(30, 58, 138)
            self.set_text_color(255, 255, 255)
            self.cell(0, 10, f"  {title}", 0, 1, "L", fill=True)
        else:
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(30, 58, 138)
            self.cell(0, 8, title, 0, 1, "L")
        self.ln(2)

    def metric_box(self, label: str, value: str, risk_level: str = "info"):
        colors = {
            "critical": (220, 53, 69),
            "high": (253, 126, 20),
            "medium": (255, 193, 7),
            "low": (40, 167, 69),
            "info": (108, 117, 125)
        }
        bg = colors.get(risk_level, colors["info"])
        self.set_fill_color(*bg)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 10)
        self.cell(60, 8, str(label), 0, 0, "L", fill=True)
        self.set_fill_color(245, 247, 249)
        self.set_text_color(33, 37, 41)
        self.cell(60, 8, str(value), 0, 1, "R", fill=True)
        self.ln(1)


def generate_ai_report(scan_id: int, scan_url: str, tier: str, outputs_doc: str, remediation_doc: str) -> bytes:
    outputs = outputs_doc.split("\n")
    total_payloads = sum(1 for line in outputs if "Status: " in line)
    errors = sum(1 for line in outputs if "ERROR" in line)
    
    critical_count = remediation_doc.count("## Specific")
    has_bypasses = critical_count > 0
    risk = "critical" if has_bypasses else "info"

    pdf = AITeamReport()
    pdf.add_page()
    
    pdf.ln(20)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(30, 58, 138)
    pdf.cell(0, 15, "BOXAI SECURITY SCAN REPORT", 0, 1, "C")
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 12, "OWASP Top 10 for LLMs / Prompt Injection Assessment", 0, 1, "C")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100)
    pdf.cell(0, 10, f"Target Endpoint: {scan_url}", 0, 1, "C")
    pdf.cell(0, 10, f"Scan Profile ID: {scan_id} | Tier: {tier.upper()}", 0, 1, "C")
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d')}", 0, 1, "C")

    pdf.add_page()
    pdf.chapter_title("1. Executive Summary", level=1)
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(33, 37, 41)
    summary_text = (
        f"This report outlines the prompt injection resilience posture of the target AI agent ({scan_url}). "
        f"During the simulated attack, BoxAI fired {total_payloads} adversarial payloads attempting jailbreaks, "
        f"system instruction extraction, and tool execution bypasses."
    )
    pdf.multi_cell(0, 7, summary_text)
    pdf.ln(5)

    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 8, "Execution Metrics", 0, 1)
    pdf.metric_box("Total Payloads Tested", str(total_payloads), "info")
    pdf.metric_box("Endpoint Errors / Timeouts", str(errors), "medium" if errors > 0 else "info")
    pdf.metric_box("Detected Bypasses", str(critical_count), "critical" if critical_count > 0 else "low")
    pdf.metric_box("Overall Posture Risk", "HIGH" if has_bypasses else "SECURE", risk)
    pdf.ln(5)
    
    pdf.add_page()
    pdf.chapter_title("2.Remediation Roadmap", level=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(33, 37, 41)
    
    clean_remediation = remediation_doc.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 6, clean_remediation)
    
    return pdf.output()

def generate_remediation_pdf(remediation_doc: str) -> bytes:
    pdf = AITeamReport()
    pdf.add_page()
    pdf.ln(10)
    pdf.chapter_title("Remediation Roadmap", level=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(33, 37, 41)
    clean_remediation = remediation_doc.encode('latin-1', 'replace').decode('latin-1')
    pdf.multi_cell(0, 6, clean_remediation)
    return pdf.output()
