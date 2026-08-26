"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { moduleLabels } from "@/lib/scan-data";

/* ── Types ─────────────────────────────────────────────── */
type ScanData = {
  id: number;
  user_id: string;
  compliance_pdf_path: string;
  remediation_pdf_path: string;
  findings_txt_path: string;
};

interface FindingsData {
  entities: {
    total: number;
    users: number;
    roles: number;
    groups: number;
    policies: number;
    service_accounts?: number;
  };
  risk: {
    admin_count: number;
    overprivileged_count: number;
    dormant_count: number;
  };
  attack_paths: {
    total: number;
    max_risk_score: number;
    avg_risk_score: number;
  };
  compliance_violations: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  total_estimated_breach_cost: number;
}

/* ── Static cards data ─────────────────────────────────── */
const STATIC_FINDINGS = [
  {
    severity: "Critical",
    label: "Privilege Escalation Path",
    title: "Admin Access Chain Detected",
    summary:
      "A chain of IAM permissions allows lateral movement from a low-privilege user to administrative access through role assumption, policy attachment, or service account impersonation.",
  },
  {
    severity: "High",
    label: "Cross-Account Exposure",
    title: "Role Trust Policy Exploitable",
    summary:
      "Trust policies enable cross-account role assumption without MFA enforcement, creating a lateral movement vector between AWS accounts or GCP projects.",
  },
  {
    severity: "Medium",
    label: "Cost-Risk Overlap",
    title: "Zombie Admin Resources Active",
    summary:
      "IAM users or service accounts with admin-level permissions show no recent API activity but remain attached to resources generating ongoing cloud costs.",
  },
  {
    severity: "Low",
    label: "Compliance Gap",
    title: "SOC 2 / RBI Control Mismatch",
    summary:
      "IAM configurations do not fully satisfy SOC 2 CC6.1 least-privilege requirements or RBI 7.1 access control mandates. Manual review recommended before next audit.",
  },
];

function getSeverityColor(severity: string) {
  switch (severity) {
    case "Critical":
      return "border-red-500/40 bg-red-500/10 text-red-400";
    case "High":
      return "border-orange-500/40 bg-orange-500/10 text-orange-400";
    case "Medium":
      return "border-yellow-500/40 bg-yellow-500/10 text-yellow-400";
    case "Low":
      return "border-blue-500/40 bg-blue-500/10 text-blue-400";
    default:
      return "border-white/10 bg-white/5 text-white";
  }
}

function formatCurrency(n: number): string {
  if (n >= 1_000_000_000) return `$${(n / 1_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

/* ── Component ─────────────────────────────────────────── */
export default function FindingsPage() {
  const { getToken, isLoaded } = useAuth();
  const [latestScan, setLatestScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState("");
  const [findings, setFindings] = useState<FindingsData | null>(null);

  const contentRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const timer = setTimeout(() => {
      if (contentRef.current) {
        contentRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    }, 150);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!isLoaded) return;
    
    async function fetchLatest() {
      try {
        const token = await getToken();
        if (!token) return; // Prevent 401
        const headers = { Authorization: `Bearer ${token}` };
        const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;

        const res = await fetch(`${backendUrl}/scan/results/latest`, { headers });
        if (res.ok) {
          const scan = await res.json();
          setLatestScan(scan);

          const scanId = scan.id ?? scan.scan_id;

          // Fetch findings data
          try {
            const findingsRes = await fetch(`${backendUrl}/scan/findings/${scanId}`, { headers });
            if (findingsRes.ok) {
              setFindings(await findingsRes.json());
            }
          } catch {
            // findings data not available, continue with static cards
          }
        } else if (res.status === 404) {
          setError("No scan results yet. Run a scan from the overview page first.");
        } else {
          setError("Failed to load scan results.");
        }
      } catch {
        setError("Could not reach the backend server.");
      } finally {
        setLoading(false);
      }
    }
    fetchLatest();
  }, [getToken, isLoaded]);

  async function downloadFindings() {
    if (!latestScan) return;
    setDownloading(true);
    try {
      const token = await getToken();
      const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
      const res = await fetch(
        `${backendUrl}/scan/download/${latestScan.id}/findings`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `authmap_findings_${latestScan.id}.pdf`;
      link.click();
      URL.revokeObjectURL(link.href);
    } catch {
      alert("Failed to download findings file.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <AppShell>
      <div className="space-y-6 pb-10" ref={contentRef}>
        <ScreenHeader
          eyebrow="Security Findings"
          title="IAM security findings from your analysis."
          description="Risk-scored findings from AuthMap's 4-layer privilege escalation detection. Each category reflects a distinct IAM attack vector across your AWS and GCP environments."
        />

        {loading && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="animate-pulse text-sm text-slate-400">Loading findings…</p>
          </div>
        )}

        {error && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="text-sm text-slate-400">{error}</p>
          </div>
        )}

        {/* Scan Results — real data section */}
        {!loading && findings && (
          <section className="space-y-6">
            <div>
              <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                Scan Results
              </p>
              <h2 className="mt-2 text-xl font-semibold text-white">Live analysis data</h2>
            </div>

            {/* Entity summary row */}
            <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
              {[
                { label: "Total Entities", value: findings.entities.total, color: "text-white" },
                { label: "Users", value: findings.entities.users, color: "text-[var(--accent-cyan)]" },
                { label: "Roles", value: findings.entities.roles, color: "text-[var(--accent-gold)]" },
                { label: "Groups", value: findings.entities.groups, color: "text-slate-300" },
                { label: "Policies", value: findings.entities.policies, color: "text-[var(--accent-magenta)]" },
              ].map((item) => (
                <div key={item.label} className="rounded-[1.4rem] border border-white/10 bg-white/[0.03] p-5">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                    {item.label}
                  </p>
                  <p className={`mt-2 text-2xl font-semibold ${item.color}`}>{item.value}</p>
                </div>
              ))}
            </div>

            {/* Risk summary */}
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="rounded-[1.4rem]  bg-white-500/[0.04] p-5">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Admin Entities
                </p>
                <p className="mt-2 text-2xl font-semibold text-red-400">{findings.risk.admin_count}</p>
              </div>
              <div className="rounded-[1.4rem]  bg-white-500/[0.04] p-5">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Overprivileged
                </p>
                <p className="mt-2 text-2xl font-semibold text-orange-400">{findings.risk.overprivileged_count}</p>
              </div>
              <div className="rounded-[1.4rem] bg-white-500/[0.04] p-5">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Dormant Credentials
                </p>
                <p className="mt-2 text-2xl font-semibold text-yellow-400">{findings.risk.dormant_count}</p>
              </div>
            </div>

            {/* Attack paths summary + compliance + breach cost */}
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {/* Attack paths */}
              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Attack Paths
                </p>
                <p className="mt-3 text-3xl font-semibold text-white">{findings.attack_paths.total}</p>
                <div className="mt-3 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Max risk score</span>
                    <span className="font-semibold text-red-400">{findings.attack_paths.max_risk_score}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Avg risk score</span>
                    <span className="font-semibold text-[var(--accent-gold)]">{findings.attack_paths.avg_risk_score.toFixed(1)}</span>
                  </div>
                </div>
              </div>

              {/* Compliance violations */}
              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Compliance Violations
                </p>
                <div className="mt-3 grid grid-cols-2 gap-2">
                  <div className="rounded-lg  bg-white-500/[0.06] p-2 text-center">
                    <p className="text-lg font-semibold text-red-400">{findings.compliance_violations.critical}</p>
                    <p className="text-[0.6rem] uppercase tracking-wider text-red-400/70">Critical</p>
                  </div>
                  <div className="rounded-lg  bg-white-500/[0.06] p-2 text-center">
                    <p className="text-lg font-semibold text-orange-400">{findings.compliance_violations.high}</p>
                    <p className="text-[0.6rem] uppercase tracking-wider text-orange-400/70">High</p>
                  </div>
                  <div className="rounded-lg  bg-white-500/[0.06] p-2 text-center">
                    <p className="text-lg font-semibold text-yellow-400">{findings.compliance_violations.medium}</p>
                    <p className="text-[0.6rem] uppercase tracking-wider text-yellow-400/70">Medium</p>
                  </div>
                  <div className="rounded-lg  bg-white-500/[0.06] p-2 text-center">
                    <p className="text-lg font-semibold text-blue-400">{findings.compliance_violations.low}</p>
                    <p className="text-[0.6rem] uppercase tracking-wider text-blue-400/70">Low</p>
                  </div>
                </div>
              </div>

              {/* Breach cost */}
              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Est. Breach Cost
                </p>
                <p className="mt-3 text-3xl font-semibold text-[var(--accent-magenta)]">
                  {formatCurrency(findings.total_estimated_breach_cost)}
                </p>
                <p className="mt-2 text-xs text-slate-500">Based on attack paths and compliance framework penalties</p>
              </div>
            </div>
          </section>
        )}

        {/* No-scan banner when findings data missing but no error */}
        {!loading && !findings && !error && (
          <div className="rounded-[1.4rem] border border-[var(--accent-cyan)]/20 bg-[rgba(158,193,182,0.05)] p-5">
            <p className="text-sm text-slate-300">
              Run a scan from the{" "}
              <Link href="/scan-wizard" className="font-semibold text-[var(--accent-cyan)] underline underline-offset-2">
                Scan Wizard
              </Link>{" "}
              to see real-time findings data alongside these categories.
            </p>
          </div>
        )}

        {/* Finding Categories — static cards (always rendered) */}
        <section>
          <p className="mb-4 font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
            Finding Categories
          </p>
          <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
            {STATIC_FINDINGS.map((item) => (
              <article
                key={item.severity}
                className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
              >
                
                <p className="mt-4 font-[family:var(--font-plex-mono)] text-[0.65rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  {item.label}
                </p>
                <h2 className="mt-2 text-lg font-semibold tracking-tight text-white">
                  {item.title}
                </h2>
                <p className="mt-3 text-sm leading-6 text-slate-300">{item.summary}</p>
              </article>
            ))}
          </div>
        </section>

        {/* Download section — only when a scan exists */}
        <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
          <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
            Findings Document
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white">
            Full scan findings log.
          </h2>
          <p className="mt-3 max-w-2xl text-sm leading-7 text-slate-300">
            The findings document is a structured text file that records every payload
            attempt, its result, the dataset source, status code, and the raw model
            response fragment captured during the scan execution.
          </p>

          {latestScan ? (
            <div className="mt-5 flex flex-wrap items-center gap-4">
              <button
                type="button"
                onClick={downloadFindings}
                disabled={downloading}
                className="action-box action-box-cyan px-5 py-3 text-sm font-semibold text-white disabled:opacity-50"
              >
                {downloading ? "Downloading…" : "Download findings.pdf"}
              </button>
              <span className="text-xs text-slate-500">
                Scan ID #{latestScan.id} &middot; findings.pdf
              </span>
            </div>
          ) : (
            !loading && (
              <p className="mt-5 text-sm text-slate-500">
                No scan on record. Run a scan from the Overview page first.
              </p>
            )
          )}
        </section>

        {/* Covered modules */}
        <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
          <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
            Covered modules
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            {moduleLabels.map((label) => (
              <span
                key={label}
                className="rounded-full border border-white/10 bg-black px-4 py-2 text-sm font-medium text-white"
              >
                {label}
              </span>
            ))}
          </div>
        </section>
      </div>
    </AppShell>
  );
}
