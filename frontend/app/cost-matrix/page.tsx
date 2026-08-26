"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState, useRef } from "react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { BarChart3, Zap } from "lucide-react";

/* ── Types ─────────────────────────────────────────────── */
interface CostPath {
  path_id?: string;
  path: string;
  risk_score: number;
  estimated_cost: number;
  compliance: string[];
  severity: string;
}

interface CompliancePenalty {
  framework: string;
  penalty_low: number;
  penalty_high: number;
}

interface CostAnalysis {
  total_estimated_breach_cost: number;
  max_regulatory_penalty: number;
  avg_per_record_cost: number;
  max_risk_score: number;
  paths: CostPath[];
  compliance_penalties: CompliancePenalty[];
}

/* ── Helpers ───────────────────────────────────────────── */
function formatCurrency(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

function severityColor(s: string) {
  switch (s.toLowerCase()) {
    case "critical": return "text-red-400 border-red-500/30 bg-red-500/10";
    case "high": return "text-orange-400 border-orange-500/30 bg-orange-500/10";
    case "medium": return "text-yellow-400 border-yellow-500/30 bg-yellow-500/10";
    case "low": return "text-blue-400 border-blue-500/30 bg-blue-500/10";
    default: return "text-slate-400 border-white/10 bg-white/5";
  }
}

function classifyQuadrant(riskScore: number, cost: number, riskThreshold: number, costThreshold: number) {
  const highRisk = riskScore >= riskThreshold;
  const highCost = cost >= costThreshold;
  if (highCost && highRisk) return { label: "High Cost · High Risk", color: "text-red-400", action: "Priority — fix now" };
  if (!highCost && highRisk) return { label: "Low Cost · High Risk", color: "text-[var(--accent-magenta)]", action: "Fix permissions" };
  if (highCost && !highRisk) return { label: "High Cost · Low Risk", color: "text-[var(--accent-gold)]", action: "Optimize spend" };
  return { label: "Low Cost · Low Risk", color: "text-[var(--accent-cyan)]", action: "Safe — no action needed" };
}

/* ── Component ─────────────────────────────────────────── */
export default function CostMatrixPage() {
  const { getToken, isLoaded } = useAuth();
  const [loading, setLoading] = useState(true);
  const [noScan, setNoScan] = useState(false);
  const [costData, setCostData] = useState<CostAnalysis | null>(null);

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
    async function load() {
      try {
        const token = await getToken();
        if (!token) return; // Prevent 401
        const headers = { Authorization: `Bearer ${token}` };
        const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;

        const scanRes = await fetch(`${backendUrl}/scan/results/latest`, { headers });
        if (!scanRes.ok) {
          setNoScan(true);
          setLoading(false);
          return;
        }
        const scan = await scanRes.json();
        const scanId = scan.id ?? scan.scan_id;

        const costRes = await fetch(`${backendUrl}/scan/cost-analysis/${scanId}`, { headers });
        if (costRes.ok) {
          setCostData(await costRes.json());
        } else {
          setNoScan(true);
        }
      } catch {
        setNoScan(true);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [getToken, isLoaded]);

  /* ── Quadrant classification ───────────────────────── */
  const riskThreshold = costData?.paths?.length ? Math.max(50, ...costData.paths.map((p) => p.risk_score)) * 0.5 : 50;
  const costThreshold = costData?.paths?.length ? Math.max(10000, ...costData.paths.map((p) => p.estimated_cost)) * 0.5 : 10000;

  const quadrants = costData?.paths
    ? {
        hh: costData.paths.filter((p) => p.risk_score >= riskThreshold && p.estimated_cost >= costThreshold),
        lh: costData.paths.filter((p) => p.risk_score >= riskThreshold && p.estimated_cost < costThreshold),
        hl: costData.paths.filter((p) => p.risk_score < riskThreshold && p.estimated_cost >= costThreshold),
        ll: costData.paths.filter((p) => p.risk_score < riskThreshold && p.estimated_cost < costThreshold),
      }
    : null;

  return (
    <AppShell>
      <div className="space-y-8 pb-10" ref={contentRef}>
        <ScreenHeader
          eyebrow="Cost Matrix"
          title="Cloud spend vs IAM risk — one scatter plot."
          description="Four-quadrant Cost (X) × Risk (Y) visualization. Instantly spot resources that are expensive AND dangerous, so you save budget while reducing attack surface."
        />

        {loading && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-10 text-center">
            <p className="animate-pulse text-sm text-slate-400">Loading cost analysis…</p>
          </div>
        )}

        {!loading && noScan && (
          <section className="rounded-[2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.04),rgba(255,255,255,0.02))] p-6 shadow-[0_20px_50px_rgba(0,0,0,0.18)] md:p-8">
            <div className="flex flex-col items-center justify-center gap-6 py-20">
              <div className="flex h-24 w-24 items-center justify-center rounded-full border border-[var(--accent-gold)]/30 bg-[rgba(234,216,178,0.08)]">
                <BarChart3 className="h-10 w-10 text-[var(--accent-gold)]" />
              </div>
              <div className="text-center">
                <h2 className="text-2xl font-semibold text-white">Cost-risk scatter plot loading zone</h2>
                <p className="mt-3 max-w-lg text-sm leading-7 text-slate-300">
                  Import cost data and run IAM analysis to populate the scatter plot. Each dot represents a cloud resource, positioned by monthly spend (X) and IAM risk score (Y).
                </p>
              </div>
              <div className="grid w-full max-w-md grid-cols-2 gap-3 pt-4">
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-center">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] uppercase tracking-[0.2em] text-slate-400">Quadrant</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--accent-cyan)]">Low cost · Low risk</p>
                  <p className="mt-1 text-xs text-slate-400">Safe — no action needed</p>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-center">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] uppercase tracking-[0.2em] text-slate-400">Quadrant</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--accent-gold)]">High cost · Low risk</p>
                  <p className="mt-1 text-xs text-slate-400">Optimize spend</p>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-center">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] uppercase tracking-[0.2em] text-slate-400">Quadrant</p>
                  <p className="mt-1 text-sm font-semibold text-[var(--accent-magenta)]">Low cost · High risk</p>
                  <p className="mt-1 text-xs text-slate-400">Fix permissions</p>
                </div>
                <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-center">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] uppercase tracking-[0.2em] text-slate-400">Quadrant</p>
                  <p className="mt-1 text-sm font-semibold text-red-400">High cost · High risk</p>
                  <p className="mt-1 text-xs text-slate-400">Priority — fix now</p>
                </div>
              </div>
              <Link
                href="/scan-wizard"
                className="action-box action-box-gold px-5 py-2.5 text-sm font-semibold text-white"
              >
                Launch Scan Wizard →
              </Link>
            </div>
          </section>
        )}

        {!loading && costData && (
          <>
            {/* SGTC Breakdown Section */}
            <section className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
              <div className="flex items-center gap-3 mb-6">
                <span className="flex h-10 w-10 items-center justify-center rounded-full border border-white/10 bg-[#12161d] text-lg font-bold text-white shadow-sm">
                </span>
                <div>
                  <h3 className="text-xl font-bold text-white tracking-tight">SGTC Risk Engine</h3>
                  <p className="text-sm text-slate-400 mt-1">
                    Risk scores are mathematically derived from a weighted blend of four dimensions (SGTC).
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="rounded-xl border border-white/10 bg-[#0a0d12]/50 p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[var(--accent-cyan)] font-bold text-lg">S</span>
                    <span className="font-semibold text-white tracking-wide">Static</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-3 font-medium">(40% Weight)</p>
                  <p className="text-sm leading-relaxed text-slate-300">
                    Evaluates absolute permissions (e.g., <code className="text-xs bg-black/50 px-1 rounded">iam:PassRole</code>). Blends the highest severity permission (60%) with the average permission risk (40%).
                  </p>
                </div>
                <div className="rounded-xl border border-white/10 bg-[#0a0d12]/50 p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[var(--accent-magenta)] font-bold text-lg">G</span>
                    <span className="font-semibold text-white tracking-wide">Graph</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-3 font-medium">(30% Weight)</p>
                  <p className="text-sm leading-relaxed text-slate-300">
                    Measures topological blast radius. Analyzes path lengths to admin roles and adds dynamic Complexity Penalties for massive attack surfaces. Weights deterministic topology logic (75%) over ML anomaly detection (25%).
                  </p>
                </div>
                <div className="rounded-xl border border-white/10 bg-[#0a0d12]/50 p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[var(--accent-gold)] font-bold text-lg">T</span>
                    <span className="font-semibold text-white tracking-wide">Temporal</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-3 font-medium">(20% Weight)</p>
                  <p className="text-sm leading-relaxed text-slate-300">
                    Analyzes behavioral anomalies using Machine Learning (Isolation Forests) on CloudTrail/Audit Logs to detect unusual temporal activity spikes.
                  </p>
                </div>
                <div className="rounded-xl border border-white/10 bg-[#0a0d12]/50 p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-red-400 font-bold text-lg">C</span>
                    <span className="font-semibold text-white tracking-wide">Cost</span>
                  </div>
                  <p className="text-xs text-slate-400 mb-3 font-medium">(10% Weight)</p>
                  <p className="text-sm leading-relaxed text-slate-300">
                    Translates technical risk into financial exposure. Normalizes the estimated data breach cost penalty against your annual revenue logic.
                  </p>
                </div>
              </div>
            </section>

            {/* Summary cards */}
            <section className="grid gap-4 sm:grid-cols-4">
              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Total Estimated Breach Cost
                </p>
                <p className="mt-3 text-3xl font-semibold text-[var(--accent-magenta)]">
                  {formatCurrency(costData.total_estimated_breach_cost)}
                </p>
              </div>
              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Maximum Regulatory Penalty
                </p>
                <p className="mt-3 text-3xl font-semibold text-red-400">
                  {formatCurrency(costData.max_regulatory_penalty)}
                </p>
              </div>
              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Average Per-Record Cost
                </p>
                <p className="mt-3 text-3xl font-semibold text-[var(--accent-gold)]">
                  ${costData.avg_per_record_cost.toFixed(2)}
                </p>
              </div>
              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.6rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                  Max SGTC Risk Score
                </p>
                <p className="mt-3 text-3xl font-semibold text-[var(--accent-cyan)]">
                  {costData.max_risk_score ? costData.max_risk_score.toFixed(1) : "0.0"} <span className="text-sm font-medium text-slate-500">/ 100</span>
                </p>
              </div>
            </section>

            {/* Per-path cost table */}
            {costData.paths && costData.paths.length > 0 && (
              <section className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                  Per-Path Cost Breakdown
                </p>
                <div className="mt-4 overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/10 text-left">
                        <th className="pb-3 pr-4 font-medium text-slate-400">Path</th>
                        <th className="pb-3 pr-4 font-medium text-slate-400">Risk</th>
                        <th className="pb-3 pr-4 font-medium text-slate-400">Est. Cost</th>
                        <th className="pb-3 pr-4 font-medium text-slate-400">Compliance</th>
                        <th className="pb-3 font-medium text-slate-400">Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {costData.paths.map((p, i) => (
                        <tr key={i} className="border-b border-white/5">
                          <td className="py-3 pr-4 text-white max-w-[200px] truncate" title={p.path}>
                            {p.path}
                          </td>
                          <td className="py-3 pr-4 font-semibold text-white">{p.risk_score}</td>
                          <td className="py-3 pr-4 font-semibold text-[var(--accent-gold)]">
                            {formatCurrency(p.estimated_cost)}
                          </td>
                          <td className="py-3 pr-4 text-slate-300">
                            {p.compliance.length > 0 ? p.compliance.join(", ") : "—"}
                          </td>
                          <td className="py-3">
                            <span className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider ${severityColor(p.severity)}`}>
                              {p.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            {/* Compliance penalty section */}
            {costData.compliance_penalties && costData.compliance_penalties.length > 0 && (
              <section className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                  Compliance Penalty Ranges
                </p>
                <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {costData.compliance_penalties.map((cp) => (
                    <div key={cp.framework} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                      <p className="text-sm font-semibold text-white">{cp.framework}</p>
                      <div className="mt-2 flex items-baseline gap-1.5">
                        <span className="text-lg font-semibold text-[var(--accent-magenta)]">{formatCurrency(cp.penalty_low)}</span>
                        <span className="text-xs text-slate-500">—</span>
                        <span className="text-lg font-semibold text-red-400">{formatCurrency(cp.penalty_high)}</span>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">Potential penalty range</p>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Quadrant display */}
            {quadrants && costData.paths.length > 0 && (
              <section className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                  Quadrant Classification
                </p>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  {[
                    { key: "hh" as const, label: "High Cost · High Risk", color: "text-red-400", borderColor: "border-red-500/30", action: "Priority — fix now", paths: quadrants.hh },
                    { key: "lh" as const, label: "Low Cost · High Risk", color: "text-[var(--accent-magenta)]", borderColor: "border-[var(--accent-magenta)]/30", action: "Fix permissions", paths: quadrants.lh },
                    { key: "hl" as const, label: "High Cost · Low Risk", color: "text-[var(--accent-gold)]", borderColor: "border-[var(--accent-gold)]/30", action: "Optimize spend", paths: quadrants.hl },
                    { key: "ll" as const, label: "Low Cost · Low Risk", color: "text-[var(--accent-cyan)]", borderColor: "border-[var(--accent-cyan)]/30", action: "Safe — no action needed", paths: quadrants.ll },
                  ].map((q) => (
                    <div key={q.key} className={`rounded-xl border ${q.borderColor} bg-white/[0.02] p-4`}>
                      <p className={`text-sm font-semibold ${q.color}`}>{q.label}</p>
                      <p className="mt-1 text-xs text-slate-500">{q.action}</p>
                      <p className="mt-2 text-2xl font-semibold text-white">{q.paths.length}</p>
                      <p className="text-xs text-slate-400">
                        {q.paths.length === 1 ? "path" : "paths"}
                      </p>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}
