"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";

type ScanData = {
  id: number;
  user_id: string;
  compliance_pdf_path: string;
  remediation_pdf_path: string;
  findings_txt_path: string;
};

const REPORT_TYPES = [
  {
    key: "compliance" as const,
    label: "IAM Compliance Report",
    title: "SOC 2 · RBI · DPDP Assessment",
    description:
      "A comprehensive PDF report mapping IAM findings to SOC 2 (CC6.1, CC6.2), RBI (7.1, 7.2), and DPDP Act (Section 8) controls. Includes gap analysis, risk scores, and audit-ready evidence.",
    accentClass: "action-box-cyan",
    filename: "compliance_report",
    icon: "📋",
  },
  {
    key: "remediation" as const,
    label: "Attack Path Remediation",
    title: "Prioritized Fix Roadmap",
    description:
      "A prioritized remediation plan with specific IAM policy changes, permission removals, MFA enforcement recommendations, and zombie resource decommissioning steps — ordered by risk score impact.",
    accentClass: "action-box-gold",
    filename: "remediation_report",
    icon: "🛡️",
  },
];

export default function ReportsPage() {
  const { getToken } = useAuth();
  const [latestScan, setLatestScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function fetchLatest() {
      try {
        const token = await getToken();
        const res = await fetch("http://localhost:8000/scan/results/latest", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          setLatestScan(await res.json());
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
  }, [getToken]);

  async function downloadReport(fileType: "compliance" | "remediation", filename: string) {
    if (!latestScan) return;
    setDownloading(fileType);
    try {
      const token = await getToken();
      const res = await fetch(
        `http://localhost:8000/scan/download/${latestScan.id}/${fileType}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `authmap_${filename}_${latestScan.id}.pdf`;
      link.click();
      URL.revokeObjectURL(link.href);
    } catch {
      alert(`Failed to download ${fileType} report.`);
    } finally {
      setDownloading(null);
    }
  }

  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Reports"
          title="IAM analysis reports."
          description="AuthMap generates compliance-mapped PDF reports and prioritized remediation roadmaps after every analysis. Download both below."
        />

        {loading && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="animate-pulse text-sm text-slate-400">Loading reports…</p>
          </div>
        )}

        {error && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="text-sm text-slate-400">{error}</p>
          </div>
        )}

        {/* Report description cards — always visible */}
        <section className="grid gap-5 lg:grid-cols-2">
          {REPORT_TYPES.map((report) => (
            <article
              key={report.key}
              className="flex flex-col justify-between rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
            >
              <div>
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{report.icon}</span>
                  <p className="font-[family:var(--font-plex-mono)] text-[0.65rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                    {report.label}
                  </p>
                </div>
                <h2 className="mt-3 text-2xl font-semibold tracking-tight text-white">
                  {report.title}
                </h2>
                <p className="mt-3 text-sm leading-7 text-slate-300">{report.description}</p>
              </div>

              <div className="mt-6">
                {latestScan ? (
                  <div className="flex flex-wrap items-center gap-4">
                    <button
                      type="button"
                      onClick={() => downloadReport(report.key, report.filename)}
                      disabled={downloading === report.key}
                      className={`action-box ${report.accentClass} px-5 py-3 text-sm font-semibold text-white disabled:opacity-50`}
                    >
                      {downloading === report.key
                        ? "Downloading…"
                        : `Download ${report.label} PDF`}
                    </button>
                    <span className="text-xs text-slate-500">
                      Scan ID #{latestScan.id} &middot; .pdf
                    </span>
                  </div>
                ) : (
                  !loading && (
                    <p className="text-sm text-slate-500">
                      No scan on record. Run a scan from the Overview page first.
                    </p>
                  )
                )}
              </div>
            </article>
          ))}
        </section>

        {/* Meta info when scan is loaded */}
        {latestScan && (
          <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
            <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Active scan record
            </p>
            <h2 className="mt-2 text-xl font-semibold tracking-tight text-white">
              Report bundle — Scan #{latestScan.id}
            </h2>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              {[
                { label: "Compliance PDF", path: latestScan.compliance_pdf_path },
                { label: "Remediation PDF", path: latestScan.remediation_pdf_path },
                { label: "Findings TXT", path: latestScan.findings_txt_path },
              ].map((f) => (
                <div
                  key={f.label}
                  className="rounded-xl border border-white/10 bg-black/30 px-4 py-3"
                >
                  <p className="text-xs font-semibold uppercase tracking-widest text-slate-400">
                    {f.label}
                  </p>
                  <p className="mt-1 truncate text-xs text-slate-300">
                    {f.path ? f.path.split("/").pop() : "—"}
                  </p>
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs text-slate-500">
              Files are stored securely on the server. Use the download buttons above to retrieve them.
            </p>
          </section>
        )}
      </div>
    </AppShell>
  );
}