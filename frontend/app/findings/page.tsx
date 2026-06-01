"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { moduleLabels } from "@/lib/scan-data";

type ScanData = {
  id: number;
  user_id: string;
  compliance_pdf_path: string;
  remediation_pdf_path: string;
  findings_txt_path: string;
};

const STATIC_FINDINGS = [
  {
    severity: "Critical",
    label: "Prompt Injection Bypass",
    title: "Direct Instruction Override",
    summary:
      "Payloads that explicitly override the system prompt — e.g. 'Ignore all previous instructions' — are tested. A Critical finding means the agent obeyed injected instructions instead of its guardrails.",
    icon: "⚡",
  },
  {
    severity: "High",
    label: "Jailbreak Compliance",
    title: "Role-play / Persona Bypass",
    summary:
      "DAN-style and persona-shifting payloads are evaluated. A High finding means the agent adopted an unrestricted alternate persona, exposing unsafe capabilities.",
    icon: "🔓",
  },
  {
    severity: "Medium",
    label: "Partial Defence Coverage",
    title: "Selective Filtering Gap",
    summary:
      "Some payloads were blocked but not all attack categories were consistently defended. Defensive coverage is incomplete — adversaries can iterate to find gaps.",
    icon: "⚠️",
  },
  {
    severity: "Low",
    label: "Endpoint Reliability",
    title: "Intermittent Error Responses",
    summary:
      "Timeouts, 5xx responses, or connection refusals were detected during the scan. These degrade security posture assessment confidence and may mask real vulnerabilities.",
    icon: "🔌",
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

export default function FindingsPage() {
  const { getToken } = useAuth();
  const [latestScan, setLatestScan] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
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

  async function downloadFindings() {
    if (!latestScan) return;
    setDownloading(true);
    try {
      const token = await getToken();
      const res = await fetch(
        `http://localhost:8000/scan/download/${latestScan.id}/findings`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `boxai_findings_${latestScan.id}.txt`;
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
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Findings"
          title="Security findings from your scan."
          description="Severity-classified findings surfaced by BoxAI's prompt injection scanner. Each category reflects a distinct attack vector. Download the full findings document for audit trail evidence."
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

        {/* Always render findings taxonomy cards */}
        <section className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
          {STATIC_FINDINGS.map((item) => (
            <article
              key={item.severity}
              className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
            >
              <div className="flex items-start justify-between gap-3">
                <span
                  className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em] ${getSeverityColor(item.severity)}`}
                >
                  {item.severity}
                </span>
                <span className="text-xl">{item.icon}</span>
              </div>
              <p className="mt-4 font-[family:var(--font-plex-mono)] text-[0.65rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                {item.label}
              </p>
              <h2 className="mt-2 text-lg font-semibold tracking-tight text-white">
                {item.title}
              </h2>
              <p className="mt-3 text-sm leading-6 text-slate-300">{item.summary}</p>
            </article>
          ))}
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
                {downloading ? "Downloading…" : "Download findings.txt"}
              </button>
              <span className="text-xs text-slate-500">
                Scan ID #{latestScan.id} &middot; findings.txt
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