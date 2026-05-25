"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { moduleLabels } from "@/lib/scan-data";

type ScanResult = {
  id: number;
  scan_url: string;
  tier: string;
  outputs: string;
  remediation: string;
};

function downloadFile(content: string, filename: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function parseSeverityFromOutputs(outputs: string): { severity: string; title: string; summary: string }[] {
  const findings: { severity: string; title: string; summary: string }[] = [];

  if (/bypass|injection succeed|vulnerable|exploitable/i.test(outputs)) {
    findings.push({
      severity: "Critical",
      title: "Prompt injection vulnerability detected",
      summary: "One or more payloads successfully bypassed the agent's defenses. The endpoint accepted injected instructions.",
    });
  }
  if (/blocked|filtered|rejected|refused/i.test(outputs)) {
    findings.push({
      severity: "Medium",
      title: "Partial prompt injection resistance observed",
      summary: "Some payloads were blocked but the defensive coverage may be incomplete across all attack categories.",
    });
  }
  if (/timeout|error|connection refused|500/i.test(outputs)) {
    findings.push({
      severity: "Low",
      title: "Endpoint reliability concerns",
      summary: "The endpoint returned errors or timeouts during scan execution which may affect security posture assessment.",
    });
  }
  if (findings.length === 0) {
    findings.push({
      severity: "Info",
      title: "Scan completed without critical findings",
      summary: "No obvious prompt injection bypass was detected in the scan outputs. Review the full documents for details.",
    });
  }

  return findings;
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case "Critical": return "border-red-500/40 bg-red-500/10 text-red-400";
    case "High": return "border-orange-500/40 bg-orange-500/10 text-orange-400";
    case "Medium": return "border-yellow-500/40 bg-yellow-500/10 text-yellow-400";
    case "Low": return "border-blue-500/40 bg-blue-500/10 text-blue-400";
    default: return "border-white/10 bg-black text-white";
  }
}

export default function FindingsPage() {
  const { getToken } = useAuth();
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
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

  const findings = latestScan ? parseSeverityFromOutputs(latestScan.outputs) : [];

  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Findings"
          title="Security findings from scan results."
          description="This page surfaces severity-tagged findings from the latest scan, with module coverage and downloadable remediation documents for operator review."
        />

        {loading && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="text-sm text-slate-400 animate-pulse">Loading findings…</p>
          </div>
        )}

        {error && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="text-sm text-slate-400">{error}</p>
          </div>
        )}

        {latestScan && (
          <>
            <section className="grid gap-5 lg:grid-cols-3">
              {findings.map((item) => (
                <article
                  key={item.title}
                  className="rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]"
                >
                  <span className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] ${getSeverityColor(item.severity)}`}>
                    {item.severity}
                  </span>
                  <h2 className="mt-4 text-2xl font-semibold tracking-tight text-white">
                    {item.title}
                  </h2>
                  <p className="mt-3 text-sm leading-7 text-slate-300">{item.summary}</p>
                </article>
              ))}
            </section>

            <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                Remediation document
              </p>
              <pre className="mt-4 max-h-72 overflow-y-auto rounded-xl border border-white/10 bg-black p-4 text-xs leading-5 text-slate-200 whitespace-pre-wrap">
                {latestScan.remediation.slice(0, 3000)}
                {latestScan.remediation.length > 3000 ? "\n\n… (truncated — download full file)" : ""}
              </pre>
              <div className="mt-4 flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={() => downloadFile(latestScan.remediation, `boxai_remediation_${latestScan.id}.txt`)}
                  className="action-box action-box-gold px-4 py-3 text-sm font-medium text-white"
                >
                  Download remediation
                </button>
                <button
                  type="button"
                  onClick={() => downloadFile(latestScan.outputs, `boxai_outputs_${latestScan.id}.txt`)}
                  className="action-box action-box-cyan px-4 py-3 text-sm font-medium text-white"
                >
                  Download scan outputs
                </button>
              </div>
            </section>

            <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                Covered modules
              </p>
              <div className="mt-5 flex flex-wrap gap-3">
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
          </>
        )}
      </div>
    </AppShell>
  );
}