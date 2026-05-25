'use-server';

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { ScreenHeader } from "@/components/screen-header";
import { scanModes } from "@/lib/scan-data";

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

export default function ScanDetailsPage() {
  const { getToken } = useAuth();
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const defaultMode = scanModes[0];

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

  return (
    <AppShell>
      <div className="space-y-8 pb-10">
        <ScreenHeader
          eyebrow="Scan details"
          title="A compact scan session view."
          description="This screen shows the current session shape, guardrails, and the nine-step timeline from module checks through compliance, remediation, and report handoff."
        />

        {loading && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="text-sm text-slate-400 animate-pulse">Loading scan data…</p>
          </div>
        )}

        {error && (
          <div className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-6">
            <p className="text-sm text-slate-400">{error}</p>
          </div>
        )}

        {latestScan && (
          <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
            <div className="grid gap-4">
              <article className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-5 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                  Target endpoint
                </p>
                <h2 className="mt-2 text-2xl font-semibold tracking-tight text-white break-all">
                  {latestScan.scan_url}
                </h2>
                <p className="mt-3 text-sm leading-7 text-slate-300">
                  Scanned with <span className="font-semibold text-white">{latestScan.tier}</span> tier prompt injection payloads.
                </p>
              </article>

              <article className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-5 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                  Scan outputs
                </p>
                <pre className="mt-3 max-h-60 overflow-y-auto rounded-xl border border-white/10 bg-black p-4 text-xs leading-5 text-slate-200 whitespace-pre-wrap">
                  {latestScan.outputs.slice(0, 2000)}
                  {latestScan.outputs.length > 2000 ? "\n\n… (truncated — download full file)" : ""}
                </pre>
                <button
                  type="button"
                  onClick={() => downloadFile(latestScan.outputs, `boxai_outputs_${latestScan.id}.txt`)}
                  className="action-box action-box-cyan mt-4 px-4 py-3 text-sm font-medium text-white"
                >
                  Download outputs document
                </button>
              </article>

              <article className="rounded-[1.6rem] border border-white/10 bg-white/[0.03] p-5 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
                <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                  Remediation
                </p>
                <pre className="mt-3 max-h-60 overflow-y-auto rounded-xl border border-white/10 bg-black p-4 text-xs leading-5 text-slate-200 whitespace-pre-wrap">
                  {latestScan.remediation.slice(0, 2000)}
                  {latestScan.remediation.length > 2000 ? "\n\n… (truncated — download full file)" : ""}
                </pre>
                <button
                  type="button"
                  onClick={() => downloadFile(latestScan.remediation, `boxai_remediation_${latestScan.id}.txt`)}
                  className="action-box action-box-gold mt-4 px-4 py-3 text-sm font-medium text-white"
                >
                  Download remediation document
                </button>
              </article>
            </div>

            <section className="rounded-[1.9rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                Timeline
              </p>
              <h2 className="mt-2 text-3xl font-semibold tracking-tight text-white">
                {defaultMode.title} pipeline
              </h2>
              <div className="mt-6 space-y-4">
                {defaultMode.stepOutputs.map((item) => (
                  <div
                    key={item.step}
                    className="flex gap-4 rounded-[1.4rem] border border-white/10 bg-black p-4"
                  >
                    <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-white text-sm font-semibold text-black">
                      {item.step}
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-white">{item.title}</h3>
                      <p className="mt-1 text-sm leading-6 text-slate-300">{item.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </section>
        )}
      </div>
    </AppShell>
  );
}