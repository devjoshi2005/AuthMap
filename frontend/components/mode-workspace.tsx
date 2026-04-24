"use client";

import Link from "next/link";
import { useRef, useState } from "react";

import { moduleLabels, scanModes, type ModeId } from "@/lib/demo-data";

function createInitialDrafts() {
  return Object.fromEntries(scanModes.map((mode) => [mode.id, ""])) as Record<
    ModeId,
    string
  >;
}

export function ModeWorkspace() {
  const [selectedModeId, setSelectedModeId] = useState<ModeId>(scanModes[0].id);
  const [drafts, setDrafts] = useState<Record<ModeId, string>>(createInitialDrafts);
  const [fileNames, setFileNames] = useState<Record<ModeId, string>>({
    config: "",
    endpoint: "",
    code: "",
  });
  const fileInputRef = useRef<HTMLInputElement>(null);

  const selectedMode =
    scanModes.find((mode) => mode.id === selectedModeId) ?? scanModes[0];
  const currentInput = drafts[selectedMode.id];
  const hasInput = currentInput.trim().length > 0;

  function updateDraft(nextValue: string) {
    setDrafts((current) => ({
      ...current,
      [selectedMode.id]: nextValue,
    }));
  }

  function loadSample() {
    updateDraft(selectedMode.sampleInput);
  }

  function clearDraft() {
    updateDraft("");
    setFileNames((current) => ({ ...current, [selectedMode.id]: "" }));
  }

  function openFilePicker() {
    fileInputRef.current?.click();
  }

  async function handleFileChange(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    const fileText = await file.text();

    updateDraft(fileText);
    setFileNames((current) => ({
      ...current,
      [selectedMode.id]: file.name,
    }));

    event.target.value = "";
  }

  return (
    <section id="intake-workspace" className="mt-8 grid gap-6 xl:grid-cols-[1.1fr_0.9fr] scroll-mt-24">
      <div className="intake-hero space-y-6 rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.3)]">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
              Start here
            </p>
            <h2 className="mt-2 text-2xl font-semibold text-white">
              Wrap your OpenClaw agent in ExoAI protection.
            </h2>
          </div>
          <p className="max-w-md text-sm leading-6 text-slate-300">
            Paste text, upload a file for config or code, or leave the field empty
            and still review the full eight-step output path.
          </p>
        </div>
        <div className="grid gap-3 lg:grid-cols-3">
          {scanModes.map((mode) => {
            const isActive = mode.id === selectedMode.id;
            const accentClass =
              mode.id === "config"
                ? "mode-accent-cyan"
                : mode.id === "endpoint"
                  ? "mode-accent-gold"
                  : "mode-accent-magenta";

            return (
              <button
                key={mode.id}
                type="button"
                onClick={() => setSelectedModeId(mode.id)}
                className={`mode-card ${accentClass} rounded-[1.25rem] border p-4 text-left transition-colors ${
                  isActive
                    ? "border-white/40 bg-white/[0.1] text-white shadow-[0_12px_30px_rgba(255,255,255,0.06)]"
                    : "border-white/10 bg-white/[0.04] text-white hover:border-white/20 hover:bg-white/[0.07]"
                }`}
              >
                <p className="text-xs font-semibold uppercase tracking-[0.24em] opacity-80">
                  {mode.label}
                </p>
                <h2 className="mt-2 text-xl font-semibold">{mode.title}</h2>
                <p className="mt-2 text-sm leading-6 opacity-90">{mode.format}</p>
              </button>
            );
          })}
        </div>

        <div>
          <div className="input-stage rounded-[1.65rem] border border-white/10 bg-black/90 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
            <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
              Input
            </p>
            <h3 className="mt-2 text-2xl font-semibold tracking-tight text-white">
              {selectedMode.title}
            </h3>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              {selectedMode.description}
            </p>
            <label className="mt-5 block text-sm font-medium text-slate-200">
              {selectedMode.inputLabel}
            </label>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-slate-400">
              <span>Paste directly</span>
              {selectedMode.allowsFileUpload ? <span>or upload a file</span> : null}
              {fileNames[selectedMode.id] ? (
                <span className="rounded-full border border-white/10 bg-white/[0.05] px-3 py-1 text-xs text-white">
                  {fileNames[selectedMode.id]}
                </span>
              ) : null}
            </div>
            <textarea
              value={currentInput}
              onChange={(event) => updateDraft(event.target.value)}
              placeholder={selectedMode.placeholder}
              className="mt-2 min-h-56 w-full rounded-[1.25rem] border border-white/12 bg-white/[0.04] px-4 py-4 text-sm leading-6 text-white outline-none transition placeholder:text-slate-500 focus:border-[var(--accent-cyan)] focus:bg-white/[0.06]"
            />
            {selectedMode.allowsFileUpload ? (
              <input
                ref={fileInputRef}
                type="file"
                accept={selectedMode.fileAccept}
                onChange={handleFileChange}
                className="hidden"
              />
            ) : null}
            <div className="mt-4 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={loadSample}
                className="action-box action-box-magenta px-4 py-3 text-sm font-medium text-white"
              >
                Load sample
              </button>
              <button
                type="button"
                onClick={clearDraft}
                className="action-box action-box-ghost px-4 py-3 text-sm font-medium text-white"
              >
                Clear
              </button>
              {selectedMode.allowsFileUpload ? (
                <button
                  type="button"
                  onClick={openFilePicker}
                  className="action-box action-box-ghost px-4 py-3 text-sm font-medium text-white"
                >
                  Upload file
                </button>
              ) : null}
            </div>
            <div className="mt-5 rounded-[1.3rem] border border-white/10 bg-white/[0.05] px-4 py-4 text-sm text-slate-100">
              <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-400">
                Input state
              </p>
              <p className="mt-2 leading-6 text-slate-100">
                {hasInput
                  ? "User sample captured. Execution preview updates for this mode only."
                  : selectedMode.emptyHint}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-6">
        <aside className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 text-slate-100 shadow-[0_20px_60px_rgba(0,0,0,0.28)]">
          <div className="flex items-center justify-between gap-3 border-b border-white/10 pb-4">
            <div>
              <p className="text-sm font-medium text-slate-100">Output execution</p>
              <p className="text-xs text-slate-300">Eight-step security pipeline</p>
            </div>
            <span className="rounded-[0.65rem] border border-[var(--accent-cyan)]/50 bg-[rgba(77,238,234,0.14)] px-3 py-1.5 text-xs font-semibold text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
              {hasInput ? "Sample loaded" : "Dry preview"}
            </span>
          </div>
          <div className="mt-5 space-y-3">
            {selectedMode.stepOutputs.map((item, index) => (
              <div
                key={item.step}
                className="pipeline-card rounded-[1.35rem] border border-white/8 bg-black px-4 py-4"
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-300">
                    Step {item.step}
                  </p>
                  <span className="text-xs text-slate-300">
                    {index === 0 && !hasInput ? "Preview only" : "Ready"}
                  </span>
                </div>
                <h3 className="mt-2 text-lg font-semibold text-white">{item.title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-200">{item.detail}</p>
                {item.href && item.ctaLabel ? (
                  <Link
                    href={item.href}
                    className="action-box action-box-magenta mt-4 inline-flex px-3 py-2 text-xs font-medium text-white"
                  >
                    {item.ctaLabel}
                  </Link>
                ) : null}
              </div>
            ))}
          </div>
        </aside>

        <section className="rounded-[2rem] border border-white/10 bg-white/[0.03] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.24)]">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-400">
                Next screens
              </p>
              <h3 className="mt-2 text-2xl font-semibold tracking-tight text-white">
                Detail, finding, and report views.
              </h3>
            </div>
          </div>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/scan-details"
              className="action-box action-box-cyan px-4 py-3 text-sm font-medium text-white"
            >
              Open scan details
            </Link>
            <Link
              href="/findings"
              className="action-box action-box-gold px-4 py-3 text-sm font-medium text-white"
            >
              Open findings
            </Link>
            <Link
              href="/reports"
              className="action-box action-box-magenta px-4 py-3 text-sm font-medium text-white"
            >
              Open reports
            </Link>
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            {moduleLabels.map((label) => (
              <span
                key={label}
                className="rounded-full border border-white/10 bg-black px-3 py-1.5 text-xs font-medium text-white"
              >
                {label}
              </span>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}