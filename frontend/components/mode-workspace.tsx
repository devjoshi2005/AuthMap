"use client";

import { useUser } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { moduleLabels, scanModes, type ModeId } from "@/lib/demo-data";

const MAX_INPUT_TYPES = 4;

function createInitialDrafts() {
  return Object.fromEntries(scanModes.map((mode) => [mode.id, ""])) as Record<
    ModeId,
    string
  >;
}

function createInitialFileNames() {
  return Object.fromEntries(scanModes.map((mode) => [mode.id, ""])) as Record<
    ModeId,
    string
  >;
}

function sanitizeModelCardInput(value: string) {
  return value
    .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/javascript:/gi, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/\r\n/g, "\n")
    .replace(/\n{4,}/g, "\n\n\n")
    .slice(0, 12000);
}

function sanitizeInput(modeId: ModeId, value: string) {
  if (modeId !== "modelCard") {
    return value;
  }

  return sanitizeModelCardInput(value);
}

function getAccentClass(modeId: ModeId) {
  switch (modeId) {
    case "config":
      return "mode-accent-cyan";
    case "endpoint":
      return "mode-accent-gold";
    case "code":
      return "mode-accent-magenta";
    case "modelCard":
      return "mode-accent-cyan";
    default:
      return "";
  }
}

export function ModeWorkspace() {
  const { user } = useUser();
  const [activeModeId, setActiveModeId] = useState<ModeId>(scanModes[0].id);
  const [drafts, setDrafts] = useState<Record<ModeId, string>>(createInitialDrafts);
  const [fileNames, setFileNames] = useState<Record<ModeId, string>>(createInitialFileNames);
  const [hasLoadedPersistedState, setHasLoadedPersistedState] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const storageKey = user ? `boxai:workspace:${user.id}` : null;

  const activeMode =
    scanModes.find((mode) => mode.id === activeModeId) ?? scanModes[0];
  const currentInput = drafts[activeMode.id];
  const hasInput = currentInput.trim().length > 0;
  const providedModes = scanModes.filter(
    (mode) => drafts[mode.id].trim().length > 0 || fileNames[mode.id].trim().length > 0,
  );
  const loadedInputCount = providedModes.length;

  useEffect(() => {
    if (!storageKey) {
      setHasLoadedPersistedState(true);
      return;
    }

    try {
      const savedState = window.localStorage.getItem(storageKey);

      if (savedState) {
        const parsedState = JSON.parse(savedState) as {
          activeModeId?: ModeId;
          selectedModeId?: ModeId;
          drafts?: Record<ModeId, string>;
          fileNames?: Record<ModeId, string>;
        };

        if (parsedState.activeModeId && scanModes.some((mode) => mode.id === parsedState.activeModeId)) {
          setActiveModeId(parsedState.activeModeId);
        } else if (
          parsedState.selectedModeId &&
          scanModes.some((mode) => mode.id === parsedState.selectedModeId)
        ) {
          setActiveModeId(parsedState.selectedModeId);
        }

        if (parsedState.drafts) {
          const restoredDrafts = parsedState.drafts;

          setDrafts((current) => ({
            ...current,
            ...restoredDrafts,
            modelCard: sanitizeInput("modelCard", restoredDrafts.modelCard ?? current.modelCard),
          }));
        }

        if (parsedState.fileNames) {
          setFileNames((current) => ({ ...current, ...parsedState.fileNames }));
        }
      }
    } catch (error) {
      console.error(error);
    } finally {
      setHasLoadedPersistedState(true);
    }
  }, [storageKey]);

  useEffect(() => {
    if (!storageKey || !hasLoadedPersistedState) {
      return;
    }

    window.localStorage.setItem(
      storageKey,
      JSON.stringify({
        activeModeId,
        drafts,
        fileNames,
      }),
    );
  }, [activeModeId, drafts, fileNames, hasLoadedPersistedState, storageKey]);

  function updateDraft(nextValue: string) {
    setDrafts((current) => ({
      ...current,
      [activeMode.id]: sanitizeInput(activeMode.id, nextValue),
    }));
  }

  function loadSample() {
    updateDraft(activeMode.sampleInput);
  }

  function clearDraft() {
    updateDraft("");
    setFileNames((current) => ({ ...current, [activeMode.id]: "" }));
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
      [activeMode.id]: file.name,
    }));

    event.target.value = "";
  }

  return (
    <section id="intake-workspace" className="mt-8 grid gap-6 xl:grid-cols-[1.1fr_0.9fr] scroll-mt-24">
      <div className="intake-hero space-y-6 rounded-[2.2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_20px_54px_rgba(0,0,0,0.18)]">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Start here
            </p>
            <h2 className="mt-2 text-[2rem] font-semibold tracking-[-0.04em] text-white">
              Seal your OpenClaw agent inside BoxAI.
            </h2>
          </div>
          <p className="max-w-md text-sm leading-6 text-slate-300">
            Choose one input type at a time in the box below. BoxAI keeps a short list of
            which sources you already provided so you can build up to four inputs without crowding the screen.
          </p>
        </div>
        <div className="grid gap-3 lg:grid-cols-4">
          {scanModes.map((mode) => {
            const isActive = mode.id === activeMode.id;
            const accentClass = getAccentClass(mode.id);
            const hasProvidedInput = drafts[mode.id].trim().length > 0 || fileNames[mode.id].trim().length > 0;

            return (
              <button
                key={mode.id}
                type="button"
                onClick={() => setActiveModeId(mode.id)}
                className={`mode-card ${accentClass} rounded-[1.5rem] border p-4 text-left transition-colors ${
                  isActive
                    ? "border-white/24 bg-white/[0.1] text-white shadow-[0_12px_30px_rgba(255,255,255,0.04)]"
                    : "border-white/10 bg-white/[0.03] text-white hover:border-white/18 hover:bg-white/[0.05]"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.22em] opacity-72">
                      {mode.label}
                    </p>
                    <h2 className="mt-2 text-xl font-semibold tracking-[-0.03em]">{mode.title}</h2>
                  </div>
                  
                </div>
                <p className="mt-3 text-sm leading-6 opacity-90">{mode.format}</p>
                <p className="mt-3 text-xs leading-5 text-slate-300">
                  {hasProvidedInput ? "Already provided" : "Choose to add this input next"}
                </p>
              </button>
            );
          })}
        </div>

        <div className="rounded-[1.6rem] border border-white/10 bg-[rgba(11,14,18,0.72)] p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                Provided inputs
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                One input box stays active at a time. This list only records which source types you have already filled in.
              </p>
            </div>
            <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-medium text-white">
              {loadedInputCount}/{MAX_INPUT_TYPES} inputs provided
            </span>
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            {providedModes.length > 0 ? (
              providedModes.map((mode, index) => (
                <button
                  key={mode.id}
                  type="button"
                  onClick={() => setActiveModeId(mode.id)}
                  className={`rounded-full border px-4 py-2 text-sm font-medium transition ${
                    mode.id === activeMode.id
                      ? "border-white/20 bg-white/[0.1] text-white"
                      : "border-white/10 bg-black text-slate-200 hover:text-white"
                  }`}
                >
                  {index + 1}. {mode.title}
                </button>
              ))
            ) : (
              <p className="text-sm leading-6 text-slate-400">
                No input added yet. Choose a type above and paste one source to start.
              </p>
            )}
          </div>
        </div>

        <div>
          <div className="input-stage rounded-[1.85rem] border border-white/10 bg-[rgba(11,14,18,0.82)] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
            <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Input
            </p>
            <h3 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-white">
              {activeMode.title}
            </h3>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              {activeMode.description}
            </p>
            <div className="mt-4 rounded-[1.2rem] border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-slate-200">
              <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.22em] text-slate-400">
                Module fit
              </p>
              <p className="mt-2 leading-6">{activeMode.coverageSummary}</p>
            </div>
            
            <label className="mt-5 block text-sm font-medium text-slate-200">
              {activeMode.inputLabel}
            </label>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-slate-400">
              <span>Paste directly</span>
              {activeMode.allowsFileUpload ? <span>or upload a file</span> : null}
              {fileNames[activeMode.id] ? (
                <span className="rounded-full border border-white/10 bg-white/[0.05] px-3 py-1 text-xs text-white">
                  {fileNames[activeMode.id]}
                </span>
              ) : null}
            </div>
            <textarea
              value={currentInput}
              onChange={(event) => updateDraft(event.target.value)}
              placeholder={activeMode.placeholder}
              className="mt-2 min-h-56 w-full rounded-[1.45rem] border border-white/12 bg-white/[0.03] px-4 py-4 text-sm leading-6 text-white outline-none transition placeholder:text-slate-500 focus:border-[var(--accent-cyan)] focus:bg-white/[0.05]"
            />
            {activeMode.allowsFileUpload ? (
              <input
                ref={fileInputRef}
                type="file"
                accept={activeMode.fileAccept}
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
              {activeMode.allowsFileUpload ? (
                <button
                  type="button"
                  onClick={openFilePicker}
                  className="action-box action-box-ghost px-4 py-3 text-sm font-medium text-white"
                >
                  Upload file
                </button>
              ) : null}
            </div>
            <div className="mt-5 rounded-[1.45rem] border border-white/10 bg-white/[0.04] px-4 py-4 text-sm text-slate-100">
              <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                Input state
              </p>
              <p className="mt-2 leading-6 text-slate-100">
                {hasInput
                  ? activeMode.id === "modelCard"
                    ? "Model card captured and sanitized. Execution preview updates for this input type."
                    : "User sample captured. Execution preview updates for this input type."
                  : activeMode.emptyHint}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-6">
        <aside className="rounded-[2.2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 text-slate-100 shadow-[0_20px_60px_rgba(0,0,0,0.18)]">
          <div className="flex items-center justify-between gap-3 border-b border-white/10 pb-4">
            <div>
              <p className="text-sm font-medium text-slate-100">Output execution</p>
              <p className="text-xs text-slate-300">Nine-step security pipeline for the active input</p>
            </div>
            <span className="rounded-full border border-[var(--accent-cyan)]/36 bg-[rgba(158,193,182,0.14)] px-3 py-1.5 text-xs font-semibold text-white shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
              {loadedInputCount > 0 ? `${loadedInputCount} loaded` : "Dry preview"}
            </span>
          </div>
          <div className="mt-4 rounded-[1.35rem] border border-white/10 bg-[rgba(11,14,18,0.72)] px-4 py-4 text-sm text-slate-200">
            <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.22em] text-slate-400">
              Current focus
            </p>
            <p className="mt-2 text-base font-semibold text-white">{activeMode.title}</p>
            <p className="mt-2 leading-6 text-slate-300">{activeMode.coverageSummary}</p>
          </div>
          <div className="mt-5 space-y-3">
            {activeMode.stepOutputs.map((item, index) => (
              <div
                key={item.step}
                className="pipeline-card rounded-[1.5rem] border border-white/8 bg-[rgba(11,14,18,0.82)] px-4 py-4"
              >
                <div className="flex items-center justify-between gap-3">
                  <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.22em] text-slate-300">
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

        <section className="rounded-[2.2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_18px_50px_rgba(0,0,0,0.16)]">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                Next screens
              </p>
              <h3 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-white">
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