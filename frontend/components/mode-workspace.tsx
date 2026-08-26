"use client";

import { useUser, useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { moduleLabels, scanModes, type ModeId } from "@/lib/scan-data";

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

function sanitizeAuditLogInput(value: string) {
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
  if (modeId !== "auditLogs") {
    return value;
  }

  return sanitizeAuditLogInput(value);
}

function getAccentClass(modeId: ModeId) {
  switch (modeId) {
    case "awsIam":
      return "mode-accent-cyan";
    case "gcpIam":
      return "mode-accent-gold";
    case "costData":
      return "mode-accent-magenta";
    case "auditLogs":
      return "mode-accent-cyan";
    default:
      return "";
  }
}

export function ModeWorkspace() {
  const { user } = useUser();
  const { getToken } = useAuth();
  const [activeModeId, setActiveModeId] = useState<ModeId>(scanModes[0].id);
  const [drafts, setDrafts] = useState<Record<ModeId, string>>(createInitialDrafts);
  const [fileNames, setFileNames] = useState<Record<ModeId, string>>(createInitialFileNames);
  const [hasLoadedPersistedState, setHasLoadedPersistedState] = useState(false);
  const [scanTier, setScanTier] = useState<"small" | "avg" | "big">("small");
  const [isScanning, setIsScanning] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [llmProvider, setLlmProvider] = useState<"openai" | "anthropic" | "gemini">("openai");
  const [apiKeyStatus, setApiKeyStatus] = useState<"unverified" | "verifying" | "verified" | "error">("unverified");
  const [apiVerifyContext, setApiVerifyContext] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const storageKey = user ? `authmap:workspace:${user.id}` : null;

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
            auditLogs: sanitizeInput("auditLogs", restoredDrafts.auditLogs ?? current.auditLogs),
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
    const savedKey = window.sessionStorage.getItem("authmap_api_key");
    const savedProvider = window.sessionStorage.getItem("authmap_llm_provider");
    if (savedKey && savedProvider) {
      setApiKey(savedKey);
      setLlmProvider(savedProvider as "openai" | "anthropic" | "gemini");
      setApiKeyStatus("verified");
    }
  }, []);

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

  async function handleVerifyApiKey() {
    if (!apiKey.trim()) return;
    setApiKeyStatus("verifying");
    try {
      const token = await getToken();
      const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
      const res = await fetch(`${backendUrl}/keys/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ provider: llmProvider, api_key: apiKey.trim() }),
      });
      if (res.ok) {
        setApiKeyStatus("verified");
        setApiVerifyContext("API key validated successfully.");
        window.sessionStorage.setItem("authmap_api_key", apiKey.trim());
        window.sessionStorage.setItem("authmap_llm_provider", llmProvider);
      } else {
        setApiKeyStatus("error");
        setApiVerifyContext("Verification failed. Please check your key.");
      }
    } catch {
      setApiKeyStatus("error");
      setApiVerifyContext("Could not reach backend to verify the key.");
    }
  }

  async function handleRunScan() {
    if (apiKeyStatus !== "verified") {
      alert("Please configure and verify an LLM API Key first.");
      return;
    }
    let url = currentInput.trim();
    if (url.startsWith("Target URL: ")) {
       url = url.replace("Target URL: ", "").split("\n")[0].trim();
    }
    setIsScanning(true);
    try {
      const token = await getToken();
      const backendUrl = process.env.NODE_ENV === "development" ? "http://localhost:8000" : process.env.NEXT_PUBLIC_BACKEND_URL;
      const res = await fetch(`${backendUrl}/scan/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ 
          url: url, 
          tier: scanTier, 
          llm_provider: llmProvider, 
          api_key: apiKey.trim() 
        }),
      });
      if (!res.ok) {
         throw new Error("Failed to run scan.");
      }
      alert("Scan completed successfully! Results stored in the global documents.");
    } catch (e) {
      console.error(e);
      alert("Error running the scan.");
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <>
      <section className="mt-8 rounded-[2.2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_20px_54px_rgba(0,0,0,0.18)]">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Configuration
            </p>
            <h2 className="mt-2 text-[2rem] font-semibold tracking-[-0.04em] text-white">
              Analysis Engine Backend Setup
            </h2>
          </div>
          <p className="max-w-md text-sm leading-6 text-slate-300">
            A valid API key powers AuthMap's graph analysis and remediation generation. We verify it via a secure backend request. The key lives only in browser session memory.
          </p>
        </div>
        
        <div className="mt-6 flex flex-col gap-4 sm:flex-row sm:items-end">
          <div className="flex-1 space-y-2">
            <label className="text-sm font-medium text-slate-300 uppercase tracking-widest text-[0.65rem]">Select LLM Provider</label>
            <select 
              value={llmProvider}
              onChange={(e) => {
                setLlmProvider(e.target.value as any);
                setApiKeyStatus("unverified");
              }}
              className="w-full rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-white/20"
            >
              <option value="openai">OpenAI (gpt-4o)</option>
              <option value="anthropic">Anthropic (claude-3-5-sonnet)</option>
              <option value="gemini">Google (gemini-pro)</option>
            </select>
          </div>
          <div className="flex-[2] space-y-2">
            <label className="text-sm font-medium text-slate-300 uppercase tracking-widest text-[0.65rem]">Enter API Key (Kept in memory)</label>
            <div className="flex gap-3">
              <input 
                type="password"
                placeholder={`Paste your ${llmProvider} API Key here...`}
                value={apiKey}
                onChange={(e) => {
                  setApiKey(e.target.value);
                  setApiKeyStatus("unverified");
                }}
                className="flex-1 rounded-xl border border-white/10 bg-black/40 px-4 py-3 text-sm text-white outline-none focus:border-white/20"
              />
              <button 
                type="button"
                onClick={handleVerifyApiKey}
                disabled={!apiKey || apiKeyStatus === "verifying" || apiKeyStatus === "verified"}
                className={`rounded-xl px-5 py-3 text-sm font-bold uppercase tracking-wider text-white transition-opacity disabled:opacity-50 ${apiKeyStatus === "verified" ? "bg-green-600" : "bg-blue-600"}`}
              >
                {apiKeyStatus === "verifying" ? "Verifying..." : apiKeyStatus === "verified" ? "Verified ✓" : "Verify Key"}
              </button>
            </div>
          </div>
        </div>
        {apiVerifyContext && (
          <p className={`mt-3 text-sm ${apiKeyStatus === "error" ? "text-red-400" : "text-green-400"}`}>
            {apiVerifyContext}
          </p>
        )}
      </section>

      <section id="intake-workspace" className={`mt-8 grid gap-6 xl:grid-cols-[1.1fr_0.9fr] scroll-mt-24 ${apiKeyStatus !== "verified" ? "pointer-events-none opacity-50" : ""}`}>
      <div className="intake-hero space-y-6 rounded-[2.2rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.02))] p-6 shadow-[0_20px_54px_rgba(0,0,0,0.18)]">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="font-[family:var(--font-plex-mono)] text-[0.72rem] font-medium uppercase tracking-[0.24em] text-slate-400">
              Start here
            </p>
            <h2 className="mt-2 text-[2rem] font-semibold tracking-[-0.04em] text-white">
              Feed your cloud. Watch the attack graph light up.
            </h2>
          </div>
          <p className="max-w-md text-sm leading-6 text-slate-300">
            Choose one data source at a time below. AuthMap tracks which sources you've imported
            so you can build a complete multi-cloud picture across all four input types.
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
                Imported sources
              </p>
              <p className="mt-2 text-sm leading-6 text-slate-300">
                One data source is active at a time. This list tracks which cloud configs you've already imported.
              </p>
            </div>
            <span className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs font-medium text-white">
              {loadedInputCount}/{MAX_INPUT_TYPES} sources imported
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

            {activeMode.id === "awsIam" && (
              <div className="mt-4 rounded-[1.2rem] border border-white/10 bg-white/[0.04] px-4 py-4 w-full">
                <p className="font-[family:var(--font-plex-mono)] text-[0.68rem] font-medium uppercase tracking-[0.24em] text-slate-400">
                  Analysis Depth
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => setScanTier("small")}
                    className={`rounded-lg border px-3 py-2 text-xs font-medium transition ${
                      scanTier === "small" ? "border-[var(--accent-gold)] bg-[var(--accent-gold)]/10 text-white" : "border-white/10 text-slate-400 hover:text-white hover:border-white/20"
                    }`}
                  >
                    Quick (Top risks, ~100 entities)
                  </button>
                  <button
                    type="button"
                    onClick={() => setScanTier("avg")}
                    className={`rounded-lg border px-3 py-2 text-xs font-medium transition ${
                      scanTier === "avg" ? "border-[var(--accent-gold)] bg-[var(--accent-gold)]/10 text-white" : "border-white/10 text-slate-400 hover:text-white hover:border-white/20"
                    }`}
                  >
                    Standard (Full graph, ~1k entities)
                  </button>
                  <button
                    type="button"
                    onClick={() => setScanTier("big")}
                    className={`rounded-lg border px-3 py-2 text-xs font-medium transition ${
                      scanTier === "big" ? "border-[var(--accent-gold)] bg-[var(--accent-gold)]/10 text-white" : "border-white/10 text-slate-400 hover:text-white hover:border-white/20"
                    }`}
                  >
                    Deep (Audit-grade, ~15k entities)
                  </button>
                </div>
              </div>
            )}

            <div className="mt-4 flex flex-wrap gap-3">
              {activeMode.id === "awsIam" && (
                <button
                  type="button"
                  onClick={handleRunScan}
                  disabled={isScanning || !currentInput.trim()}
                  className="action-box action-box-gold px-4 py-3 text-sm font-medium text-white disabled:opacity-50"
                >
                  {isScanning ? "Analyzing..." : "Run Analysis"}
                </button>
              )}
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
                  ? activeMode.id === "auditLogs"
                    ? "Audit logs captured and normalized. Analysis pipeline ready for this data source."
                    : "Cloud config imported. Analysis pipeline updates for this data source."
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
              <p className="text-xs text-slate-300">6-step analysis pipeline for the active data source</p>
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
                Findings, compliance reports, and remediation plans.
              </h3>
            </div>
          </div>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link
              href="/findings"
              className="action-box action-box-cyan px-4 py-3 text-sm font-medium text-white"
            >
              View IAM findings
            </Link>
            <Link
              href="/reports"
              className="action-box action-box-gold px-4 py-3 text-sm font-medium text-white"
            >
              Download reports
            </Link>
            <Link
              href="/"
              className="action-box action-box-magenta px-4 py-3 text-sm font-medium text-white"
            >
              Back to dashboard
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
    </>
  );
}
