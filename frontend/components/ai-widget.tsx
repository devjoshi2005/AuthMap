"use client";

import { useState, useEffect, useRef } from "react";
import { useAuth } from "@clerk/nextjs";
import { useRouter } from "next/navigation";
import {
  X,
  Maximize2,
  Send,
  Loader2,
  Check,
  Copy,
  ArrowRight,
  RotateCcw,
  Database,
} from "lucide-react";
import { MarkdownMessage } from "@/components/markdown-message";
import { clientRAGEngine } from "@/lib/rag/client-rag-engine";

interface Message {
  role: "user" | "assistant";
  content: string;
  modelUsed?: string;
  timestamp?: string;
  image_base64?: string;
}

const QUICK_PROMPTS = [
  "Which IAM roles have full AdministratorAccess?",
  "Show the highest risk privilege escalation paths",
  "How can we achieve compliance for SOC 2 & DPDP?",
  "What is our estimated breach cost exposure?",
];

// 20b returned blank completions; the consultant is pinned to 120b.
const CURATED_MODELS = [
  { id: "openai/gpt-oss-120b", label: "Complex (120B)", desc: "Deep multi-step reasoning for IAM escalation" },
];

export function AIWidget() {
  const { getToken, isLoaded } = useAuth();
  const router = useRouter();
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [selectedModel, setSelectedModel] = useState<string>("openai/gpt-oss-120b");
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [attachedImage, setAttachedImage] = useState<string | null>(null);
  const [pasteError, setPasteError] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const items = e.clipboardData?.items;
    if (!items) return;

    for (let i = 0; i < items.length; i++) {
      if (items[i].type.indexOf("image") !== -1) {
        const file = items[i].getAsFile();
        if (file) {
          if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
            setPasteError("Please upload an image in PNG, JPEG, or WEBP format.");
            setTimeout(() => setPasteError(""), 5000);
            return;
          }
          
          setPasteError("");
          
          const url = URL.createObjectURL(file);
          const img = new Image();
          img.onload = () => {
            const canvas = document.createElement("canvas");
            let width = img.width;
            let height = img.height;
            const MAX_DIM = 512;
            
            if (width > MAX_DIM || height > MAX_DIM) {
              if (width > height) {
                height = Math.round((height * MAX_DIM) / width);
                width = MAX_DIM;
              } else {
                width = Math.round((width * MAX_DIM) / height);
                height = MAX_DIM;
              }
            }

            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext("2d");
            if (ctx) {
              ctx.filter = "blur(1px)";
              ctx.drawImage(img, 0, 0, width, height);
              const dataUrl = canvas.toDataURL("image/jpeg", 0.75);
              setAttachedImage(dataUrl);
            }
            URL.revokeObjectURL(url);
          };
          img.src = url;
        }
      }
    }
  };

  // Lazy-load the heavy client-side ML Web Worker only when the widget is explicitly opened
  useEffect(() => {
    if (isOpen) {
      clientRAGEngine.init().catch((err) => console.error("Client RAG failed to init:", err));
    }
  }, [isOpen]);

  useEffect(() => {
    try {
      const saved = sessionStorage.getItem("boxai_chat_history");
      if (saved) {
        setMessages(JSON.parse(saved));
      } else {
        setMessages([
          {
            role: "assistant",
            content:
              "Hello! I am your **AuthMap AI Security Consultant**.\n\nAsk me anything about your live graph topology, overprivileged trust chains, blast radius minimization, or compliance remediation steps.",
            modelUsed: "openai/gpt-oss-120b",
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          },
        ]);
      }
    } catch (e) {}
  }, []);

  useEffect(() => {
    if (messages.length > 0) {
      try {
        sessionStorage.setItem("boxai_chat_history", JSON.stringify(messages));
      } catch (e) {}
    }
  }, [messages]);

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isOpen]);

  const handleSend = async (textToSend?: string) => {
    const text = textToSend || input.trim();
    if (!text || loading || !isLoaded) return;

    const timeStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const newMessages: Message[] = [...messages, { 
      role: "user", 
      content: text, 
      timestamp: timeStr,
      image_base64: attachedImage || undefined
    }];
    setMessages(newMessages);
    if (!textToSend) setInput("");
    setLoading(true);

    try {
      const token = await getToken();

      const savedCreds = localStorage.getItem("boxai_scan_creds");
      let neo4jCreds: Record<string, string> = {};
      if (savedCreds) {
        try {
          const data = JSON.parse(savedCreds);
          if (data.neo4jUri) neo4jCreds.neo4j_uri = data.neo4jUri;
          if (data.neo4jUser) neo4jCreds.neo4j_username = data.neo4jUser;
          if (data.neo4jPassword) neo4jCreds.neo4j_password = data.neo4jPassword;
        } catch (e) {}
      }

      const lastScanId = sessionStorage.getItem("boxai_last_scan_id") || undefined;
      let scanConfig = undefined;
      try {
        const savedConfig = sessionStorage.getItem("boxai_scan_config");
        if (savedConfig) scanConfig = JSON.parse(savedConfig);
      } catch (e) {}

      // Retrieve local context from Client RAG (Transformers.js + IndexedDB)
      let clientRagContext: any[] = [];
      try {
        const searchResults = await clientRAGEngine.retrieveContext(text, 3);
        clientRagContext = searchResults.map((r) => ({
          title: r.chunk.title,
          content: r.chunk.content,
          framework: r.chunk.framework,
          control_id: r.chunk.control_id,
          remediation: r.chunk.remediation,
          category: r.chunk.category,
          score: r.score,
        }));
      } catch (ragErr) {
        console.warn("Client RAG retrieval in widget skipped:", ragErr);
      }

      const res = await fetch("/api/ai/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          query: text,
          model_name: selectedModel,
          history: messages.map((m) => ({ role: m.role, content: m.content })),
          scan_id: lastScanId,
          scan_config: scanConfig,
          client_rag_context: clientRagContext.length > 0 ? clientRagContext : undefined,
          stream: true,
          image_base64: attachedImage || undefined,
          ...neo4jCreds,
        }),
      });

      setAttachedImage(null);

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server returned status ${res.status}`);
      }

      if (!res.body) throw new Error("No response body");
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let done = false;
      let accumulatedResponse = "";
      let modelUsed = selectedModel;

      setMessages([
        ...newMessages,
        {
          role: "assistant",
          content: "",
          modelUsed,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);

      while (!done) {
        const { value, done: readerDone } = await reader.read();
        done = readerDone;
        if (value) {
          const chunkStr = decoder.decode(value, { stream: true });
          const parts = chunkStr.split("\n\n");
          for (const part of parts) {
            if (!part.trim()) continue;
            try {
              const parsed = JSON.parse(part);
              if (parsed.type === "meta") {
                modelUsed = parsed.model || selectedModel;
              } else if (parsed.type === "chunk") {
                accumulatedResponse += parsed.text;
                setMessages((prev) => {
                  const msgs = [...prev];
                  msgs[msgs.length - 1] = {
                    ...msgs[msgs.length - 1],
                    content: accumulatedResponse,
                    modelUsed,
                  };
                  return msgs;
                });
              } else if (parsed.type === "done") {
                done = true;
              }
            } catch (e) {}
          }
        }
      }
    } catch (err: any) {
      setMessages([
        ...newMessages,
        {
          role: "assistant",
          content: `AI Assistant Warning: ${err.message || "Failed to fetch response."}`,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (content: string, idx: number) => {
    navigator.clipboard.writeText(content);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const openFullScreen = () => {
    try {
      sessionStorage.setItem("boxai_chat_history", JSON.stringify(messages));
      sessionStorage.setItem("boxai_chat_transfer_from_widget", "true");
    } catch (e) {}
    router.push("/ask");
  };

  const clearChat = () => {
    setMessages([
      {
        role: "assistant",
        content:
          "Hello! I am your **AuthMap AI Security Consultant**.\n\nAsk me anything about your live graph topology, overprivileged trust chains, blast radius minimization, or compliance remediation steps.",
        modelUsed: selectedModel,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      },
    ]);
  };

  return (
    <div className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-50">
      {/* ── Floating Trigger Button (ChatGPT / Horizon Style) ── */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="group relative flex items-center gap-3 rounded-full border border-white/15 bg-[#181818]/95 px-4 py-2.5 text-white shadow-[0_12px_40px_rgba(0,0,0,0.6)] backdrop-blur-xl transition-all duration-200 hover:scale-[1.03] hover:border-white/30 hover:bg-[#222222] active:scale-95"
          title="Open AuthMap AI Consultant"
        >
          {/* White AM Logo Avatar */}
          <div className="relative flex h-8 w-8 items-center justify-center rounded-full bg-white text-black font-bold text-[0.72rem] shadow-sm transition group-hover:bg-white/90">
            AM
            {/* Live Indicator Dot */}
            <span className="absolute -bottom-0.5 -right-0.5 flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500 border border-[#181818]"></span>
            </span>
          </div>

          <div className="flex flex-col text-left pr-1">
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-semibold text-white tracking-tight">AuthMap AI</span>
              <span className="rounded-full bg-white/10 px-1.5 py-0.2 text-[0.58rem] font-medium text-white/80">
                Online
              </span>
            </div>
            <span className="text-[0.65rem] text-[#999999]">Ask AI Consultant</span>
          </div>
        </button>
      )}

      {/* ── Floating Assistant Drawer (Modern ChatGPT Aesthetic) ── */}
      {isOpen && (
        <div
          className="flex h-[calc(100vh-8rem)] w-[calc(100vw-2rem)] sm:h-[38rem] sm:w-[28rem] flex-col overflow-hidden rounded-2xl border border-white/15 bg-[#181818] text-[#ececec] shadow-[0_25px_70px_rgba(0,0,0,0.85)] backdrop-blur-2xl transition-all duration-200"
          style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif' }}
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-white/10 bg-[#1e1e1e] px-4 py-3">
            <div className="flex items-center gap-2.5">
              {/* White AM Logo */}
              <div className="flex h-7 w-7 items-center justify-center rounded-full bg-white text-black font-bold text-xs shadow-sm">
                AM
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <h2 className="text-xs font-semibold text-white tracking-tight">
                    AuthMap AI
                  </h2>
                  <span className="rounded-md border border-white/20 bg-white/10 px-1.5 py-0.5 text-[0.6rem] font-medium text-white">
                    Assistant
                  </span>
                </div>
                <p className="text-[0.62rem] text-[#999999]">
                  Live Supabase & Neo4j Connected
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={clearChat}
                className="rounded-lg p-1.5 text-[#999999] transition hover:bg-white/10 hover:text-white"
                title="Reset conversation"
              >
                <RotateCcw className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={openFullScreen}
                className="rounded-lg p-1.5 text-[#999999] transition hover:bg-white/10 hover:text-white"
                title="Expand to Full Screen (/ask)"
              >
                <Maximize2 className="h-3.5 w-3.5" />
              </button>
              <button
                onClick={() => setIsOpen(false)}
                className="rounded-lg p-1.5 text-[#999999] transition hover:bg-white/10 hover:text-white"
                title="Close Drawer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* 3-Model Manual Selection Bar (High Contrast, Human-Designed) */}
          <div className="flex items-center justify-between border-b border-white/10 bg-[#141414] px-4 py-2.5">
            <span className="text-[0.68rem] font-medium text-[#8e8e8e]">Model</span>
            <div className="flex items-center rounded-xl bg-[#242424] p-1 border border-white/5">
              {CURATED_MODELS.map((m) => {
                const isSelected = selectedModel === m.id;
                return (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => setSelectedModel(m.id)}
                    style={
                      isSelected
                        ? { color: "#000000", backgroundColor: "#ffffff" }
                        : { color: "#a1a1aa", backgroundColor: "transparent" }
                    }
                    className={`rounded-lg px-2.5 py-1 text-[0.68rem] transition-all duration-150 ${
                      isSelected
                        ? "!text-black !bg-white font-bold shadow-sm"
                        : "!text-zinc-400 hover:!text-white hover:bg-white/[0.05] font-medium"
                    }`}
                    title={m.desc}
                  >
                    {m.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Messages Feed */}
          <div className="chat-scroll flex-1 overflow-y-auto overflow-x-hidden p-4 space-y-4 bg-[#181818]">
            {messages.map((m, idx) => {
              const isUser = m.role === "user";
              return (
                <div key={idx} className="space-y-1.5">
                  {/* Avatar & Sender Info */}
                  <div className="flex items-center justify-between text-[0.68rem] text-[#999999] px-1">
                    <div className="flex items-center gap-1.5">
                      {!isUser ? (
                        <div className="flex h-4 w-4 items-center justify-center rounded-full bg-white text-black font-bold text-[0.55rem]">
                          AM
                        </div>
                      ) : null}
                      <span className="font-semibold text-white/90">
                        {isUser ? "You" : "AuthMap AI"}
                      </span>
                    </div>
                    {m.timestamp && <span>{m.timestamp}</span>}
                  </div>

                  {/* Message Bubble */}
                  <div
                    className={`rounded-2xl p-3.5 text-[0.82rem] leading-relaxed ${
                      isUser
                        ? "ml-auto max-w-[85%] bg-[#2f2f2f] text-white border border-white/5"
                        : "w-full bg-[#212121] border border-white/10 text-[#ececec]"
                    }`}
                  >
                    {isUser ? (
                      <div className="flex flex-col gap-2 whitespace-pre-wrap leading-relaxed">
                        {m.image_base64 && (
                          <img src={m.image_base64} alt="User attached" className="max-w-full rounded-xl object-contain max-h-[150px]" />
                        )}
                        {m.content}
                      </div>
                    ) : (
                      <MarkdownMessage content={m.content} size="sm" />
                    )}

                    {!isUser && (
                      <div className="mt-3 flex items-center justify-between border-t border-white/5 pt-2 text-[0.62rem] text-[#999999]">
                        <span className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[#b4b4b4]">
                          {m.modelUsed?.includes("120b") ? "120B Complex" : "120B Complex"}
                        </span>
                        <button
                          onClick={() => handleCopy(m.content, idx)}
                          className="flex items-center gap-1 rounded-md px-2 py-0.5 text-[#999999] hover:bg-white/10 hover:text-white transition"
                        >
                          {copiedIdx === idx ? (
                            <>
                              <Check className="h-3 w-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}

            {loading && (
              <div className="space-y-1.5">
                <div className="flex items-center gap-1.5 text-[0.68rem] text-[#999999] px-1">
                  <div className="flex h-4 w-4 items-center justify-center rounded-full bg-white text-black font-bold text-[0.55rem]">
                    AM
                  </div>
                  <span className="font-semibold text-white/90">AuthMap AI</span>
                </div>
                <div className="flex items-center gap-2.5 rounded-2xl border border-white/10 bg-[#212121] p-3 text-xs text-[#b4b4b4]">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-white" />
                  <span>Analyzing topology and synthesizing guidance...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompt Suggestions */}
          {messages.length <= 2 && (
            <div className="border-t border-white/5 bg-[#141414] p-3">
              <p className="mb-1.5 px-1 text-[0.62rem] font-semibold uppercase tracking-wider text-[#8e8e8e]">
                Suggested Questions
              </p>
              <div className="grid grid-cols-1 gap-1.5">
                {QUICK_PROMPTS.map((q, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSend(q)}
                    className="flex items-center justify-between rounded-xl border border-white/10 bg-[#1e1e1e] px-3 py-1.5 text-left text-[0.55rem] text-[#ececec] transition hover:border-white/30 hover:bg-[#282828] hover:text-white active:scale-[0.99]"
                  >
                    <span className="truncate leading-relaxed">{q}</span>
                    <ArrowRight className="h-3 w-3 shrink-0 text-[#8e8e8e] ml-1.5" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Input Pill Bar */}
          <div className="border-t border-white/10 bg-[#1e1e1e] p-3 flex flex-col gap-2">
            {pasteError && (
              <div className="text-red-400 text-[0.65rem] font-semibold px-3 py-1 bg-red-400/10 border border-red-400/20 rounded-md self-start ml-2 mb-1">
                {pasteError}
              </div>
            )}
            {attachedImage && (
              <div className="relative w-12 h-12 rounded-lg overflow-hidden border border-white/20 bg-[#2f2f2f] self-start ml-2">
                <img src={attachedImage} alt="Attachment preview" className="w-full h-full object-cover" />
                <button
                  type="button"
                  onClick={() => setAttachedImage(null)}
                  className="absolute top-0.5 right-0.5 bg-black/60 rounded-full p-0.5 text-white hover:bg-black transition"
                >
                  <X className="h-2 w-2" />
                </button>
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="flex items-center gap-2 rounded-full border border-white/15 bg-[#2a2a2a] px-3 py-1.5 focus-within:border-white/40 focus-within:bg-[#2f2f2f] transition"
            >
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onPaste={handlePaste}
                placeholder="Ask about IAM, or paste an image..."
                disabled={loading}
                className="flex-1 bg-transparent text-xs text-[#ececec] placeholder:text-[#8e8e8e] focus:outline-none px-1"
              />
              <button
                type="submit"
                disabled={loading || (!input.trim() && !attachedImage)}
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-white text-black transition hover:bg-white/90 disabled:opacity-20 active:scale-95 shadow-sm"
                title="Send query"
              >
                <Send className="h-3.5 w-3.5" />
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
