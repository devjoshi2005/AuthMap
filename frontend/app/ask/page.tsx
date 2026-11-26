"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import { useAuth, useUser, UserButton } from "@clerk/nextjs";
import { useRouter, usePathname } from "next/navigation";
import Link from "next/link";
import {
  Send,
  Loader2,
  Copy,
  Check,
  Plus,
  Trash2,
  ShieldCheck,
  Zap,
  Terminal,
  Scale,
  PanelLeftClose,
  PanelLeft,
  Search,
  MessageSquare,
  RotateCcw,
  ChevronDown,
  ArrowUp,
  Brain,
  Clock,
  X,
  CheckCircle2,
  Database,
  Cpu,
} from "lucide-react";
import { MarkdownMessage } from "@/components/markdown-message";
import { clientRAGEngine, EngineStatus } from "@/lib/rag/client-rag-engine";

interface Message {
  role: "user" | "assistant";
  content: string;
  modelUsed?: string;
  timestamp?: string;
  image_base64?: string;
}

interface Conversation {
  id: string;
  title: string;
  createdAt: number;
  messages: Message[];
  modelUsed?: string;
  expires_at?: string;
}

interface MemoryItem {
  id?: string;
  key: string;
  content: string;
  category: string;
  source?: string;
  created_at?: string;
  updated_at?: string;
}

const PROMPT_SUGGESTIONS = [
  {
    title: "SOC 2 & DPDP Compliance Audit",
    category: "Compliance",
    description: "Audit multi-cloud IAM configurations against SOC 2 CC6.1-CC6.8 and Indian DPDP Act 2023.",
    prompt: "Perform a comprehensive compliance check across our IAM setup for SOC 2 Type II and DPDP Act 2023. Detail every non-compliant identity and exact remediation steps.",
    icon: ShieldCheck,
  },
  {
    title: "Trace Attack Paths & Escalations",
    category: "Security Graph",
    description: "Identify multi-hop privilege escalation paths where non-admin users reach OrganizationAdmin.",
    prompt: "What are the highest risk privilege escalation paths discovered in our Neo4j graph topology? Explain how an attacker could traverse them and how to sever the links.",
    icon: Zap,
  },
  {
    title: "Automated Terraform & CLI Fixes",
    category: "Remediation",
    description: "Generate copy-pasteable AWS/GCP CLI commands and Terraform guardrails for least privilege.",
    prompt: "Generate an AWS CLI and Terraform remediation script to revoke overprivileged admin policies and enforce MFA on all console-access accounts.",
    icon: Terminal,
  },
  {
    title: "Financial Breach Impact Analysis",
    category: "Risk & Cost",
    description: "Calculate dollar breach exposure and regulatory penalty risks based on IBM benchmarks.",
    prompt: "Provide an executive summary of our estimated breach cost impact, maximum regulatory penalties under DPDP/GDPR, and cyber insurance IAM prerequisites.",
    icon: Scale,
  },
];

// 20b returned blank completions; the consultant is pinned to 120b.
const CURATED_MODELS = [
  {
    id: "openai/gpt-oss-120b",
    name: "Complex",
    version: "120B Deep Audit",
    label: "Complex (120B)",
    desc: "Deep multi-step reasoning for intricate IAM escalation graphs and regulatory legal audits.",
    badge: "Default",
  },
];

const PRESET_MEMORIES = [
  {
    key: "primary_cloud_region",
    category: "cloud_architecture",
    label: "AWS ap-south-1 & GCP asia-south1",
    content: "AWS ap-south-1 (Mumbai) & GCP asia-south1",
  },
  {
    key: "target_compliance_frameworks",
    category: "compliance_goals",
    label: "SOC 2 Type II & DPDP Act 2023",
    content: "SOC 2 Type II readiness and Indian DPDP Act 2023 compliance",
  },
  {
    key: "preferred_remediation_output",
    category: "engineering_preferences",
    label: "Terraform & AWS CLI Output",
    content: "Provide production-grade Terraform blocks and AWS CLI snippets with least privilege",
  },
  {
    key: "sandbox_exclusions",
    category: "exclusions",
    label: "Exclude Sandbox Roles",
    content: "Exclude staging-sandbox-* and test-eval-* IAM roles from critical severity escalations",
  },
];

export default function AskPage() {
  const { getToken, isLoaded, userId } = useAuth();
  const { user } = useUser();
  const router = useRouter();
  const pathname = usePathname();

  // Handle Client Router Cache interceptions when navigating from /graph to /ask
  useEffect(() => {
    if (pathname === "/ask") {
      const isTransferFromWidget = sessionStorage.getItem("boxai_chat_transfer_from_widget");
      if (isTransferFromWidget) {
        const sessionHistory = sessionStorage.getItem("boxai_chat_history");
        if (sessionHistory) {
          try {
            const parsed = JSON.parse(sessionHistory);
            if (Array.isArray(parsed) && parsed.length > 0) {
              const widgetConv: Conversation = {
                id: "conv_widget_" + Date.now(),
                title: "Widget Consultation",
                createdAt: Date.now(),
                messages: parsed,
              };
              setConversations((prev) => {
                 const newConversations = [widgetConv, ...prev];
                 try {
                   localStorage.setItem("boxai_saved_conversations", JSON.stringify(newConversations));
                 } catch(e){}
                 return newConversations;
              });
              setActiveId(widgetConv.id);
            }
          } catch (e) {}
        }
        sessionStorage.removeItem("boxai_chat_transfer_from_widget");
      }
    }
  }, [pathname]);

  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeId, setActiveId] = useState<string>("default");
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [selectedModel, setSelectedModel] = useState<string>("openai/gpt-oss-120b");
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [modelDropdownOpen, setModelDropdownOpen] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);
  const [attachedImage, setAttachedImage] = useState<string | null>(null);
  const [pasteError, setPasteError] = useState("");

  const handlePaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
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
          
          // Visual Normalization & EXIF Stripping via Canvas
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
              // Apply Gaussian blur to disrupt adversarial noise
              ctx.filter = "blur(1px)";
              ctx.drawImage(img, 0, 0, width, height);
              // Export to base64 jpeg (strips EXIF implicitly, reduces token footprint)
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

  // ── Long-Term Memory State ─────────────────────────────────────────
  const [memoryModalOpen, setMemoryModalOpen] = useState(false);
  const [memories, setMemories] = useState<MemoryItem[]>([]);
  const [loadingMemories, setLoadingMemories] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newContent, setNewContent] = useState("");
  const [newCategory, setNewCategory] = useState("cloud_architecture");
  const [memorySavedFeedback, setMemorySavedFeedback] = useState(false);

  // ── Client-Side Neural RAG State (Transformers.js + IndexedDB) ────
  const [ragStatus, setRagStatus] = useState<EngineStatus | null>(null);

  useEffect(() => {
    const unsub = clientRAGEngine.onStatusChange((status) => {
      setRagStatus(status);
    });
    clientRAGEngine.init();
    return () => unsub();
  }, []);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auth redirect check
  useEffect(() => {
    if (isLoaded && !userId) {
      router.replace("/");
    }
  }, [isLoaded, userId, router]);

  // Load 48h conversations and persistent memories from backend and cache
  useEffect(() => {
    async function initData() {
      let initialList: Conversation[] = [];

      // 1. First load local cache for instantaneous rendering
      try {
        const savedAll = localStorage.getItem("boxai_saved_conversations");
        if (savedAll) {
          const parsed = JSON.parse(savedAll);
          if (Array.isArray(parsed) && parsed.length > 0) {
            const now = Date.now();
            const fortyEightHours = 48 * 60 * 60 * 1000;
            initialList = parsed.filter((c) => now - (c.createdAt || now) < fortyEightHours);
          }
        }
      } catch (e) {}

      // 2. Check session history from drawer widget
      const sessionHistory = sessionStorage.getItem("boxai_chat_history");
      let sessionMessages: Message[] = [];
      
      if (sessionHistory) {
        try {
          const parsedSession = JSON.parse(sessionHistory);
          if (Array.isArray(parsedSession) && parsedSession.length > 0) {
            sessionMessages = parsedSession;
          }
        } catch (e) {}
      }

      if (initialList.length === 0) {
        const defaultConv: Conversation = {
          id: "conv_" + Date.now(),
          title: sessionMessages.length > 0 ? "IAM Security Consultation" : "New Consultation",
          createdAt: Date.now(),
          messages: sessionMessages,
        };
        initialList = [defaultConv];
      }

      setConversations(initialList);
      setActiveId(initialList[0].id);
      setIsInitialized(true);

      // 3. Fetch synced server-side conversations & memories from Supabase backend
      if (userId) {
        try {
          const token = await getToken();
          // Fetch conversations
          const res = await fetch("/api/ai/conversations", {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (res.ok) {
            const data = await res.json();
            if (Array.isArray(data) && data.length > 0) {
              const formatted: Conversation[] = data.map((d: any) => ({
                id: d.id,
                title: d.title || "Consultation",
                createdAt: new Date(d.created_at || d.updated_at).getTime(),
                messages: d.messages || [],
                modelUsed: d.model_name,
                expires_at: d.expires_at,
              }));

              setConversations((prev) => {
                const map = new Map<string, Conversation>();
                formatted.forEach((c) => map.set(c.id, c));
                prev.forEach((c) => {
                  if (!map.has(c.id)) map.set(c.id, c);
                });
                const merged = Array.from(map.values()).sort(
                  (a, b) => (b.createdAt || 0) - (a.createdAt || 0)
                );
                try {
                  localStorage.setItem("boxai_saved_conversations", JSON.stringify(merged));
                } catch (e) {}
                return merged;
              });
            }
          }
        } catch (e) {}

        // Fetch Memories
        fetchMemories();
      }
    }

    if (isLoaded && userId && !isInitialized) {
      initData();
    }
  }, [isLoaded, userId, isInitialized, getToken]);

  const fetchMemories = async () => {
    if (!userId) return;
    setLoadingMemories(true);
    try {
      const token = await getToken();
      const res = await fetch("/api/ai/memory", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        const memList = Array.isArray(data) ? data : (data.memories || []);
        setMemories(memList);
        if (memList.length > 0) {
          clientRAGEngine.ingestUserMemories(memList).catch(() => {});
        }
      }
    } catch (e) {
    } finally {
      setLoadingMemories(false);
    }
  };

  const handleSaveMemory = async (customKey?: string, customContent?: string, customCat?: string) => {
    const keyToSave = customKey || newKey.trim();
    const contentToSave = customContent || newContent.trim();
    const catToSave = customCat || newCategory;

    if (!keyToSave || !contentToSave || !userId) return;

    try {
      const token = await getToken();
      const res = await fetch("/api/ai/memory", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          key: keyToSave,
          content: contentToSave,
          category: catToSave,
          source: "user_custom",
        }),
      });

      if (res.ok) {
        setMemorySavedFeedback(true);
        setTimeout(() => setMemorySavedFeedback(false), 2000);
        if (!customKey) {
          setNewKey("");
          setNewContent("");
        }
        await fetchMemories();
      }
    } catch (e) {}
  };

  const handleDeleteMemory = async (keyOrId: string) => {
    if (!userId || !keyOrId) return;
    try {
      const token = await getToken();
      const res = await fetch(`/api/ai/memory?key=${encodeURIComponent(keyOrId)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        setMemories((prev) => prev.filter((m) => m.key !== keyOrId && m.id !== keyOrId));
      }
    } catch (e) {}
  };

  // Sync to local cache on conversation update
  useEffect(() => {
    if (conversations.length > 0) {
      try {
        localStorage.setItem("boxai_saved_conversations", JSON.stringify(conversations));
      } catch (e) {}
    }
  }, [conversations]);

  // Sync active conversation back to session storage for seamless drawer continuity
  useEffect(() => {
    const active = conversations.find((c) => c.id === activeId);
    if (active && active.messages.length > 0) {
      try {
        sessionStorage.setItem("boxai_chat_history", JSON.stringify(active.messages));
      } catch (e) {}
    }
  }, [conversations, activeId]);

  // Auto-scroll on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [conversations, activeId, loading]);

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 200)}px`;
    }
  }, [input]);

  const activeConversation = useMemo(() => {
    return conversations.find((c) => c.id === activeId) || conversations[0];
  }, [conversations, activeId]);

  const activeMessages = useMemo(() => {
    return activeConversation?.messages || [];
  }, [activeConversation]);

  // Filter conversations for search
  const filteredConversations = useMemo(() => {
    if (!searchFilter.trim()) return conversations;
    const q = searchFilter.toLowerCase();
    return conversations.filter(
      (c) =>
        c.title.toLowerCase().includes(q) ||
        c.messages.some((m) => m.content.toLowerCase().includes(q))
    );
  }, [conversations, searchFilter]);

  // Group conversations by time (within the 48-hour frame)
  const groupedConversations = useMemo(() => {
    const today: Conversation[] = [];
    const yesterday: Conversation[] = [];
    const earlier: Conversation[] = [];

    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    const yesterdayStart = todayStart - 24 * 60 * 60 * 1000;

    filteredConversations.forEach((c) => {
      const time = c.createdAt || Date.now();
      if (time >= todayStart) {
        today.push(c);
      } else if (time >= yesterdayStart) {
        yesterday.push(c);
      } else {
        earlier.push(c);
      }
    });

    return {
      Today: today,
      Yesterday: yesterday,
      "Past 48 Hours": earlier,
    };
  }, [filteredConversations]);

  const handleNewChat = () => {
    const newConv: Conversation = {
      id: "conv_" + Date.now(),
      title: "New Consultation",
      createdAt: Date.now(),
      messages: [],
    };
    setConversations([newConv, ...conversations]);
    setActiveId(newConv.id);
    setInput("");
  };

  const handleDeleteConversation = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const filtered = conversations.filter((c) => c.id !== id);
    setConversations(filtered);
    if (activeId === id) {
      if (filtered.length > 0) {
        setActiveId(filtered[0].id);
      } else {
        const newConv: Conversation = {
          id: "conv_" + Date.now(),
          title: "New Consultation",
          createdAt: Date.now(),
          messages: [],
        };
        setConversations([newConv]);
        setActiveId(newConv.id);
      }
    }

    if (userId) {
      try {
        const token = await getToken();
        await fetch(`/api/ai/conversations?id=${id}`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch (err) {}
    }
  };

  const handleClearCurrent = () => {
    if (!activeConversation) return;
    const updated = conversations.map((c) =>
      c.id === activeId ? { ...c, messages: [] } : c
    );
    setConversations(updated);
    try {
      sessionStorage.removeItem("boxai_chat_history");
    } catch (e) {}
  };

  const handleCopy = (content: string, idx: number) => {
    navigator.clipboard.writeText(content);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleSend = async (textToSend?: string) => {
    const text = textToSend || input.trim();
    if (!text || loading || !isLoaded) return;

    const timeStr = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const userMsg: Message = { 
      role: "user", 
      content: text, 
      timestamp: timeStr,
      image_base64: attachedImage || undefined 
    };

    let updatedTitle = "";
    const updatedConversations = conversations.map((c) => {
      if (c.id === activeId) {
        const isInitialTitle = c.title === "New Consultation" || c.title === "IAM Security Consultation";
        if (isInitialTitle && c.messages.length === 0) {
          updatedTitle = text.slice(0, 32) + (text.length > 32 ? "..." : "");
        }
        return {
          ...c,
          title: updatedTitle || c.title,
          messages: [...c.messages, userMsg],
        };
      }
      return c;
    });

    setConversations(updatedConversations);
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

      const currentConv = conversations.find((c) => c.id === activeId);
      const historyPayload = (currentConv?.messages || []).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      // 1. Check Semantic Cache First
      let cachedResponse = null;
      try {
        cachedResponse = await clientRAGEngine.checkSemanticCache(text);
      } catch (e) {
        console.warn("Semantic cache check error:", e);
      }

      if (cachedResponse) {
        // Cache hit! Skip RAG and backend entirely
        const assistantMsg: Message = {
          role: "assistant",
          content: cachedResponse,
          modelUsed: "semantic-cache",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        };

        const finalConversations = updatedConversations.map((c) => {
          if (c.id === activeId) {
            return {
              ...c,
              messages: [...c.messages, assistantMsg],
              updatedAt: Date.now(),
            };
          }
          return c;
        });

        setConversations(finalConversations);
        setLoading(false);
        return;
      }

      // Retrieve local context from Client RAG and Edge Web Search concurrently
      let clientRagContext: any[] = [];
      let webSearchContext: any[] = [];

      try {
        const [ragResults, webResults] = await Promise.allSettled([
          clientRAGEngine.retrieveContext(text, 4),
          fetch("/api/edge-search", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: text }),
          }).then((r) => r.json()),
        ]);

        if (ragResults.status === "fulfilled") {
          clientRagContext = ragResults.value.map((r: any) => ({
            title: r.chunk.title,
            content: r.chunk.content,
            framework: r.chunk.framework,
            control_id: r.chunk.control_id,
            remediation: r.chunk.remediation,
            category: r.chunk.category,
            score: r.score,
          }));
        }

        if (webResults.status === "fulfilled" && webResults.value?.results) {
          webSearchContext = webResults.value.results;
        }
      } catch (err) {
        console.warn("Context retrieval skipped/failed:", err);
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
          history: historyPayload,
          scan_id: lastScanId,
          scan_config: scanConfig,
          client_rag_context: clientRagContext.length > 0 ? clientRagContext : undefined,
          web_search_context: webSearchContext.length > 0 ? webSearchContext : undefined,
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

      const baseAssistantMsg: Message = {
        role: "assistant",
        content: "",
        modelUsed: modelUsed,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      
      // Initialize the assistant message in state
      setConversations((prev) => prev.map((c) => {
        if (c.id === activeId) {
          return { ...c, messages: [...c.messages, baseAssistantMsg] };
        }
        return c;
      }));

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
                baseAssistantMsg.modelUsed = modelUsed;
              } else if (parsed.type === "chunk") {
                accumulatedResponse += parsed.text;
                setConversations((prev) => prev.map((c) => {
                  if (c.id === activeId) {
                    const msgs = [...c.messages];
                    msgs[msgs.length - 1] = { ...msgs[msgs.length - 1], content: accumulatedResponse, modelUsed };
                    return { ...c, messages: msgs };
                  }
                  return c;
                }));
              } else if (parsed.type === "done") {
                done = true;
              }
            } catch (e) {}
          }
        }
      }

      const finalConversations = conversations.map((c) => {
        if (c.id === activeId) {
          const msgs = [...c.messages];
          msgs.push({
            role: "user",
            content: text,
          });
          msgs.push({
            ...baseAssistantMsg,
            content: accumulatedResponse,
          });
          return {
            ...c,
            modelUsed: modelUsed,
            messages: msgs,
          };
        }
        return c;
      });

      // Save to semantic cache for future instant lookups
      if (accumulatedResponse.length > 0) {
        clientRAGEngine.saveToSemanticCache(text, accumulatedResponse).catch(console.warn);
      }

      setConversations((prev) => prev.map((c) => {
        if (c.id === activeId) {
           const msgs = [...c.messages];
           if (msgs.length > 0 && msgs[msgs.length-1].role === "assistant") {
               msgs[msgs.length-1].content = accumulatedResponse;
           }
           return { ...c, messages: msgs, modelUsed };
        }
        return c;
      }));

      // Async persist full conversation to Supabase (48-hr rolling window)
      if (userId) {
        try {
          const currentUpdated = finalConversations.find((c) => c.id === activeId);
          if (currentUpdated) {
            getToken().then((authToken) => {
              if (!authToken) return;
              fetch("/api/ai/conversations", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${authToken}`,
                },
                body: JSON.stringify({
                  id: activeId,
                  title: updatedTitle || activeConversation?.title || "IAM Consultation",
                  messages: currentUpdated.messages,
                  model_name: modelUsed || selectedModel,
                }),
              }).catch(() => {});
            }).catch(() => {});
          }
        } catch (e) {}
      }
    } catch (err: any) {
      const errorMsg: Message = {
        role: "assistant",
        content: `**AuthMap AI Encountered an Issue**:\n\n${err.message || "Failed to reach AI inference service."}\n\n*Check that your API keys are active in backend configuration.*`,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setConversations((prev) =>
        prev.map((c) => (c.id === activeId ? { ...c, messages: [...c.messages, errorMsg] } : c))
      );
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const activeModelObj = useMemo(() => {
    return CURATED_MODELS.find((m) => m.id === selectedModel) || CURATED_MODELS[0];
  }, [selectedModel]);

  return (
    <div
      className="flex h-screen w-screen overflow-hidden bg-[#212121] text-[#ececec] antialiased"
      style={{
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
      }}
    >
      {/* Mobile Backdrop */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 z-20 bg-black/60 md:hidden backdrop-blur-sm transition-opacity" 
          onClick={() => setSidebarOpen(false)} 
        />
      )}

      {/* ── Sidebar (ChatGPT Style) ─────────────────────────────────── */}
      <aside
        className={`${
          sidebarOpen ? "w-64" : "w-0"
        } absolute md:relative z-30 h-full flex flex-col shrink-0 overflow-hidden bg-[#171717] border-r border-white/[0.06] transition-all duration-300`}
      >
        {/* Top Branding & New Chat */}
        <div className="p-3.5 space-y-3">
          <div className="flex items-center justify-between px-1.5 py-1">
            <Link href="/welcome" className="flex items-center gap-2 group">
              <span className="text-lg font-semibold tracking-tight text-white group-hover:text-white/80 transition">
                AuthMap
              </span>
              <span className="rounded-md border border-white/20 bg-white/10 px-1.5 py-0.5 text-[0.65rem] font-semibold text-white">
                AI
              </span>
            </Link>

            <button
              onClick={() => setSidebarOpen(false)}
              className="rounded-lg p-1.5 text-[#8e8e8e] hover:bg-[#212121] hover:text-white transition"
              title="Close sidebar"
            >
              <PanelLeftClose className="h-4 w-4" />
            </button>
          </div>

          <button
            onClick={handleNewChat}
            className="flex w-full items-center justify-between rounded-xl border border-white/10 bg-[#212121] px-3.5 py-2.5 text-xs font-medium text-white transition hover:bg-[#2a2a2a] hover:border-white/20 active:scale-[0.99]"
          >
            <div className="flex items-center gap-2">
              <Plus className="h-4 w-4 text-white" />
              <span>New consultation</span>
            </div>
            <span className="text-[0.65rem] text-[#8e8e8e]">⌘K</span>
          </button>
        </div>

        {/* Search Chats */}
        <div className="px-3.5 pb-2">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-[#8e8e8e]" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Search conversations..."
              className="w-full rounded-xl border border-white/10 bg-[#212121] py-2 pl-8 pr-3 text-xs text-[#ececec] placeholder:text-[#8e8e8e] focus:border-white/30 focus:outline-none tracking-normal"
            />
          </div>
        </div>

        {/* 48-Hour TTL Policy Indicator */}
        <div className="px-3.5 pb-2">
          <div className="flex items-center gap-1.5 rounded-lg border border-white/[0.06] bg-[#212121]/50 px-2.5 py-1.5 text-[0.68rem] text-[#8e8e8e]">
            <Clock className="h-3 w-3 shrink-0 text-emerald-400" />
            <span className="truncate">48-hr rolling history window</span>
          </div>
        </div>

        {/* Conversation List */}
        <div className="chat-scroll flex-1 overflow-y-auto px-2 space-y-4 pb-4">
          {Object.entries(groupedConversations).map(([groupName, convList]) => {
            if (convList.length === 0) return null;
            return (
              <div key={groupName} className="space-y-1">
                <div className="px-2.5 text-[0.68rem] font-semibold text-[#8e8e8e]">
                  {groupName}
                </div>
                {convList.map((conv) => {
                  const isActive = conv.id === activeId;
                  return (
                    <div
                      key={conv.id}
                      onClick={() => setActiveId(conv.id)}
                      className={`group relative flex items-center justify-between rounded-xl px-3 py-2 text-xs transition cursor-pointer ${
                        isActive
                          ? "bg-[#212121] text-white font-medium shadow-sm"
                          : "text-[#b4b4b4] hover:bg-[#212121]/60 hover:text-white"
                      }`}
                    >
                      <div className="flex items-center gap-2.5 overflow-hidden pr-6">
                        <MessageSquare className="h-3.5 w-3.5 shrink-0 text-[#8e8e8e]" />
                        <span className="truncate">{conv.title}</span>
                      </div>

                      {/* Delete on Hover */}
                      <button
                        onClick={(e) => handleDeleteConversation(conv.id, e)}
                        className="absolute right-2 opacity-0 group-hover:opacity-100 rounded p-1 text-[#8e8e8e] hover:text-white transition"
                        title="Delete chat"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>

        {/* User Account / Footer */}
        <div className="border-t border-white/[0.08] p-3">
          <div className="flex items-center justify-between rounded-xl p-1.5 hover:bg-[#212121] transition">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <UserButton />
              <div className="flex flex-col overflow-hidden text-left">
                <span className="text-xs font-medium text-white truncate">
                  {user?.fullName || user?.primaryEmailAddress?.emailAddress || "Security Engineer"}
                </span>
                <span className="text-[0.65rem] text-[#8e8e8e]">Organization Admin</span>
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* ── Main Chat Canvas ────────────────────────────────────────── */}
      <div className="relative flex flex-1 flex-col overflow-hidden bg-[#212121]">
        {/* Top Navbar */}
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-white/[0.06] bg-[#212121]/90 px-4 backdrop-blur-md z-20">
          <div className="flex items-center gap-2 sm:gap-3">
            {!sidebarOpen && (
              <button
                onClick={() => setSidebarOpen(true)}
                className="rounded-lg p-1.5 text-[#8e8e8e] hover:bg-[#2f2f2f] hover:text-white transition"
                title="Open sidebar"
              >
                <PanelLeft className="h-4 w-4" />
              </button>
            )}

            {/* Model Selector Dropdown (Clean ChatGPT Style) */}
            <div className="relative">
              <button
                onClick={() => setModelDropdownOpen(!modelDropdownOpen)}
                className="group flex items-center gap-1.5 sm:gap-2 rounded-xl px-2 sm:px-3 py-1.5 text-sm font-semibold text-white/90 transition hover:bg-white/[0.08] hover:text-white"
              >
                <span className="truncate max-w-[100px] sm:max-w-none">{activeModelObj.name}</span>
                <span className="hidden sm:inline text-xs font-normal text-[#8e8e8e]">
                  ({activeModelObj.version.split(" ")[0]})
                </span>
                <ChevronDown
                  className={`h-3.5 w-3.5 text-[#8e8e8e] transition-transform duration-200 ${
                    modelDropdownOpen ? "rotate-180 text-white" : "group-hover:text-white"
                  }`}
                />
              </button>

              {modelDropdownOpen && (
                <>
                  <div
                    className="fixed inset-0 z-40"
                    onClick={() => setModelDropdownOpen(false)}
                  />
                  <div className="absolute left-0 mt-2 w-84 rounded-2xl border border-white/10 bg-[#282828] p-1.5 shadow-[0_20px_50px_rgba(0,0,0,0.85)] z-50 space-y-1">
                    {CURATED_MODELS.map((m) => {
                      const isSelected = selectedModel === m.id;
                      return (
                        <button
                          key={m.id}
                          onClick={() => {
                            setSelectedModel(m.id);
                            setModelDropdownOpen(false);
                          }}
                          className={`flex w-full items-start justify-between rounded-xl p-3 text-left transition ${
                            isSelected
                              ? "bg-[#333333] text-white"
                              : "text-[#ececec] hover:bg-[#303030]"
                          }`}
                        >
                          <div className="space-y-1 pr-2">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold text-white">{m.name}</span>
                              <span className="text-[0.68rem] text-[#8e8e8e]">({m.version})</span>
                              {m.badge === "Default" && (
                                <span className="rounded bg-white/10 px-1.5 py-0.2 text-[0.6rem] font-medium text-[#b4b4b4]">
                                  Default
                                </span>
                              )}
                            </div>
                            <p className="text-[0.72rem] text-[#8e8e8e] leading-relaxed">
                              {m.desc}
                            </p>
                          </div>
                          {isSelected && (
                            <Check className="h-4 w-4 text-white shrink-0 mt-0.5" />
                          )}
                        </button>
                      );
                    })}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Right Actions: Neural RAG Status, Long-Term Memory, Reset & Exit */}
          <div className="flex items-center gap-2">
            {/* Client-Side Neural RAG Status Badge */}
            <div
              className="hidden sm:flex items-center gap-1.5 rounded-xl border border-white/10 bg-[#262626] px-2.5 py-1.5 text-xs text-[#ececec] shadow-sm"
              title={`Client-Side Neural RAG (${ragStatus?.isReady ? "Ready" : "Active"} - ${ragStatus?.totalVectors || 0} vectors in IndexedDB)`}
            >
              <Database className="h-3.5 w-3.5 text-emerald-400" />
              <span className="hidden md:inline font-medium text-[0.72rem] text-white/90">
                Client RAG
              </span>
              {ragStatus?.isReady || (ragStatus?.totalVectors && ragStatus.totalVectors > 0) ? (
                <span className="inline-flex items-center gap-1 text-[0.68rem] text-emerald-400 font-mono">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  {ragStatus.totalVectors}
                </span>
              ) : ragStatus?.isIndexing ? (
                <span className="inline-flex items-center gap-1 text-[0.68rem] text-cyan-400 font-mono">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  {ragStatus.progressPercent ? `${Math.round(ragStatus.progressPercent)}%` : "Indexing"}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-[0.68rem] text-emerald-400/80 font-mono">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/60" />
                  Ready
                </span>
              )}
            </div>

            {/* Long-Term Memory Context Trigger (ChatGPT Style) */}
            <button
              onClick={() => {
                setMemoryModalOpen(true);
                fetchMemories();
              }}
              className="flex items-center gap-1.5 sm:gap-2 rounded-xl border border-white/10 bg-[#2f2f2f] px-2.5 sm:px-3 py-1.5 text-xs font-medium text-[#ececec] transition hover:bg-[#383838] hover:border-white/20 shadow-sm"
              title="Manage AI Memory Context"
            >
              <Brain className="h-3.5 w-3.5 text-[#8e8e8e]" />
              <span className="hidden sm:inline">Memory</span>
              {memories.length > 0 && (
                <span className="flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-white/15 px-1 text-[0.6rem] font-semibold text-white">
                  {memories.length}
                </span>
              )}
            </button>

            {activeMessages.length > 0 && (
              <button
                onClick={handleClearCurrent}
                className="flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#2f2f2f] px-2.5 py-1.5 text-xs text-[#ececec] transition hover:bg-[#383838]"
                title="Reset conversation"
              >
                <RotateCcw className="h-3.5 w-3.5 text-[#8e8e8e]" />
                <span className="hidden sm:inline">Reset</span>
              </button>
            )}

            <Link
              href="/welcome"
              className="rounded-lg border border-white/10 bg-[#2f2f2f] px-2.5 sm:px-3 py-1.5 text-xs font-medium text-[#ececec] transition hover:bg-[#383838]"
            >
              <span className="hidden sm:inline">Exit</span>
              <span className="sm:hidden">X</span>
            </Link>
          </div>
        </header>

        {/* Messages / Welcome View */}
        <div className="chat-scroll flex-1 overflow-y-auto pb-36">
          {activeMessages.length === 0 ? (
            /* ── Centered Welcome Screen ────────────────────────────────── */
            <div className="mx-auto flex h-full max-w-3xl flex-col items-center justify-center px-4 py-16 text-center">
              <div className="mb-2 flex items-center justify-center gap-2">
                <span className="text-3xl sm:text-4xl font-semibold tracking-tight text-white">
                  AuthMap AI
                </span>
              </div>
              <p className="max-w-md text-sm text-[#8e8e8e]">
                Multi-cloud IAM security and compliance copilot. Powered by live graph traversal, long-term organizational memory, and production-grade Groq intelligence.
              </p>

              {/* Memory Indicator Pill */}
              {memories.length > 0 && (
                <div
                  onClick={() => setMemoryModalOpen(true)}
                  className="mt-4 inline-flex items-center gap-2 rounded-full border border-white/10 bg-[#2f2f2f] px-3.5 py-1 text-xs text-[#ececec] transition hover:bg-[#383838] hover:border-white/20 cursor-pointer"
                >
                  <Brain className="h-3.5 w-3.5 text-[#8e8e8e]" />
                  <span>
                    Active Context: <strong>{memories.length} saved memories</strong> active
                  </span>
                </div>
              )}

              {/* 2x2 Clean Prompt Cards */}
              <div className="mt-8 grid w-full grid-cols-1 gap-3 sm:grid-cols-2 text-left">
                {PROMPT_SUGGESTIONS.map((card, idx) => {
                  const Icon = card.icon;
                  return (
                    <button
                      key={idx}
                      onClick={() => handleSend(card.prompt)}
                      className="group flex flex-col justify-between rounded-2xl border border-white/[0.08] bg-[#2f2f2f] p-4 transition hover:bg-[#383838] hover:border-white/20 active:scale-[0.99] shadow-sm"
                    >
                      <div>
                        <div className="flex items-center justify-between">
                          <Icon className="h-4 w-4 text-white" />
                          <span className="text-[0.65rem] font-semibold text-[#8e8e8e]">
                            {card.category}
                          </span>
                        </div>
                        <h3 className="mt-2.5 text-xs font-semibold text-white transition">
                          {card.title}
                        </h3>
                        <p className="mt-1 text-[0.75rem] text-[#8e8e8e] line-clamp-2 leading-relaxed">
                          {card.description}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          ) : (
            /* ── Active Conversation Stream (ChatGPT Flat Centered Layout) ─ */
            <div className="mx-auto max-w-3xl px-4 py-8 space-y-8">
              {activeMessages.map((m, i) => {
                const isUser = m.role === "user";
                return (
                  <div key={i} className="space-y-2">
                    {/* Message Body */}
                    {isUser ? (
                      <div className="flex justify-end">
                        <div className="max-w-[78%] rounded-[24px] bg-[#2f2f2f] px-5 py-3.5 text-[0.95rem] leading-[1.65] text-[#ececec] shadow-sm flex flex-col gap-3">
                          {m.image_base64 && (
                            <img src={m.image_base64} alt="User attached" className="max-w-full rounded-xl object-contain max-h-[300px]" />
                          )}
                          <div className="whitespace-pre-wrap">{m.content}</div>
                        </div>
                      </div>
                    ) : (
                      <div className="w-full space-y-3">
                        <div className="flex items-center gap-2 text-xs font-semibold text-white">
                          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-white text-black font-bold text-[0.65rem]">
                            AM
                          </div>
                          <span>AuthMap AI</span>
                        </div>

                        <div className="text-[1rem] leading-[1.75] text-[#ececec]">
                          <MarkdownMessage content={m.content} size="base" />
                        </div>

                        {/* AI Toolbar */}
                        <div className="flex items-center justify-between pt-2 text-xs text-[#8e8e8e]">
                          <div className="flex items-center gap-2">
                            {m.modelUsed && (
                              <span className="rounded-md border border-white/10 bg-[#2f2f2f] px-2 py-0.5 font-mono text-[0.68rem] text-[#b4b4b4]">
                                {m.modelUsed.includes("120b") ? "120B Deep Audit" : "120B Deep Audit"}
                              </span>
                            )}
                            {memories.length > 0 && (
                              <span className="flex items-center gap-1 rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[0.65rem] text-[#b4b4b4]">
                                <Brain className="h-3 w-3" />
                                Memory Active
                              </span>
                            )}
                          </div>

                          <button
                            onClick={() => handleCopy(m.content, i)}
                            className="flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs text-[#8e8e8e] transition hover:bg-[#2f2f2f] hover:text-white"
                          >
                            {copiedIndex === i ? (
                              <>
                                <Check className="h-3.5 w-3.5 text-emerald-400" />
                                <span className="text-emerald-400 font-medium">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="h-3.5 w-3.5" />
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {loading && (
                <div className="w-full space-y-3">
                  <div className="flex items-center gap-2 text-xs font-semibold text-white">
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-white text-black font-bold text-[0.65rem]">
                      AM
                    </div>
                    <span>AuthMap AI</span>
                  </div>
                  <div className="flex items-center gap-3 py-2 text-sm text-[#b4b4b4]">
                    <Loader2 className="h-4 w-4 animate-spin text-white" />
                    <span>Analyzing multi-cloud graph topology and synthesizing guidance...</span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* ── Fixed Bottom Floating Input Area (ChatGPT Pill) ─────────── */}
        <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-[#212121] via-[#212121]/95 to-transparent p-4 pb-6 z-20">
          <div className="mx-auto max-w-3xl flex flex-col gap-2">
            {pasteError && (
              <div className="text-red-400 text-xs font-semibold px-4 py-1.5 bg-red-400/10 border border-red-400/20 rounded-md self-start ml-2 mb-1">
                {pasteError}
              </div>
            )}
            {attachedImage && (
              <div className="relative w-20 h-20 rounded-xl overflow-hidden border border-white/20 bg-[#2f2f2f] self-start ml-4">
                <img src={attachedImage} alt="Pasted attachment" className="w-full h-full object-cover" />
                <button
                  type="button"
                  onClick={() => setAttachedImage(null)}
                  className="absolute top-1 right-1 bg-black/60 rounded-full p-1 text-white hover:bg-black transition"
                >
                  <X className="h-3 w-3" />
                </button>
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="relative flex items-center rounded-[28px] border border-white/10 bg-[#2f2f2f] p-1.5 pl-4 pr-12 shadow-2xl focus-within:border-white/25 focus-within:bg-[#343434] transition"
            >
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                onPaste={handlePaste}
                placeholder="Ask AuthMap AI about IAM policies, or paste an image..."
                rows={1}
                disabled={loading}
                className="max-h-48 w-full resize-none bg-transparent py-2 text-sm text-white placeholder:text-[#8e8e8e] focus:outline-none leading-relaxed"
              />
              <button
                type="submit"
                disabled={loading || (!input.trim() && !attachedImage)}
                className="absolute right-2.5 flex h-8 w-8 items-center justify-center rounded-full bg-white text-black font-bold transition hover:opacity-90 active:scale-95 disabled:bg-[#424242] disabled:text-[#8e8e8e]"
                title="Send message"
              >
                <ArrowUp className="h-4 w-4" />
              </button>
            </form>
            <p className="mt-2 text-center text-[0.72rem] text-[#8e8e8e]">
              AuthMap AI references live Neo4j graph topology, persistent org context, and compliance telemetry.
            </p>
          </div>
        </div>
      </div>

      {/* ── Manage Long-Term Memory & Org Context Modal ──────────────── */}
      {memoryModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md">
          <div className="relative flex max-h-[90vh] w-full max-w-2xl flex-col rounded-3xl border border-white/15 bg-[#222222] shadow-2xl overflow-hidden text-[#ececec]">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-white/10 px-6 py-4 bg-[#282828]">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <Brain className="h-4 w-4 text-purple-400" />
                  <h3 className="text-base font-semibold text-white">
                    Memory
                  </h3>
                </div>
                <p className="text-xs text-zinc-400">
                  AuthMap AI remembers details about your cloud architecture, compliance targets, and preferences across conversations.
                </p>
              </div>
              <button
                onClick={() => setMemoryModalOpen(false)}
                className="rounded-lg p-1.5 text-zinc-400 hover:bg-white/10 hover:text-white transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="chat-scroll flex-1 overflow-y-auto p-6 space-y-6 bg-[#1c1c1c]">
              {/* Quick Context Templates */}
              <div className="space-y-2">
                <div className="text-[0.68rem] font-semibold uppercase tracking-wider text-zinc-400">
                  Suggested Context Notes
                </div>
                <div className="flex flex-wrap gap-2">
                  {PRESET_MEMORIES.map((preset, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => handleSaveMemory(preset.key, preset.content, preset.category)}
                      className="flex items-center gap-1.5 rounded-full border border-white/15 bg-[#282828] px-3.5 py-1.5 text-xs font-medium text-white transition hover:border-emerald-500/40 hover:bg-[#303030] hover:text-emerald-300 active:scale-[0.98]"
                    >
                      <Plus className="h-3 w-3 text-emerald-400" />
                      <span>{preset.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* Add Custom Memory Entry */}
              <div className="rounded-2xl border border-white/10 bg-[#252525] p-4 space-y-3 shadow-md">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white tracking-wide">
                    Add a new memory note
                  </span>
                  {memorySavedFeedback && (
                    <span className="flex items-center gap-1 text-xs text-emerald-300 font-semibold bg-emerald-500/20 px-2.5 py-0.5 rounded-lg border border-emerald-500/30">
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                      Saved to Memory!
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[0.68rem] font-medium text-zinc-400 mb-1">
                      Topic / Key
                    </label>
                    <input
                      type="text"
                      value={newKey}
                      onChange={(e) => setNewKey(e.target.value)}
                      placeholder="e.g., aws_primary_region, soc2_scope"
                      className="w-full rounded-xl border border-white/15 bg-[#181818] px-3 py-2 text-xs text-white placeholder:text-zinc-500 focus:border-white/40 focus:bg-[#141414] focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-[0.68rem] font-medium text-zinc-400 mb-1">
                      Category
                    </label>
                    <select
                      value={newCategory}
                      onChange={(e) => setNewCategory(e.target.value)}
                      className="w-full rounded-xl border border-white/15 bg-[#181818] px-3 py-2 text-xs text-white focus:border-white/40 focus:bg-[#141414] focus:outline-none"
                    >
                      <option value="cloud_architecture">Cloud Architecture</option>
                      <option value="compliance_goals">Compliance Goals</option>
                      <option value="engineering_preferences">Engineering Preferences</option>
                      <option value="exclusions">Policy Exclusions</option>
                      <option value="general">General</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-[0.68rem] font-medium text-zinc-400 mb-1">
                    Context Details
                  </label>
                  <textarea
                    value={newContent}
                    onChange={(e) => setNewContent(e.target.value)}
                    placeholder="What should AuthMap AI remember? (e.g., 'Primary AWS account operates in ap-south-1. Output remediation with copy-paste Terraform modules.')"
                    rows={2}
                    className="w-full resize-none rounded-xl border border-white/15 bg-[#181818] p-3 text-xs text-white placeholder:text-zinc-500 focus:border-white/40 focus:bg-[#141414] focus:outline-none leading-relaxed"
                  />
                </div>

                <div className="flex justify-end pt-1">
                  <button
                    type="button"
                    onClick={() => handleSaveMemory()}
                    disabled={!newKey.trim() || !newContent.trim()}
                    className={`flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold transition-all duration-150 ${
                      newKey.trim() && newContent.trim()
                        ? "bg-white text-black hover:bg-zinc-200 shadow-md active:scale-95 cursor-pointer"
                        : "bg-[#333333] text-zinc-400 border border-white/10 cursor-not-allowed"
                    }`}
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>Save Memory</span>
                  </button>
                </div>
              </div>

              {/* Active Memory Notes List */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[0.68rem] font-semibold uppercase tracking-wider text-zinc-400">
                    Remembered Information ({memories.length})
                  </span>
                  <span className="text-[0.68rem] text-zinc-500">
                    Included in context across sessions
                  </span>
                </div>

                {loadingMemories ? (
                  <div className="flex items-center justify-center py-8 text-xs text-zinc-400">
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    Loading memories...
                  </div>
                ) : memories.length === 0 ? (
                  <div className="rounded-2xl border border-white/10 bg-[#252525]/50 p-6 text-center text-xs text-zinc-400">
                    No memories saved yet. Add key context above or select suggested notes.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {memories.map((mem) => {
                      let badgeColor = "bg-purple-500/15 text-purple-300 border-purple-500/30";
                      if (mem.category === "cloud_architecture") badgeColor = "bg-sky-500/15 text-sky-300 border-sky-500/30";
                      else if (mem.category === "compliance_goals") badgeColor = "bg-emerald-500/15 text-emerald-300 border-emerald-500/30";
                      else if (mem.category === "engineering_preferences") badgeColor = "bg-amber-500/15 text-amber-300 border-amber-500/30";
                      else if (mem.category === "exclusions") badgeColor = "bg-rose-500/15 text-rose-300 border-rose-500/30";

                      return (
                        <div
                          key={mem.key || mem.id}
                          className="group flex items-start justify-between rounded-2xl border border-white/10 bg-[#252525] p-3.5 transition hover:border-white/20"
                        >
                          <div className="space-y-1.5 pr-4">
                            <div className="flex items-center gap-2">
                              <span className={`rounded-md border px-2 py-0.5 text-[0.62rem] font-semibold tracking-wide uppercase ${badgeColor}`}>
                                {mem.category?.replace(/_/g, " ") || "GENERAL"}
                              </span>
                              <span className="text-xs font-semibold text-white">
                                {mem.key?.replace(/_/g, " ")}
                              </span>
                            </div>
                            <p className="text-xs text-zinc-300 leading-relaxed">
                              {mem.content}
                            </p>
                          </div>
                          <button
                            onClick={() => handleDeleteMemory(mem.key || mem.id || "")}
                            className="rounded-lg p-1.5 text-zinc-400 hover:text-rose-400 hover:bg-rose-500/10 transition"
                            title="Delete memory"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-between border-t border-white/10 bg-[#282828] px-6 py-3.5">
              <span className="text-[0.68rem] text-zinc-400">
                Stored securely in your PostgreSQL database.
              </span>
              <button
                onClick={() => setMemoryModalOpen(false)}
                className="rounded-xl bg px-4 py-1.5 text-xs font-semibold text-black transition hover:bg-zinc-50"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
