import DOMPurify from "dompurify";
import { clientRAGStore, RAGChunk, RAGVector } from "./client-rag-store";
import staticComplianceData from "./data/compliance-dataset.json";

export interface SearchResult {
  chunk: RAGChunk;
  score: number;
}

export interface EngineStatus {
  isReady: boolean;
  isIndexing: boolean;
  model: string;
  totalChunks: number;
  totalVectors: number;
  progressPercent: number;
  statusMessage: string;
}

const DATASET_VERSION = "2.0.0_authmap_compliance";

// ── Strict Client-Side Ingestion & DoS Quota Limits ─────────────────
const MAX_TOTAL_CHUNKS = 500;
const MAX_CHUNK_CHARACTERS = 4000;
const MAX_QUERY_LENGTH = 1000;

function sanitizeInputText(input: string, maxLen: number = MAX_CHUNK_CHARACTERS): string {
  if (!input || typeof input !== "string") return "";
  // Strip all HTML/scripts/event-handlers via DOMPurify
  const clean = typeof window !== "undefined"
    ? DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] })
    : input.replace(/<[^>]*>?/gm, "");
  return clean.substring(0, maxLen).trim();
}

class ClientRAGEngine {
  private worker: Worker | null = null;
  private isReady = false;
  private isIndexing = false;
  private statusMessage = "Initializing Client RAG...";
  private progressPercent = 0;
  private vectorCount = 0;
  private chunkCount = 0;
  private pendingRequests = new Map<string, { resolve: (val: any) => void; reject: (err: any) => void }>();
  private statusListeners = new Set<(status: EngineStatus) => void>();
  private initPromise: Promise<void> | null = null;

  constructor() {
    // Check initial count from storage if in browser
    if (typeof window !== "undefined") {
      clientRAGStore.count().then((c) => {
        this.chunkCount = c.chunks;
        this.vectorCount = c.vectors;
        if (c.vectors > 0) {
          this.statusMessage = `Client RAG Ready (${c.vectors} vectors cached)`;
        }
        this.notifyStatus();
      }).catch(() => {});
    }
  }

  public onStatusChange(callback: (status: EngineStatus) => void): () => void {
    this.statusListeners.add(callback);
    callback(this.getStatus());
    return () => this.statusListeners.delete(callback);
  }

  private notifyStatus() {
    const status = this.getStatus();
    this.statusListeners.forEach((cb) => {
      try {
        cb(status);
      } catch (err) {
        console.error("Status callback error:", err);
      }
    });
  }

  public getStatus(): EngineStatus {
    return {
      isReady: this.isReady,
      isIndexing: this.isIndexing,
      model: "all-MiniLM-L6-v2 (Quantized)",
      totalChunks: this.chunkCount,
      totalVectors: this.vectorCount,
      progressPercent: this.progressPercent,
      statusMessage: this.statusMessage,
    };
  }

  public async init(): Promise<void> {
    if (typeof window === "undefined") return;
    if (this.isReady) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      try {
        this.statusMessage = "Starting Neural Worker...";
        this.notifyStatus();

        this.worker = new Worker(new URL("./embedding.worker.ts", import.meta.url), {
          type: "module",
        });

        this.worker.onmessage = this.handleWorkerMessage.bind(this);
        this.worker.onerror = (err) => {
          console.error("[Client RAG] Worker error:", err);
          this.statusMessage = "Worker fallback: " + (err?.message || "Unavailable");
          this.notifyStatus();
        };

        // Initialize model in worker with 120s timeout (for slow connections downloading 22MB ONNX)
        const initTimeout = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Worker model load timed out")), 120000)
        );
        await Promise.race([this.postWorkerMessage("INIT", {}), initTimeout]);

        // Security: Purge expired user memories and semantic caches (48h rolling window)
        await clientRAGStore.pruneExpiredData();

        // Check if dataset is indexed in IndexedDB
        const storedVersion = await clientRAGStore.getMetadata("dataset_version");
        const count = await clientRAGStore.count();
        this.chunkCount = count.chunks;
        this.vectorCount = count.vectors;

        if (storedVersion !== DATASET_VERSION || count.chunks === 0 || count.vectors === 0) {
          this.statusMessage = "Indexing Compliance Benchmarks...";
          this.isIndexing = true;
          this.notifyStatus();

          await this.indexStaticDataset();

          const newCount = await clientRAGStore.count();
          this.chunkCount = newCount.chunks;
          this.vectorCount = newCount.vectors;

          await clientRAGStore.setMetadata("dataset_version", DATASET_VERSION);
          await clientRAGStore.setMetadata("last_synced", Date.now());
        }

        this.isReady = true;
        this.isIndexing = false;
        this.statusMessage = `Client RAG Ready (${this.vectorCount} vectors in IndexedDB)`;
        this.notifyStatus();
      } catch (err: any) {
        console.warn("[Client RAG] Neural worker init skipped, running in fallback mode:", err?.message || err);
        this.statusMessage = "Client RAG Fallback Mode";
        this.isIndexing = false;
        this.isReady = false;
        this.notifyStatus();
      }
    })();

    return this.initPromise;
  }

  private handleWorkerMessage(event: MessageEvent) {
    const { id, type, payload, error } = event.data;

    if (type === "PROGRESS") {
      if (payload && payload.progress !== undefined) {
        this.progressPercent = Math.round(payload.progress);
        this.statusMessage = `Downloading ONNX Model: ${this.progressPercent}%`;
        this.notifyStatus();
      }
      return;
    }

    if (type === "BATCH_PROGRESS") {
      const { current, total } = payload;
      this.progressPercent = Math.round((current / total) * 100);
      this.statusMessage = `Embedding Knowledge Base: ${current}/${total} chunks (${this.progressPercent}%)`;
      this.notifyStatus();
      return;
    }

    const pending = this.pendingRequests.get(id);
    if (!pending) return;

    this.pendingRequests.delete(id);

    if (type === "ERROR" || error) {
      pending.reject(new Error(error || "Worker operation failed"));
    } else {
      pending.resolve(payload);
    }
  }

  private postWorkerMessage(type: string, payload: any): Promise<any> {
    if (!this.worker) {
      return Promise.reject(new Error("Worker not initialized"));
    }

    const id = "req_" + Math.random().toString(36).substring(2, 9) + "_" + Date.now();
    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      this.worker!.postMessage({ id, type, payload });
    });
  }

  private async indexStaticDataset(): Promise<void> {
    const chunks: RAGChunk[] = (staticComplianceData as any[]).map((item) => ({
      id: sanitizeInputText(item.id, 100),
      title: sanitizeInputText(item.title, 200),
      content: sanitizeInputText(`${item.title}: ${item.content}${item.remediation ? ` Remediation: ${item.remediation}` : ""}`, MAX_CHUNK_CHARACTERS),
      category: sanitizeInputText(item.category || "", 100),
      framework: sanitizeInputText(item.framework || "", 100),
      control_id: sanitizeInputText(item.control_id || "", 100),
      remediation: sanitizeInputText(item.remediation || "", 1000),
      source: "static_compliance",
      timestamp: Date.now(),
    }));

    // Generate embeddings in worker batch
    const batchPayload = chunks.map((c) => ({ id: c.id, text: c.content }));
    const batchRes = await this.postWorkerMessage("EMBED_BATCH", { items: batchPayload });
    const vectors: RAGVector[] = batchRes.results.map((r: any) => ({
      id: r.id,
      vector: r.embedding,
    }));

    // Save to IndexedDB
    await clientRAGStore.saveChunks(chunks);
    await clientRAGStore.saveVectors(vectors);
  }

  /**
   * Ingests dynamic scan telemetry and findings into the persistent client RAG index
   */
  public async ingestScanTelemetry(scanId: string, cloud: string, findings: Array<{ id: string; title: string; description: string; severity: string }>): Promise<void> {
    if (!findings || findings.length === 0) return;
    await this.init();

    // Check storage quotas to prevent DoS via quota exhaustion
    const currentCounts = await clientRAGStore.count();
    if (currentCounts.chunks + findings.length > MAX_TOTAL_CHUNKS) {
      console.warn(`[Client RAG] Ingestion quota exceeded (${currentCounts.chunks} chunks). Truncating scan items to prevent DoS.`);
      findings = findings.slice(0, Math.max(0, MAX_TOTAL_CHUNKS - currentCounts.chunks));
    }
    if (findings.length === 0) return;

    const sanitizedScanId = sanitizeInputText(scanId, 64);
    const sanitizedCloud = sanitizeInputText(cloud, 32);

    const chunks: RAGChunk[] = findings.map((f) => ({
      id: sanitizeInputText(`scan_${sanitizedScanId}_${f.id}`, 100),
      title: sanitizeInputText(`[${sanitizedCloud.toUpperCase()} Finding] ${f.title}`, 200),
      content: sanitizeInputText(`Scan ${sanitizedScanId} (${sanitizedCloud.toUpperCase()}) Severity: ${f.severity}. ${f.title} - ${f.description}`, MAX_CHUNK_CHARACTERS),
      category: "Scan Finding",
      source: "scan_telemetry",
      metadata: { scanId: sanitizedScanId, cloud: sanitizedCloud, severity: sanitizeInputText(f.severity, 32) },
      timestamp: Date.now(),
    }));

    const batchPayload = chunks.map((c) => ({ id: c.id, text: c.content }));
    const batchRes = await this.postWorkerMessage("EMBED_BATCH", { items: batchPayload });
    const vectors: RAGVector[] = batchRes.results.map((r: any) => ({
      id: r.id,
      vector: r.embedding,
    }));

    await clientRAGStore.saveChunks(chunks);
    await clientRAGStore.saveVectors(vectors);
    const newCount = await clientRAGStore.count();
    this.chunkCount = newCount.chunks;
    this.vectorCount = newCount.vectors;
    this.notifyStatus();
  }

  /**
   * Ingests user security memories and architectural notes into persistent RAG
   */
  public async ingestUserMemories(memories: Array<{ key: string; content: string; category?: string }>): Promise<void> {
    if (!memories || memories.length === 0) return;
    await this.init().catch(() => {});

    const currentCounts = await clientRAGStore.count();
    if (currentCounts.chunks + memories.length > MAX_TOTAL_CHUNKS) {
      console.warn(`[Client RAG] Memory ingestion quota exceeded. Limiting memories.`);
      memories = memories.slice(0, Math.max(0, MAX_TOTAL_CHUNKS - currentCounts.chunks));
    }
    if (memories.length === 0) return;

    const chunks: RAGChunk[] = memories.map((m) => {
      const sanitizedKey = sanitizeInputText(m.key, 100);
      const sanitizedCategory = sanitizeInputText(m.category || "general", 50);
      return {
        id: `mem_${sanitizedKey}`,
        title: `[User Memory] ${sanitizedKey}`,
        content: sanitizeInputText(`Architectural context [${sanitizedKey} (${sanitizedCategory})]: ${m.content}`, MAX_CHUNK_CHARACTERS),
        category: sanitizedCategory,
        source: "user_memory",
        timestamp: Date.now(),
      };
    });

    const batchPayload = chunks.map((c) => ({ id: c.id, text: c.content }));
    const batchRes = await this.postWorkerMessage("EMBED_BATCH", { items: batchPayload });
    const vectors: RAGVector[] = batchRes.results.map((r: any) => ({
      id: r.id,
      vector: r.embedding,
    }));

    await clientRAGStore.saveChunks(chunks);
    await clientRAGStore.saveVectors(vectors);
    const newCount = await clientRAGStore.count();
    this.chunkCount = newCount.chunks;
    this.vectorCount = newCount.vectors;
    this.notifyStatus();
  }

  /**
   * Vector similarity search with hybrid keyword matching over IndexedDB persistent vectors
   * Protected with a 2.5s fail-safe timeout so AI chat never stalls
   */
  public async retrieveContext(queryText: string, topK: number = 5): Promise<SearchResult[]> {
    const sanitizedQuery = sanitizeInputText(queryText, MAX_QUERY_LENGTH);
    if (!sanitizedQuery) return [];

    // Allow quick init check with 1.5s max wait
    if (!this.isReady && this.initPromise) {
      const quickInit = new Promise((resolve) => setTimeout(resolve, 1500));
      await Promise.race([this.initPromise, quickInit]).catch(() => {});
    }

    try {
      const [allChunks, allVectors] = await Promise.all([
        clientRAGStore.getAllChunks(),
        clientRAGStore.getAllVectors(),
      ]);

      if (allVectors.length === 0) return [];

      const candidateTexts: Record<string, string> = {};
      const chunkMap = new Map<string, RAGChunk>();
      for (const chunk of allChunks) {
        candidateTexts[chunk.id] = chunk.content;
        chunkMap.set(chunk.id, chunk);
      }

      const searchPromise = this.postWorkerMessage("VECTOR_SEARCH", {
        queryText: sanitizedQuery,
        candidateVectors: allVectors,
        candidateTexts,
        topK: Math.min(Math.max(1, topK), 20),
      });

      // 2.5 second fail-safe timeout
      const timeoutPromise = new Promise<{ results: any[] }>((_, reject) =>
        setTimeout(() => reject(new Error("Client RAG vector search timed out")), 2500)
      );

      const searchRes = await Promise.race([searchPromise, timeoutPromise]);

      const results: SearchResult[] = [];
      for (const item of (searchRes?.results || [])) {
        const chunk = chunkMap.get(item.id);
        if (chunk) {
          results.push({
            chunk,
            score: item.score,
          });
        }
      }

      return results;
    } catch (err: any) {
      console.warn("[Client RAG] Vector search skipped or timed out:", err?.message || err);
      return [];
    }
  }
  // --- Semantic Caching ---
  public async checkSemanticCache(queryText: string): Promise<string | null> {
    const sanitizedQuery = sanitizeInputText(queryText, MAX_QUERY_LENGTH);
    if (!sanitizedQuery) return null;

    try {
      if (!this.isReady && this.initPromise) {
        const quickInit = new Promise((resolve) => setTimeout(resolve, 1500));
        await Promise.race([this.initPromise, quickInit]).catch(() => {});
      }

      const allCached = await clientRAGStore.getAllCachedResponses();
      if (allCached.length === 0) return null;

      // Create a map of vectors and texts
      const candidateVectors: any[] = [];
      const candidateTexts: any = {};
      for (const item of allCached) {
        if (item.vector) {
          candidateVectors.push({ id: item.id, vector: item.vector });
          candidateTexts[item.id] = item.query;
        }
      }

      if (candidateVectors.length === 0) return null;

      const searchPromise = this.postWorkerMessage("VECTOR_SEARCH", {
        queryText: sanitizedQuery,
        candidateVectors,
        candidateTexts,
        topK: 1,
      });

      const timeoutPromise = new Promise<{ results: any[] }>((_, reject) =>
        setTimeout(() => reject(new Error("Cache check timed out")), 1000)
      );

      const searchRes = await Promise.race([searchPromise, timeoutPromise]);
      if (searchRes?.results && searchRes.results.length > 0) {
        const topHit = searchRes.results[0];
        // 0.95 similarity threshold for semantic cache hit
        if (topHit.score > 0.95) {
          const hit = allCached.find(c => c.id === topHit.id);
          if (hit) return hit.response;
        }
      }
    } catch (e) {
      console.warn("Semantic cache check failed:", e);
    }
    return null;
  }

  public async saveToSemanticCache(queryText: string, response: string): Promise<void> {
    const sanitizedQuery = sanitizeInputText(queryText, MAX_QUERY_LENGTH);
    if (!sanitizedQuery) return;

    try {
      const embedRes = await this.postWorkerMessage("EMBED_TEXT", { text: sanitizedQuery });
      if (embedRes?.embedding) {
        const queryId = "cache_" + Date.now() + "_" + Math.floor(Math.random() * 1000);
        
        // We need to store the vector in the semantic_cache store as well
        // We'll update client-rag-store.ts to handle this correctly.
        const db = await clientRAGStore["getDB"]();
        const tx = db.transaction("semantic_cache", "readwrite");
        const store = tx.objectStore("semantic_cache");
        store.put({ 
          id: queryId, 
          query: sanitizedQuery, 
          response, 
          vector: embedRes.embedding,
          timestamp: Date.now() 
        });
      }
    } catch (e) {
      console.warn("Failed to save to semantic cache", e);
    }
  }
}

// Export singleton instance
export const clientRAGEngine = new ClientRAGEngine();
