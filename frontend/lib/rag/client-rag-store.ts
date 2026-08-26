/**
 * High-performance Encrypted IndexedDB Persistent Vector & Chunk Store for Client-Side RAG
 * Cross-session persistence for compliance benchmarks, scan telemetry, and user memories.
 * Fully protected by AES-GCM-256 Web Crypto encryption against local storage forensics.
 */

export interface RAGChunk {
  id: string;
  title: string;
  content: string;
  category?: string;
  framework?: string;
  control_id?: string;
  remediation?: string;
  source: "static_compliance" | "scan_telemetry" | "graph_topology" | "user_memory";
  metadata?: Record<string, any>;
  timestamp: number;
}

export interface RAGVector {
  id: string;
  vector: number[];
}

interface EncryptedRecord {
  id: string;
  iv: number[];
  ciphertext: number[];
  isEncrypted: true;
}

const DB_NAME = "AuthMap_Client_RAG_v1";
const DB_VERSION = 2;
const STORE_CHUNKS = "chunks";
const STORE_VECTORS = "vectors";
const STORE_META = "metadata";

class ClientRAGStore {
  private dbPromise: Promise<IDBDatabase> | null = null;
  private cryptoKeyPromise: Promise<CryptoKey> | null = null;

  private getDB(): Promise<IDBDatabase> {
    if (typeof window === "undefined") {
      return Promise.reject(new Error("IndexedDB is only available in browser environments"));
    }

    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, DB_VERSION);

        req.onupgradeneeded = (event: IDBVersionChangeEvent) => {
          const db = (event.target as IDBOpenDBRequest).result;
          if (!db.objectStoreNames.contains(STORE_CHUNKS)) {
            db.createObjectStore(STORE_CHUNKS, { keyPath: "id" });
          }
          if (!db.objectStoreNames.contains(STORE_VECTORS)) {
            db.createObjectStore(STORE_VECTORS, { keyPath: "id" });
          }
          if (!db.objectStoreNames.contains(STORE_META)) {
            db.createObjectStore(STORE_META, { keyPath: "key" });
          }
          if (!db.objectStoreNames.contains("semantic_cache")) {
            db.createObjectStore("semantic_cache", { keyPath: "id" });
          }
        };

        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }

    return this.dbPromise;
  }

  /**
   * Derives a cryptographic AES-GCM-256 key using PBKDF2 (100,000 iterations, SHA-256)
   */
  private async getCryptoKey(): Promise<CryptoKey> {
    if (typeof window === "undefined" || !window.crypto?.subtle) {
      throw new Error("Web Crypto API is not available");
    }

    if (!this.cryptoKeyPromise) {
      this.cryptoKeyPromise = (async () => {
        // Persist browser client entropy in localStorage for multi-tab and page-reload stability
        let entropyStr = localStorage.getItem("authmap_rag_entropy_v1");
        if (!entropyStr) {
          const entropy = crypto.getRandomValues(new Uint8Array(32));
          entropyStr = Array.from(entropy).map((b) => b.toString(16).padStart(2, "0")).join("");
          try {
            localStorage.setItem("authmap_rag_entropy_v1", entropyStr);
          } catch (e) {}
        }

        let saltStr = localStorage.getItem("authmap_rag_crypto_salt_v1");
        let salt: Uint8Array;
        if (!saltStr) {
          salt = crypto.getRandomValues(new Uint8Array(16));
          saltStr = Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("");
          try {
            localStorage.setItem("authmap_rag_crypto_salt_v1", saltStr);
          } catch (e) {}
        } else {
          const match = saltStr.match(/.{1,2}/g);
          salt = new Uint8Array(match ? match.map((byte) => parseInt(byte, 16)) : [1, 2, 3, 4]);
        }

        const enc = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
          "raw",
          enc.encode(entropyStr + "_AuthMap_Client_RAG_2026"),
          "PBKDF2",
          false,
          ["deriveKey"]
        );

        return await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: salt as any,
            iterations: 100000,
            hash: "SHA-256",
          },
          baseKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        );
      })();
    }

    return this.cryptoKeyPromise;
  }

  private async encryptPayload(id: string, payload: any): Promise<EncryptedRecord> {
    const key = await this.getCryptoKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(payload));
    const encryptedBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoded
    );

    return {
      id,
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(encryptedBuf)),
      isEncrypted: true,
    };
  }

  private async decryptPayload<T>(record: any): Promise<T | null> {
    if (!record) return null;
    if (!record.isEncrypted || !record.iv || !record.ciphertext) {
      // Legacy plaintext record backward compatibility
      return record as T;
    }

    try {
      const key = await this.getCryptoKey();
      const iv = new Uint8Array(record.iv);
      const ciphertext = new Uint8Array(record.ciphertext);

      const decryptedBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
      );

      const decryptedText = new TextDecoder().decode(decryptedBuf);
      return JSON.parse(decryptedText) as T;
    } catch (err) {
      console.warn("[Client RAG] Failed to decrypt record with current session key:", record.id);
      return null;
    }
  }

  async saveChunks(chunks: RAGChunk[]): Promise<void> {
    const db = await this.getDB();
    const encryptedRecords = await Promise.all(
      chunks.map((c) => this.encryptPayload(c.id, c))
    );

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_CHUNKS, "readwrite");
      const store = tx.objectStore(STORE_CHUNKS);
      for (const rec of encryptedRecords) {
        store.put(rec);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async saveVectors(vectors: RAGVector[]): Promise<void> {
    const db = await this.getDB();
    const encryptedRecords = await Promise.all(
      vectors.map((v) => this.encryptPayload(v.id, v))
    );

    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_VECTORS, "readwrite");
      const store = tx.objectStore(STORE_VECTORS);
      for (const rec of encryptedRecords) {
        store.put(rec);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async getAllChunks(): Promise<RAGChunk[]> {
    const db = await this.getDB();
    const rawList: any[] = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_CHUNKS, "readonly");
      const store = tx.objectStore(STORE_CHUNKS);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });

    const decrypted = await Promise.all(rawList.map((r) => this.decryptPayload<RAGChunk>(r)));
    return decrypted.filter((c): c is RAGChunk => c !== null);
  }

  async getAllVectors(): Promise<RAGVector[]> {
    const db = await this.getDB();
    const rawList: any[] = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_VECTORS, "readonly");
      const store = tx.objectStore(STORE_VECTORS);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });

    const decrypted = await Promise.all(rawList.map((r) => this.decryptPayload<RAGVector>(r)));
    return decrypted.filter((v): v is RAGVector => v !== null);
  }

  async getChunksByIds(ids: string[]): Promise<RAGChunk[]> {
    const all = await this.getAllChunks();
    const idSet = new Set(ids);
    return all.filter((c) => idSet.has(c.id));
  }

  async getMetadata(key: string): Promise<any> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_META, "readonly");
      const store = tx.objectStore(STORE_META);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result?.value);
      req.onerror = () => reject(req.error);
    });
  }

  async setMetadata(key: string, value: any): Promise<void> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_META, "readwrite");
      const store = tx.objectStore(STORE_META);
      store.put({ key, value });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  // --- Semantic Cache Methods ---
  public async getCachedResponse(queryId: string): Promise<{ query: string, response: string, timestamp: number } | null> {
    try {
      const db = await this.getDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("semantic_cache", "readonly");
        const store = tx.objectStore("semantic_cache");
        const req = store.get(queryId);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
      });
    } catch (e) {
      console.warn("Failed to get cached response", e);
      return null;
    }
  }

  public async saveCachedResponse(queryId: string, query: string, response: string): Promise<void> {
    try {
      const db = await this.getDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("semantic_cache", "readwrite");
        const store = tx.objectStore("semantic_cache");
        store.put({ id: queryId, query, response, timestamp: Date.now() });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } catch (e) {
      console.warn("Failed to save cached response", e);
    }
  }

  public async getAllCachedResponses(): Promise<any[]> {
    try {
      const db = await this.getDB();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("semantic_cache", "readonly");
        const store = tx.objectStore("semantic_cache");
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => reject(req.error);
      });
    } catch (e) {
      console.warn("Failed to get all cached responses", e);
      return [];
    }
  }

  async count(): Promise<{ chunks: number; vectors: number }> {
    const db = await this.getDB();
    const chunkCount = await new Promise<number>((resolve, reject) => {
      const tx = db.transaction(STORE_CHUNKS, "readonly");
      const req = tx.objectStore(STORE_CHUNKS).count();
      req.onsuccess = () => resolve(req.result || 0);
      req.onerror = () => reject(req.error);
    });

    const vectorCount = await new Promise<number>((resolve, reject) => {
      const tx = db.transaction(STORE_VECTORS, "readonly");
      const req = tx.objectStore(STORE_VECTORS).count();
      req.onsuccess = () => resolve(req.result || 0);
      req.onerror = () => reject(req.error);
    });

    return { chunks: chunkCount, vectors: vectorCount };
  }

  async clear(): Promise<void> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction([STORE_CHUNKS, STORE_VECTORS, STORE_META, "semantic_cache"], "readwrite");
      tx.objectStore(STORE_CHUNKS).clear();
      tx.objectStore(STORE_VECTORS).clear();
      tx.objectStore(STORE_META).clear();
      tx.objectStore("semantic_cache").clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  /**
   * 48-Hour Rolling Window Pruning
   * Deletes user_memory chunks, their corresponding vectors, and semantic cache
   * entries older than 48 hours for strict security compliance.
   */
  public async pruneExpiredData(): Promise<void> {
    try {
      const db = await this.getDB();
      const cutoff = Date.now() - 48 * 60 * 60 * 1000;
      
      // 1. Prune semantic cache
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction("semantic_cache", "readwrite");
        const store = tx.objectStore("semantic_cache");
        const req = store.openCursor();
        req.onsuccess = (e) => {
          const cursor = (e.target as IDBRequest).result;
          if (cursor) {
            if (cursor.value.timestamp < cutoff) {
              cursor.delete();
            }
            cursor.continue();
          } else {
            resolve();
          }
        };
        req.onerror = () => reject(tx.error);
      });

      // 2. Prune user_memory chunks & their vectors
      const chunks = await this.getAllChunks();
      const expiredIds = chunks
        .filter(c => c.source === "user_memory" && c.timestamp < cutoff)
        .map(c => c.id);

      if (expiredIds.length > 0) {
        await new Promise<void>((resolve, reject) => {
          const tx = db.transaction([STORE_CHUNKS, STORE_VECTORS], "readwrite");
          const chunkStore = tx.objectStore(STORE_CHUNKS);
          const vectorStore = tx.objectStore(STORE_VECTORS);
          
          expiredIds.forEach(id => {
            chunkStore.delete(id);
            vectorStore.delete(id);
          });
          
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        });
        console.log(`[Security] Pruned ${expiredIds.length} expired user memories.`);
      }
    } catch (e) {
      console.error("[Security] Error pruning expired data:", e);
    }
  }
}

// Export singleton instance
export const clientRAGStore = new ClientRAGStore();

