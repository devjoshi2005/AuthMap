import { pipeline, env } from "@xenova/transformers";

// Configure transformers.js for Web Worker environment
env.allowLocalModels = false;
env.useBrowserCache = true;
if (env.backends && env.backends.onnx && env.backends.onnx.wasm) {
  env.backends.onnx.wasm.numThreads = 1;
  env.backends.onnx.wasm.simd = true;
}

// Pipeline singleton inside the worker
let featureExtractor: any = null;
let isInitializing = false;

async function getExtractor(onProgress?: (data: any) => void) {
  if (featureExtractor) return featureExtractor;
  if (isInitializing) {
    // Wait until initialized
    while (isInitializing) {
      await new Promise((r) => setTimeout(r, 50));
    }
    return featureExtractor;
  }

  isInitializing = true;
  try {
    featureExtractor = await pipeline("feature-extraction", "Xenova/all-MiniLM-L6-v2", {
      quantized: true,
      progress_callback: onProgress,
    });
  } catch (err) {
    console.error("[Embedding Worker] Failed to initialize pipeline:", err);
    throw err;
  } finally {
    isInitializing = false;
  }
  return featureExtractor;
}

// Compute cosine similarity between two L2-normalized float arrays
function cosineSimilarity(a: Float32Array | number[], b: Float32Array | number[]): number {
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  const len = a.length;
  for (let i = 0; i < len; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

// Keyword token match booster
function computeKeywordBoost(query: string, text: string): number {
  const queryTokens = query.toLowerCase().split(/[\s,._:/-]+/).filter((t) => t.length > 2);
  const textLower = text.toLowerCase();
  let matches = 0;
  for (const token of queryTokens) {
    if (textLower.includes(token)) {
      matches += 1;
    }
  }
  return queryTokens.length > 0 ? (matches / queryTokens.length) * 0.15 : 0;
}

// Message handler for Web Worker
self.addEventListener("message", async (event: MessageEvent) => {
  const { id, type, payload } = event.data;

  try {
    if (type === "INIT") {
      await getExtractor((progress) => {
        self.postMessage({
          id,
          type: "PROGRESS",
          payload: progress,
        });
      });

      self.postMessage({
        id,
        type: "INIT_COMPLETE",
        payload: { success: true, model: "Xenova/all-MiniLM-L6-v2" },
      });
    } else if (type === "EMBED_TEXT") {
      const extractor = await getExtractor();
      const output = await extractor(payload.text, { pooling: "mean", normalize: true });
      const embedding = Array.from(output.data as Float32Array);

      self.postMessage({
        id,
        type: "EMBED_COMPLETE",
        payload: { embedding },
      });
    } else if (type === "EMBED_BATCH") {
      const extractor = await getExtractor();
      const rawItems: { id: string; text: string }[] = payload.items || [];
      // Enforce safe batch size to avoid memory spikes
      const items = rawItems.slice(0, 100);
      const results: { id: string; embedding: number[] }[] = [];

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        // Truncate text per item to safe limit
        const safeText = (item.text || "").substring(0, 4000);
        const output = await extractor(safeText, { pooling: "mean", normalize: true });
        results.push({
          id: item.id,
          embedding: Array.from(output.data as Float32Array),
        });

        // Micro-yield every 8 items to keep worker responsive and allow GC
        if ((i + 1) % 8 === 0) {
          await new Promise((r) => setTimeout(r, 0));
        }

        // Report batch progress
        if ((i + 1) % 5 === 0 || i === items.length - 1) {
          self.postMessage({
            id,
            type: "BATCH_PROGRESS",
            payload: { current: i + 1, total: items.length },
          });
        }
      }

      self.postMessage({
        id,
        type: "BATCH_COMPLETE",
        payload: { results },
      });
    } else if (type === "VECTOR_SEARCH") {
      const extractor = await getExtractor();
      const { queryText, candidateVectors, candidateTexts, topK = 5 } = payload;

      // 1. Embed query
      const queryOutput = await extractor(queryText, { pooling: "mean", normalize: true });
      const queryVec = queryOutput.data as Float32Array;

      // 2. Compute similarity for all candidate vectors
      const scored: { id: string; score: number }[] = [];

      for (let i = 0; i < candidateVectors.length; i++) {
        const item = candidateVectors[i];
        const rawSim = cosineSimilarity(queryVec, item.vector);

        // Optional keyword boost for exact technical terms
        const text = candidateTexts ? candidateTexts[item.id] || "" : "";
        const boost = text ? computeKeywordBoost(queryText, text) : 0;
        const finalScore = rawSim + boost;

        scored.push({
          id: item.id,
          score: finalScore,
        });
      }

      // 3. Sort descending and take topK
      scored.sort((a, b) => b.score - a.score);
      const topResults = scored.slice(0, topK);

      self.postMessage({
        id,
        type: "SEARCH_COMPLETE",
        payload: { results: topResults },
      });
    } else {
      self.postMessage({
        id,
        type: "ERROR",
        error: `Unknown action type: ${type}`,
      });
    }
  } catch (err: any) {
    console.error("[Embedding Worker Error]:", err);
    self.postMessage({
      id,
      type: "ERROR",
      error: err.message || String(err),
    });
  }
});
