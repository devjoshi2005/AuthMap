import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization") || "";

    const body = await req.json();

    // Use configured environment backend URL first, fallback to dev local server if unreachable
    const envBackend = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_BACKEND_URL;
    const candidates = (process.env.NODE_ENV === "development"
      ? ["http://localhost:8000", envBackend, "http://127.0.0.1:8000"]
      : [envBackend, "http://localhost:8000", "http://127.0.0.1:8000"]).filter(Boolean) as string[];
    const uniqueBackends = Array.from(new Set(candidates.map((u) => u.replace(/\/$/, ""))));

    let lastError: any = null;

    for (const backendUrl of uniqueBackends) {
      try {
        const targetUrl = `${backendUrl}/ai/chat`;
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        if (authHeader) headers["Authorization"] = authHeader;

        const res = await fetch(targetUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(60000), // Increased from 15s to 60s for LLM processing
        });

        if (res.ok) {
          if (body.stream) {
            return new Response(res.body, {
              headers: {
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
              },
            });
          } else {
            const data = await res.json();
            return NextResponse.json(data);
          }
        }

        // If 404 (endpoint not deployed on this backend) or 502/503, try next candidate
        if (res.status === 404 || res.status >= 500) {
          const text = await res.text().catch(() => "");
          lastError = new Error(`Backend at ${backendUrl} returned ${res.status}: ${text}`);
          continue;
        }

        // For 401 or 422, return directly
        const errJson = await res.json().catch(() => ({ detail: "Backend error" }));
        return NextResponse.json(errJson, { status: res.status });
      } catch (err: any) {
        lastError = err;
        continue;
      }
    }

    return NextResponse.json(
      {
        detail: `Could not reach an active AuthMap AI backend service. ${lastError?.message || "Please ensure the backend service on port 8000 is running."}`,
      },
      { status: 503 }
    );
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Internal server error in AI proxy" },
      { status: 500 }
    );
  }
}
