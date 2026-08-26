import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization") || "";
    const body = await req.json();

    const envBackend = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_BACKEND_URL;
    const candidates = (process.env.NODE_ENV === "development"
      ? ["http://localhost:8000", envBackend, "http://127.0.0.1:8000"]
      : [envBackend, "http://localhost:8000", "http://127.0.0.1:8000"]).filter(Boolean) as string[];
    const uniqueBackends = Array.from(new Set(candidates.map((u) => u.replace(/\/$/, ""))));

    for (const backendUrl of uniqueBackends) {
      try {
        const targetUrl = `${backendUrl}/ai/export`;
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        if (authHeader) headers["Authorization"] = authHeader;

        const res = await fetch(targetUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(15000)
        });

        if (res.ok) {
          const blob = await res.arrayBuffer();
          const contentType = res.headers.get("content-type") || "application/octet-stream";
          return new NextResponse(blob, {
            status: 200,
            headers: {
              "Content-Type": contentType,
              "Content-Disposition": res.headers.get("content-disposition") || 'attachment; filename="authmap_report.txt"',
            }
          });
        }

        if (res.status === 404 || res.status >= 500) {
          continue;
        }

        const errJson = await res.json().catch(() => ({ detail: "Export failed" }));
        return NextResponse.json(errJson, { status: res.status });
      } catch (err) {
        continue;
      }
    }

    return NextResponse.json({ detail: "AI export service unavailable" }, { status: 503 });
  } catch (error: any) {
    return NextResponse.json({ detail: error.message || "Internal server error" }, { status: 500 });
  }
}
