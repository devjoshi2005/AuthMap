import { NextRequest, NextResponse } from "next/server";

function getCandidateBackends(): string[] {
  const envBackend = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_BACKEND_URL;
  const candidates = (process.env.NODE_ENV === "development"
    ? ["http://localhost:8000", envBackend, "http://127.0.0.1:8000"]
    : [envBackend, "http://localhost:8000", "http://127.0.0.1:8000"]).filter(Boolean) as string[];
  return Array.from(new Set(candidates.map((u) => u.replace(/\/$/, ""))));
}

export async function GET(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization") || "";
    const backends = getCandidateBackends();

    for (const backend of backends) {
      try {
        const res = await fetch(`${backend}/ai/memory`, {
          headers: authHeader ? { Authorization: authHeader } : {},
          signal: AbortSignal.timeout(10000),
        });
        if (res.ok) {
          const data = await res.json();
          return NextResponse.json(data);
        }
      } catch (e) {
        continue;
      }
    }
    return NextResponse.json([], { status: 200 });
  } catch (error: any) {
    return NextResponse.json({ detail: error.message || "Error fetching memories" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization") || "";
    const body = await req.json();
    const backends = getCandidateBackends();

    for (const backend of backends) {
      try {
        const res = await fetch(`${backend}/ai/memory`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(authHeader ? { Authorization: authHeader } : {}),
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10000),
        });
        if (res.ok) {
          const data = await res.json();
          return NextResponse.json(data);
        }
      } catch (e) {
        continue;
      }
    }
    return NextResponse.json({ detail: "Backend unavailable" }, { status: 503 });
  } catch (error: any) {
    return NextResponse.json({ detail: error.message || "Error saving memory note" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const authHeader = req.headers.get("authorization") || "";
    const { searchParams } = new URL(req.url);
    const key = searchParams.get("key");
    if (!key) {
      return NextResponse.json({ detail: "Missing memory key" }, { status: 400 });
    }

    const backends = getCandidateBackends();
    for (const backend of backends) {
      try {
        const res = await fetch(`${backend}/ai/memory/${encodeURIComponent(key)}`, {
          method: "DELETE",
          headers: authHeader ? { Authorization: authHeader } : {},
          signal: AbortSignal.timeout(10000),
        });
        if (res.ok) {
          const data = await res.json();
          return NextResponse.json(data);
        }
      } catch (e) {
        continue;
      }
    }
    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json({ detail: error.message || "Error deleting memory" }, { status: 500 });
  }
}
