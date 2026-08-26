import { NextRequest, NextResponse } from "next/server";
import * as cheerio from "cheerio";

export const runtime = "edge";

// Basic SSRF protection (simplified for edge, relying heavily on DDG not being an open proxy)
// We only ever request duckduckgo HTML search.
function validateWebUrlSafety(urlStr: string): boolean {
  try {
    const url = new URL(urlStr);
    if (!["http:", "https:"].includes(url.protocol)) return false;
    
    // Prevent obvious local IP hits from DDG results
    const host = url.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || host.includes("internal")) {
      return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

export async function POST(req: NextRequest) {
  try {
    const { query, max_results = 3 } = await req.json();
    
    if (!query) {
      return NextResponse.json({ results: [] }, { status: 400 });
    }

    const encodedQuery = encodeURIComponent(query);
    const searchUrl = `https://html.duckduckgo.com/html/?q=${encodedQuery}`;

    // Add random-ish user agent to avoid basic blocks
    const response = await fetch(searchUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
      },
    });

    if (!response.ok) {
      console.warn("Edge web search failed with status:", response.status);
      return NextResponse.json({ results: [] }, { status: 500 });
    }

    const html = await response.text();
    const $ = cheerio.load(html);
    
    const results: Array<{title: string, snippet: string, url: string}> = [];
    
    // DuckDuckGo HTML results parsing
    $(".result__body").each((i, el) => {
      if (i >= max_results) return false;
      
      const titleElem = $(el).find("h2 a.result__a");
      const snippetElem = $(el).find("a.result__snippet");
      
      const rawTitle = titleElem.text().trim();
      const rawSnippet = snippetElem.text().trim();
      let rawUrl = titleElem.attr("href") || "";
      
      // Clean up DDG redirect URLs
      const urlMatch = rawUrl.match(/uddg=([^&]+)/);
      if (urlMatch && urlMatch[1]) {
        rawUrl = decodeURIComponent(urlMatch[1]);
      }
      
      if (validateWebUrlSafety(rawUrl) && rawSnippet) {
        results.push({
          title: rawTitle,
          snippet: rawSnippet,
          url: rawUrl
        });
      }
    });

    return NextResponse.json({ results });
  } catch (error: any) {
    console.error("Edge search error:", error);
    return NextResponse.json({ error: error.message, results: [] }, { status: 500 });
  }
}
