import os
import re
import html
import logging
from typing import List, Dict, Any, Optional
import httpx
from collectors.ai_security_guardrails import (
    normalize_and_clean_input,
    validate_web_url_safety,
    sanitize_web_snippet,
)

logger = logging.getLogger(__name__)

SEARCH_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

from bs4 import BeautifulSoup
from urllib.parse import unquote

class LiveWebSearchAgent:
    """Optimized real-time Web Search Fallback for live GRC, CVE, and cloud security updates with SSRF protection."""

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    NEWS_HINTS = re.compile(
        r"\b(latest|news|today|current|currently|recent|recently|breaking|update[sd]?|"
        r"new\s+(law|rule|policy|regulation|draft)|amend(ed|ment)?|announce[sd]?|"
        r"trend|roadmap|upcoming|deadline|20(2[4-9]|3[0-9])|cve-\d+|advisory|"
        r"future|foreseeable|outlook|timeline)\b",
        re.IGNORECASE,
    )

    async def should_search_web(self, query: str) -> bool:
        """Fast keyword gate — no LLM round-trip (saves 1-2s per request)."""
        return bool(self.NEWS_HINTS.search(query or ""))

    _cache: Dict[str, tuple] = {}
    _CACHE_TTL = 600.0

    async def search(self, query: str, max_results: int = 4) -> List[Dict[str, str]]:
        """Live search with cache: Google News RSS first, DuckDuckGo HTML fallback."""
        import time
        clean_q = normalize_and_clean_input(query)
        cache_key = clean_q.strip().lower()
        cached = self._cache.get(cache_key)
        if cached and (time.time() - cached[1]) < self._CACHE_TTL:
            return cached[0]

        results: List[Dict[str, str]] = []
        try:
            async with httpx.AsyncClient(headers=SEARCH_HEADERS, timeout=self.timeout, follow_redirects=True) as client:
                results = await self._search_google_news(client, clean_q, max_results)
                if not results:
                    results = await self._search_duckduckgo(client, clean_q, max_results)
        except Exception as e:
            logger.warning(f"Live web search failed for query '{clean_q}': {e}")

        if results:
            self._cache[cache_key] = (results, time.time())
        return results

    async def _search_google_news(self, client, query: str, max_results: int) -> List[Dict[str, str]]:
        """Google News RSS: reliable from data centres, no API key."""
        import xml.etree.ElementTree as ET
        resp = await client.get(
            "https://news.google.com/rss/search",
            params={"q": query, "hl": "en-IN", "gl": "IN", "ceid": "IN:en"},
        )
        if resp.status_code != 200:
            return []
        out = []
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError:
            return []
        for item in root.iter("item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()
            source_el = item.find("source")
            source = (source_el.text.strip() if source_el is not None and source_el.text else "")
            if not title:
                continue
            snippet = " — ".join(x for x in [source, pub] if x)
            out.append({
                "title": sanitize_web_snippet(title)[:200],
                "snippet": sanitize_web_snippet(snippet)[:240],
                "url": link if validate_web_url_safety(link) else "",
            })
            if len(out) >= max_results:
                break
        return out

    async def _search_duckduckgo(self, client, query: str, max_results: int) -> List[Dict[str, str]]:
        encoded_query = httpx.URL("", params={"q": query}).query.decode("utf-8")
        resp = await client.get(f"https://html.duckduckgo.com/html/?{encoded_query}")
        if resp.status_code == 200:
            return self._parse_ddg_html(resp.text, max_results)
        return []

    def _parse_ddg_html(self, html_text: str, max_results: int) -> List[Dict[str, str]]:
        """Parses search snippets and URLs using standard BeautifulSoup HTML parser with SSRF & nh3 XSS sanitization."""
        results = []
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            result_divs = soup.find_all("div", class_=lambda c: c and "results_links" in c)

            for div in result_divs[:max_results]:
                snippet_elem = div.find("a", class_=lambda c: c and "result__snippet" in c)
                title_elem = div.find("a", class_=lambda c: c and "result__a" in c)

                raw_snippet = snippet_elem.get_text() if snippet_elem else ""
                clean_snippet = sanitize_web_snippet(raw_snippet)

                raw_title = title_elem.get_text() if title_elem else "Web Reference"
                clean_title = sanitize_web_snippet(raw_title)

                raw_url = title_elem.get("href", "") if title_elem else ""
                url_match = re.search(r"uddg=([^&]+)", raw_url)
                extracted_link = unquote(url_match.group(1)) if url_match else raw_url

                # SSRF Filter: Ensure URL is public and valid
                link = extracted_link if validate_web_url_safety(extracted_link) else ""

                if clean_snippet:
                    results.append({
                        "title": clean_title or "Web Reference",
                        "snippet": clean_snippet,
                        "url": link
                    })
        except Exception as e:
            logger.error(f"Error parsing search HTML: {e}")

        return results

# Singleton instance
_web_search_agent = LiveWebSearchAgent()

def get_web_search_agent() -> LiveWebSearchAgent:
    return _web_search_agent
