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

    async def should_search_web(self, query: str) -> bool:
        """Dynamically determines if a query requires live web search using a fast LLM."""
        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY"))
            prompt = (
                f"Does this query require looking up recent news, breaking CVEs, or real-time external knowledge "
                f"that wouldn't be in a static database? Query: '{query}'\n\n"
                f"Reply strictly with 'YES' or 'NO'."
            )
            resp = await client.chat.completions.create(
                model="openai/gpt-oss-20b",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=10,
                temperature=0
            )
            content = (resp.choices[0].message.content or "").strip().upper()
            return "YES" in content
        except Exception as e:
            logger.debug(f"Dynamic web search trigger fallback to false: {e}")
            return False

    async def search(self, query: str, max_results: int = 4) -> List[Dict[str, str]]:
        """Performs a lightweight, real-time search with zero dependencies on paid APIs and strict SSRF filtering."""
        results = []
        clean_q = normalize_and_clean_input(query)
        try:
            # DuckDuckGo HTML search endpoint
            encoded_query = httpx.URL("", params={"q": clean_q}).query.decode("utf-8")
            url = f"https://html.duckduckgo.com/html/?{encoded_query}"

            async with httpx.AsyncClient(headers=SEARCH_HEADERS, timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    results = self._parse_ddg_html(resp.text, max_results)

        except Exception as e:
            logger.warning(f"Live web search failed for query '{clean_q}': {e}")

        return results

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
