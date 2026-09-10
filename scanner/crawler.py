"""
NayVista Shield - Safe Same-Origin Crawler
Performs conservative, throttled asynchronous web discovery:
- Strictly bound to target origin.
- Max 15 pages, Max depth 2.
- Concurrency limited to 3 workers.
- 100ms rate-throttling between requests.
- Response size limit 2MB.
- Robots.txt parsing.
- Robust handling for real-world DNS, TLS, timeout, 403/429/5xx, and CDN responses.
"""

import asyncio
import time
from urllib.parse import urlparse
from typing import List, Dict, Set, Any, Optional
import httpx
from bs4 import BeautifulSoup
from scanner.scope import TargetScope
from scanner.config import (
    USER_AGENT,
    MAX_PAGES,
    MAX_DEPTH,
    MAX_CONCURRENCY,
    REQUEST_THROTTLE_SECONDS,
    RESPONSE_MAX_BYTES,
    TIMEOUT_SECONDS,
    MAX_REDIRECTS,
)

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".mp4", ".mp3", ".avi", ".mov", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".exe", ".dmg", ".iso", ".apk", ".bin"
}

class CrawledPage:
    def __init__(self, url: str, status_code: int, headers: httpx.Headers, text: str, depth: int, elapsed_ms: float):
        self.url = url
        self.status_code = status_code
        self.headers = dict(headers)
        self.text = text
        self.depth = depth
        self.elapsed_ms = elapsed_ms
        self.soup: Optional[BeautifulSoup] = None

    def get_soup(self) -> BeautifulSoup:
        if self.soup is None:
            self.soup = BeautifulSoup(self.text, "html.parser")
        return self.soup

class SafeCrawler:
    def __init__(self, scope: TargetScope, max_pages: int = MAX_PAGES, max_depth: int = MAX_DEPTH, max_crawl_duration: float = 18.0, on_activity: Optional[Any] = None):
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_crawl_duration = max_crawl_duration
        self.on_activity = on_activity
        self.visited_urls: Set[str] = set()
        self.pages: List[CrawledPage] = []
        self.disallowed_paths: List[str] = []
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        # Operational diagnostics for real-world online assessment
        self.crawl_error: Optional[str] = None
        self.crawl_error_code: Optional[str] = None
        self.crawl_error_category: Optional[str] = None
        self.initial_status_code: Optional[int] = None
        self.waf_or_blocked: bool = False
        self.rate_limited: bool = False
        self.server_error: bool = False
        self.tls_verification_failed: bool = False
        self.tls_error_detail: Optional[str] = None
        self.crawl_budget_exceeded: bool = False
        self.slow_pages: List[str] = []
        self.limitations: List[Dict[str, Any]] = []
        self.queue: List[tuple[str, int]] = []
        self._insecure_mode: bool = False
        self.start_time: float = time.time()

    def _emit_activity(self, msg: str):
        if self.on_activity:
            try:
                self.on_activity(msg)
            except Exception:
                pass

    async def _fetch_robots_txt(self, client: httpx.AsyncClient):
        """Fetches and parses robots.txt for same-origin disallow rules."""
        robots_url = f"{self.scope.scheme}://{self.scope.hostname}:{self.scope.port}/robots.txt"
        try:
            resp = await client.get(
                robots_url,
                headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"},
                timeout=5.0
            )
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                applies_to_us = True
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("user-agent:"):
                        agent = line.split(":", 1)[1].strip().lower()
                        applies_to_us = agent in ("*", "nayvistashield", "nayvistashield-security-auditor", "sentinelscan")
                    elif applies_to_us and line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self.disallowed_paths.append(path)
                if self.disallowed_paths:
                    self._emit_activity(f"Robots.txt parsed: {len(self.disallowed_paths)} disallow rule(s) active")
        except Exception:
            pass

    def _is_path_allowed(self, path: str) -> bool:
        """Checks if a URL path is disallowed by robots.txt."""
        for disallowed in self.disallowed_paths:
            if disallowed == "/" or path.startswith(disallowed):
                return False
        return True

    def _has_binary_extension(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in BINARY_EXTENSIONS)

    async def _fetch_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
        redirect_chain: Optional[Set[str]] = None
    ) -> Optional[CrawledPage]:
        """Fetches a single page securely with size, scope, and redirect enforcement."""
        if redirect_chain is None:
            redirect_chain = set()

        if url in redirect_chain or len(redirect_chain) > MAX_REDIRECTS:
            # Prevent circular redirect loops
            return None

        redirect_chain.add(url)

        async with self.semaphore:
            # Respect rate throttle
            await asyncio.sleep(REQUEST_THROTTLE_SECONDS)

            t0 = time.perf_counter()
            try:
                headers = {
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                }

                timeout = httpx.Timeout(TIMEOUT_SECONDS, connect=5.0)

                async with client.stream(
                    "GET",
                    url,
                    headers=headers,
                    follow_redirects=False,
                    timeout=timeout,
                ) as response:
                    elapsed = (time.perf_counter() - t0) * 1000

                    # Handle HTTP redirects with per-hop same-origin and SSRF re-validation
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location")
                        if location:
                            norm_loc = self.scope.normalize_url(location, base_url=url)
                            if self.scope.is_same_origin(norm_loc):
                                return await self._fetch_url(client, norm_loc, depth, redirect_chain)
                            else:
                                # Cross-origin redirect encountered: record boundary response without following
                                return CrawledPage(url, response.status_code, response.headers, "", depth, elapsed)

                    # Skip body buffering for binary media assets
                    content_type = response.headers.get("content-type", "").lower()
                    if any(ct in content_type for ct in ("image/", "audio/", "video/", "application/pdf", "application/zip", "application/octet-stream")):
                        return CrawledPage(url, response.status_code, response.headers, "", depth, elapsed)

                    # Read body with 2MB limit
                    chunks = []
                    total_bytes = 0
                    async for chunk in response.aiter_bytes():
                        total_bytes += len(chunk)
                        if total_bytes > RESPONSE_MAX_BYTES:
                            break
                        chunks.append(chunk)

                    body = b"".join(chunks).decode("utf-8", errors="replace")
                    self._emit_activity(f"Fetched {url} (HTTP {response.status_code}, {elapsed:.0f}ms)")
                    return CrawledPage(url, response.status_code, response.headers, body, depth, elapsed)

            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException) as e:
                if depth == 0:
                    self.crawl_error_code = "TARGET_TIMEOUT"
                    self.crawl_error_category = "ASSESSMENT_LIMITATION"
                    self.crawl_error = f"Target took longer than {TIMEOUT_SECONDS} seconds to respond."
                else:
                    self.slow_pages.append(url)
                return None
            except httpx.ConnectError as e:
                err_str = str(e).lower()
                if depth == 0:
                    if "ssl" in err_str or "certificate" in err_str or "handshake" in err_str:
                        self.crawl_error_code = "TARGET_TLS_FAILURE"
                        self.crawl_error_category = "ASSESSMENT_LIMITATION"
                        self.crawl_error = f"TLS/SSL certificate connection failed: {e}"
                        self.tls_verification_failed = True
                        self.tls_error_detail = str(e)
                    elif "refused" in err_str:
                        self.crawl_error_code = "TARGET_CONNECTION_REFUSED"
                        self.crawl_error_category = "ASSESSMENT_LIMITATION"
                        self.crawl_error = "Connection was refused by target server."
                    else:
                        self.crawl_error_code = "TARGET_UNREACHABLE"
                        self.crawl_error_category = "ASSESSMENT_LIMITATION"
                        self.crawl_error = f"Target could not be reached (host unreachable): {e}"
                return None
            except (httpx.RemoteProtocolError, httpx.ReadError, ConnectionResetError) as e:
                if depth == 0:
                    self.crawl_error_code = "TARGET_CONNECTION_REFUSED"
                    self.crawl_error_category = "ASSESSMENT_LIMITATION"
                    self.crawl_error = f"Connection was reset or closed prematurely by the server: {e}"
                return None
            except httpx.NetworkError as e:
                if depth == 0:
                    self.crawl_error_code = "TARGET_UNREACHABLE"
                    self.crawl_error_category = "ASSESSMENT_LIMITATION"
                    self.crawl_error = f"Network communication failed while connecting to target: {e}"
                return None
            except Exception as e:
                if depth == 0:
                    self.crawl_error_code = "TARGET_UNREACHABLE"
                    self.crawl_error_category = "ASSESSMENT_LIMITATION"
                    self.crawl_error = f"Unexpected error while contacting target: {e}"
                return None

    async def fetch_root(self, start_url: Optional[str] = None) -> List[CrawledPage]:
        """Fetches the root target page, robots.txt, and seeds crawl queue."""
        initial_url = self.scope.normalize_url(start_url or self.scope.raw_target)
        self.visited_urls.add(initial_url)
        self.queue = [(initial_url, 0)]

        verify_ssl = not self.scope.allow_local
        limits = httpx.Limits(max_connections=MAX_CONCURRENCY, max_keepalive_connections=MAX_CONCURRENCY)

        async with httpx.AsyncClient(verify=verify_ssl, limits=limits, http2=False) as client:
            await self._fetch_robots_txt(client)

            # Attempt fetching root URL
            initial_page = await self._fetch_url(client, initial_url, depth=0)

            # If failed due to TLS error on root URL, don't crash! Re-try with non-verifying client
            if not initial_page and self.crawl_error_code == "TARGET_TLS_FAILURE" and verify_ssl:
                self.tls_verification_failed = True
                self._insecure_mode = True
                async with httpx.AsyncClient(verify=False, limits=limits, http2=False) as insecure_client:
                    initial_page = await self._fetch_url(insecure_client, initial_url, depth=0)
                    if initial_page:
                        self.pages.append(initial_page)
                        self.initial_status_code = initial_page.status_code
                        if initial_page.status_code == 403:
                            self.waf_or_blocked = True
                        elif initial_page.status_code == 429:
                            self.rate_limited = True
                            self.crawl_error_code = "TARGET_429"
                            self.crawl_error_category = "ASSESSMENT_LIMITATION"
                            self.crawl_error = "Target returned HTTP 429 Too Many Requests (rate limited)."
                        elif initial_page.status_code >= 500:
                            self.server_error = True

                        if not (self.waf_or_blocked or self.rate_limited):
                            if initial_page.status_code == 200:
                                self._enqueue_links(initial_page, self.queue, depth=0)
                        return self.pages

            if not initial_page and self.crawl_error_code in ("TARGET_UNAVAILABLE", "TARGET_TIMEOUT", "TARGET_CONNECTION_REFUSED"):
                await asyncio.sleep(0.5)
                initial_page = await self._fetch_url(client, initial_url, depth=0)

            if not initial_page:
                return self.pages

            self.pages.append(initial_page)
            self.initial_status_code = initial_page.status_code

            if initial_page.status_code == 403:
                self.waf_or_blocked = True
            elif initial_page.status_code == 429:
                self.rate_limited = True
                self.crawl_error_code = "TARGET_429"
                self.crawl_error_category = "ASSESSMENT_LIMITATION"
                self.crawl_error = "Target returned HTTP 429 Too Many Requests (rate limited)."
                self.limitations.append({
                    "stage": "WEB CRAWLING",
                    "status": "LIMITED",
                    "code": "TARGET_429",
                    "category": "ASSESSMENT_LIMITATION",
                    "reason": "Target returned HTTP 429 Too Many Requests. Respecting target-side rate limiting.",
                })
            elif initial_page.status_code >= 500:
                self.server_error = True

            if initial_page.status_code == 200:
                self._enqueue_links(initial_page, self.queue, depth=0)

        return self.pages

    async def crawl_subpages(self) -> List[CrawledPage]:
        """Crawls discovered subpages up to max_pages within bounded crawl duration."""
        if not self.queue or self.waf_or_blocked or self.rate_limited:
            return self.pages

        verify_ssl = False if getattr(self, "_insecure_mode", False) else not self.scope.allow_local
        limits = httpx.Limits(max_connections=MAX_CONCURRENCY, max_keepalive_connections=MAX_CONCURRENCY)

        async with httpx.AsyncClient(verify=verify_ssl, limits=limits, http2=False) as client:
            while self.queue and len(self.pages) < self.max_pages:
                if time.time() - self.start_time > self.max_crawl_duration:
                    self.crawl_budget_exceeded = True
                    self.limitations.append({
                        "stage": "WEB CRAWLING",
                        "status": "LIMITED",
                        "code": "CRAWL_BUDGET_EXCEEDED",
                        "category": "ASSESSMENT_LIMITATION",
                        "reason": f"Web crawling reached its configured assessment budget ({self.max_crawl_duration:.0f}s ceiling).",
                    })
                    break

                current_url, depth = self.queue.pop(0)

                if self._has_binary_extension(current_url):
                    continue

                parsed = urlparse(current_url)
                if not self._is_path_allowed(parsed.path or "/"):
                    continue

                page = await self._fetch_url(client, current_url, depth)
                if page:
                    self.pages.append(page)
                    if page.status_code == 429:
                        self.rate_limited = True
                        self.limitations.append({
                            "stage": "WEB CRAWLING",
                            "status": "LIMITED",
                            "code": "TARGET_429",
                            "category": "ASSESSMENT_LIMITATION",
                            "reason": "Target returned HTTP 429 during subpage crawl. Respecting rate limits.",
                        })
                        break
                    if depth < self.max_depth and page.status_code == 200:
                        self._enqueue_links(page, self.queue, depth)

        if self.slow_pages and not any(l.get("code") == "TARGET_TIMEOUT" for l in self.limitations):
            self.limitations.append({
                "stage": "WEB CRAWLING",
                "status": "LIMITED",
                "code": "TARGET_TIMEOUT",
                "category": "ASSESSMENT_LIMITATION",
                "reason": f"{len(self.slow_pages)} page(s) timed out during crawl.",
            })

        return self.pages

    async def crawl(self, start_url: Optional[str] = None) -> List[CrawledPage]:
        """Crawls starting from target within scope boundaries."""
        if not self.pages:
            await self.fetch_root(start_url)
        return await self.crawl_subpages()

    def _enqueue_links(self, page: CrawledPage, queue: List[tuple[str, int]], depth: int):
        """Extracts same-origin href links from HTML page."""
        content_type = page.headers.get("content-type", "").lower()
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            return

        try:
            soup = page.get_soup()
            for anchor in soup.find_all("a", href=True):
                href = anchor["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                full_url = self.scope.normalize_url(href, base_url=page.url)

                if self._has_binary_extension(full_url):
                    continue

                if self.scope.is_same_origin(full_url) and full_url not in self.visited_urls:
                    self.visited_urls.add(full_url)
                    queue.append((full_url, depth + 1))
                    if len(self.visited_urls) >= self.max_pages * 2:
                        break
        except Exception:
            pass
