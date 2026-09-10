"""
NayVista Shield - Active Request Safety Controller
Enforces concurrency limits, request budgets, timeouts, 429 backoff,
and per-hop SSRF validation for active security validation modules.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse
import httpx
from scanner.active.scope_policy import ScopePolicy, OutOfScopeError
from scanner.scope import TargetSSRFBlockedError, TargetInvalidSchemeError

class BudgetExceededError(Exception):
    """Raised when an active stage or assessment budget is exhausted."""
    pass

class RequestCancelledError(Exception):
    """Raised when the assessment is cancelled by the user or backend."""
    pass

class ActiveResponse:
    def __init__(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        text: str,
        elapsed_ms: float,
        method: str,
        redirect_history: Optional[List[str]] = None,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.elapsed_ms = elapsed_ms
        self.method = method
        self.redirect_history = redirect_history or []

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

class ActiveRequestController:
    """
    Central safety governor for all outbound active security validation probes.
    """
    ALLOWED_METHODS: Set[str] = {"GET", "HEAD", "OPTIONS"}
    DEFAULT_USER_AGENT = "NayVista-Shield-Security-Auditor/2.0 (+https://nayvista.com/shield; security-assessment)"

    def __init__(
        self,
        scope_policy: ScopePolicy,
        max_concurrency: int = 4,
        max_total_requests: int = 100,
        max_stage_requests: int = 20,
        connect_timeout: float = 4.0,
        read_timeout: float = 6.0,
        max_response_size: int = 2 * 1024 * 1024,
        max_redirects: int = 3,
        cancel_event: Optional[asyncio.Event] = None,
        on_activity: Optional[Any] = None,
    ):
        self.scope_policy = scope_policy
        self.semaphore = asyncio.Semaphore(max(1, min(max_concurrency, 8)))
        self.max_total_requests = max_total_requests
        self.max_stage_requests = max_stage_requests
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_response_size = max_response_size
        self.max_redirects = max_redirects
        self.cancel_event = cancel_event
        self.on_activity = on_activity

        self.total_requests_made: int = 0
        self.stage_requests_made: Dict[str, int] = {}
        self.current_stage: str = "general"
        self.consecutive_429_count: int = 0
        self.limitations: List[Dict[str, Any]] = []
        self._client: Optional[httpx.AsyncClient] = None

    def _log_activity(self, message: str):
        if self.on_activity:
            try:
                self.on_activity(message)
            except Exception:
                pass

    def set_current_stage(self, stage_name: str):
        self.current_stage = stage_name
        if stage_name not in self.stage_requests_made:
            self.stage_requests_made[stage_name] = 0

    async def get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
            timeout = httpx.Timeout(
                connect=self.connect_timeout,
                read=self.read_timeout,
                write=self.read_timeout,
                pool=self.connect_timeout,
            )
            self._client = httpx.AsyncClient(
                verify=False,  # Permit inspecting self-signed or test certificates
                timeout=timeout,
                limits=limits,
                headers={"User-Agent": self.DEFAULT_USER_AGENT},
                follow_redirects=False,  # Manual redirect control for SSRF safety
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_override: Optional[float] = None,
    ) -> Optional[ActiveResponse]:
        """
        Executes a bounded, safe HTTP request subject to concurrency, budgets,
        SSRF checks, redirect boundaries, and 429 rate limit backoff.
        """
        method_upper = method.upper()
        if method_upper not in self.ALLOWED_METHODS:
            raise ValueError(f"Method '{method_upper}' is not permitted. Only {self.ALLOWED_METHODS} are allowed.")

        if self.cancel_event and self.cancel_event.is_set():
            raise RequestCancelledError("Assessment was cancelled.")

        if self.total_requests_made >= self.max_total_requests:
            self._log_activity(f"Total assessment request budget ({self.max_total_requests}) reached.")
            return None

        current_stage_count = self.stage_requests_made.get(self.current_stage, 0)
        if current_stage_count >= self.max_stage_requests:
            self._log_activity(f"Stage '{self.current_stage}' request budget ({self.max_stage_requests}) reached.")
            return None

        if not self.scope_policy.is_in_scope(url):
            raise OutOfScopeError(f"URL '{url}' is outside authorized scope or blocked by SSRF.")

        async with self.semaphore:
            if self.cancel_event and self.cancel_event.is_set():
                raise RequestCancelledError("Assessment was cancelled.")

            return await self._execute_request_flow(method_upper, url, headers, timeout_override)

    async def _execute_request_flow(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout_override: Optional[float] = None,
    ) -> Optional[ActiveResponse]:
        client = await self.get_client()
        current_url = url
        redirect_history: List[str] = []
        req_headers = dict(headers or {})

        for redirect_hop in range(self.max_redirects + 1):
            if self.cancel_event and self.cancel_event.is_set():
                raise RequestCancelledError("Assessment was cancelled.")

            self.total_requests_made += 1
            self.stage_requests_made[self.current_stage] = self.stage_requests_made.get(self.current_stage, 0) + 1

            t_start = time.time()
            try:
                # Custom timeout if overridden
                req_kwargs: Dict[str, Any] = {"headers": req_headers}
                if timeout_override:
                    req_kwargs["timeout"] = httpx.Timeout(timeout_override)

                resp = await client.request(method, current_url, **req_kwargs)
                elapsed_ms = (time.time() - t_start) * 1000.0

                # Handle 429 Too Many Requests
                if resp.status_code == 429:
                    self.consecutive_429_count += 1
                    retry_after = resp.headers.get("retry-after", "2")
                    try:
                        backoff = min(5.0, max(1.0, float(retry_after)))
                    except (ValueError, TypeError):
                        backoff = 2.0

                    self._log_activity(f"Received HTTP 429 from target. Backing off for {backoff:.1f}s.")
                    if self.consecutive_429_count >= 3:
                        if not any(l.get("code") == "TARGET_429" for l in self.limitations):
                            self.limitations.append({
                                "stage": self.current_stage,
                                "status": "LIMITED",
                                "code": "TARGET_429",
                                "category": "ASSESSMENT_LIMITATION",
                                "reason": "Target returned repeated HTTP 429 Too Many Requests. Rate limiting throttled active probes.",
                            })
                    await asyncio.sleep(backoff)
                else:
                    self.consecutive_429_count = 0

                # Check for redirects
                if resp.is_redirect and "location" in resp.headers and redirect_hop < self.max_redirects:
                    redirect_history.append(current_url)
                    raw_loc = resp.headers["location"]
                    try:
                        next_url = self.scope_policy.validate_redirect(current_url, raw_loc)
                        current_url = next_url
                        # Continue redirect hop with GET if 303 or 302
                        if resp.status_code in (302, 303) and method != "HEAD":
                            method = "GET"
                        continue
                    except OutOfScopeError as ose:
                        self._log_activity(f"Redirect blocked (out-of-scope/SSRF): {ose}")
                        # Stop redirect and return response as-is
                        pass

                # Read body bounded to max_response_size
                text_body = ""
                if method != "HEAD":
                    content_bytes = resp.content[:self.max_response_size]
                    try:
                        text_body = content_bytes.decode(resp.encoding or "utf-8", errors="replace")
                    except Exception:
                        text_body = content_bytes.decode("utf-8", errors="replace")

                return ActiveResponse(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=text_body,
                    elapsed_ms=elapsed_ms,
                    method=method,
                    redirect_history=redirect_history,
                )

            except httpx.TimeoutException:
                self._log_activity(f"Request timeout connecting to: {current_url}")
                return None
            except httpx.RequestError as re:
                self._log_activity(f"Request error connecting to {current_url}: {re}")
                return None
            except Exception as e:
                self._log_activity(f"Unexpected request failure: {e}")
                return None

        return None
