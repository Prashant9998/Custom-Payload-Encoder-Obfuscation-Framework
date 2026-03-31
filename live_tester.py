"""
live_tester.py
author: Prashant Sharma

Live HTTP-based WAF testing module.
Sends encoded payload variants to a real web target and analyzes
the HTTP response to determine if the WAF blocked or allowed them.

IMPORTANT — LEGAL DISCLAIMER:
This module is for authorized penetration testing and security research
only. By using the Live Test feature, the user confirms they have written
authorization from the target system owner. Unauthorized use against
any system is illegal under the IT Act 2000 (India), CFAA (USA),
Computer Misuse Act (UK), and equivalent laws worldwide.
The authors accept no responsibility for any misuse.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("encoder.live_tester")

# ── Configuration ────────────────────────────────────────────

DEFAULT_TIMEOUT = 8          # seconds per request
DEFAULT_RATE_LIMIT = 2.0     # requests per second  (configurable in UI)
DEFAULT_USER_AGENT = (
    "PayloadEncoderFramework/2.0 (Security Research; authorized-pentest)"
)

# HTTP status codes that typically indicate WAF blocking
WAF_BLOCK_CODES = {403, 406, 429, 418, 503}

# Text patterns in response body that indicate WAF block pages
WAF_BLOCK_PATTERNS = [
    r"(?i)access\s+denied",
    r"(?i)blocked\s+by",
    r"(?i)cloudflare",
    r"(?i)request\s+forbidden",
    r"(?i)security\s+check",
    r"(?i)firewall\s+blocked",
    r"(?i)mod_security",
    r"(?i)you\s+have\s+been\s+blocked",
    r"(?i)automated\s+attack",
    r"(?i)suspicious\s+activity",
    r"(?i)waf\s+blocked",
    r"(?i)your\s+ip\s+has\s+been",
]


@dataclass
class LiveTestResult:
    """Result for a single payload fired at a live target."""
    payload_original: str
    payload_encoded: str
    technique: str
    url_tested: str
    status_code: int
    response_time_ms: float
    bypassed: bool
    block_reason: Optional[str] = None
    response_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "payload_original": self.payload_original,
            "payload_encoded": self.payload_encoded,
            "technique": self.technique,
            "url_tested": self.url_tested,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time_ms, 1),
            "bypassed": self.bypassed,
            "block_reason": self.block_reason,
            "response_snippet": self.response_snippet[:200],
        }


@dataclass
class LiveTestReport:
    """Summary report of a full live test run."""
    target_url_template: str
    total_fired: int = 0
    bypassed: int = 0
    blocked: int = 0
    errors: int = 0
    results: List[LiveTestResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def evasion_rate(self) -> float:
        if self.total_fired == 0:
            return 0.0
        return round(self.bypassed / self.total_fired * 100, 1)

    def to_dict(self) -> dict:
        return {
            "target_url_template": self.target_url_template,
            "total_fired": self.total_fired,
            "bypassed": self.bypassed,
            "blocked": self.blocked,
            "errors": self.errors,
            "evasion_rate_pct": self.evasion_rate,
            "duration_seconds": round(self.duration_seconds, 2),
            "results": [r.to_dict() for r in self.results],
        }


class LiveTester:
    """
    Fire encoded payload variants at a real HTTP target and
    measure how many bypass the WAF vs get blocked.

    The URL template must contain [PAYLOAD] placeholder:
        http://target.com/search?q=[PAYLOAD]
        http://localhost:5001/api/encode  (POST mode)

    Usage:
        tester = LiveTester()
        report = tester.run(
            url_template="http://localhost:8080/search?q=[PAYLOAD]",
            variants=[{"encoded": "...", "technique": "..."}],
            rate_per_second=2.0,
        )
    """

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def validate_url(self, url_template: str) -> tuple[bool, str]:
        """
        Validate the target URL template.
        Returns (is_valid, error_message).
        """
        if "[PAYLOAD]" not in url_template:
            return False, "URL must contain [PAYLOAD] placeholder"

        try:
            parsed = urlparse(url_template.replace("[PAYLOAD]", "test"))
            if parsed.scheme not in ("http", "https"):
                return False, "Only http:// and https:// URLs are supported"
            if not parsed.netloc:
                return False, "Invalid URL: no hostname found"
        except Exception as e:
            return False, f"URL parse error: {e}"

        return True, ""

    def _fire_single(
        self,
        url_template: str,
        encoded_payload: str,
        original_payload: str,
        technique: str,
        method: str = "GET",
        post_field: str = "payload",
    ) -> LiveTestResult:
        """Fire a single HTTP request and analyze the response."""
        target_url = url_template.replace("[PAYLOAD]", encoded_payload)
        start = time.time()

        try:
            if method.upper() == "POST":
                resp = self._session.post(
                    target_url.split("?")[0],
                    data={post_field: encoded_payload},
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                )
            else:
                resp = self._session.get(
                    target_url,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True,
                )

            elapsed_ms = (time.time() - start) * 1000
            status = resp.status_code
            body = resp.text[:1000]

            # Determine if blocked
            blocked = False
            block_reason = None

            if status in WAF_BLOCK_CODES:
                blocked = True
                block_reason = f"HTTP {status}"
            else:
                for pattern in WAF_BLOCK_PATTERNS:
                    if re.search(pattern, body):
                        blocked = True
                        block_reason = f"Block page detected"
                        break

            return LiveTestResult(
                payload_original=original_payload,
                payload_encoded=encoded_payload,
                technique=technique,
                url_tested=target_url[:120],
                status_code=status,
                response_time_ms=elapsed_ms,
                bypassed=not blocked,
                block_reason=block_reason,
                response_snippet=body[:200],
            )

        except requests.exceptions.Timeout:
            return LiveTestResult(
                payload_original=original_payload,
                payload_encoded=encoded_payload,
                technique=technique,
                url_tested=target_url[:120],
                status_code=0,
                response_time_ms=(time.time() - start) * 1000,
                bypassed=False,
                block_reason="Request timed out",
            )
        except Exception as exc:
            return LiveTestResult(
                payload_original=original_payload,
                payload_encoded=encoded_payload,
                technique=technique,
                url_tested=target_url[:120],
                status_code=0,
                response_time_ms=(time.time() - start) * 1000,
                bypassed=False,
                block_reason=f"Error: {str(exc)[:100]}",
            )

    def run(
        self,
        url_template: str,
        variants: List[dict],
        original_payload: str = "",
        rate_per_second: float = DEFAULT_RATE_LIMIT,
        method: str = "GET",
        post_field: str = "payload",
    ) -> LiveTestReport:
        """
        Run all variants against the target URL and return a full report.

        Args:
            url_template: URL with [PAYLOAD] placeholder
            variants: List of {"encoded": str, "technique": str, "techniques_applied": [...]}
            original_payload: The original pre-encoding payload string
            rate_per_second: Requests per second (default 2.0)
            method: HTTP method GET or POST
            post_field: POST body field name to inject payload into
        """
        is_valid, err = self.validate_url(url_template)
        if not is_valid:
            report = LiveTestReport(target_url_template=url_template)
            logger.error("Invalid URL: %s", err)
            return report

        report = LiveTestReport(target_url_template=url_template)
        start_time = time.time()
        delay = 1.0 / max(0.1, rate_per_second)

        for variant in variants:
            encoded = variant.get("encoded", "")
            technique = (
                " → ".join(variant.get("techniques_applied", []))
                or variant.get("technique", "unknown")
            )

            if not encoded:
                continue

            result = self._fire_single(
                url_template=url_template,
                encoded_payload=encoded,
                original_payload=original_payload,
                technique=technique,
                method=method,
                post_field=post_field,
            )

            report.results.append(result)
            report.total_fired += 1

            if result.status_code == 0:
                report.errors += 1
            elif result.bypassed:
                report.bypassed += 1
            else:
                report.blocked += 1

            time.sleep(delay)

        report.duration_seconds = time.time() - start_time
        return report
