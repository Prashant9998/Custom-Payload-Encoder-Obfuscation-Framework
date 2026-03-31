"""
modsec_connector.py
ModSecurity WAF connector + OWASP CRS rule simulator.

Two operational modes:
  1. LIVE mode  — sends HTTP requests to a real ModSecurity-protected endpoint
                  and reads the response code (403 = blocked, 200 = bypassed).

  2. SIMULATE mode — applies a faithful subset of OWASP CRS v3.3 rules locally
                     without needing a running ModSecurity instance.
                     Useful for rapid local iteration and CI testing.

─────────────────────────────────────────────────────────────────────────────
INSTALLATION (Linux — Ubuntu/Debian)
─────────────────────────────────────────────────────────────────────────────

1. Install ModSecurity + Nginx connector:
   sudo apt-get update
   sudo apt-get install -y libmodsecurity3 libmodsecurity-dev nginx libnginx-mod-http-modsecurity

2. Clone OWASP Core Rule Set:
   sudo mkdir -p /etc/modsecurity/crs
   git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/crs
   sudo cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

3. Configure Nginx (/etc/nginx/nginx.conf snippet):
   http {
       modsecurity on;
       modsecurity_rules_file /etc/modsecurity/modsec_includes.conf;
       server {
           listen 8080;
           location / {
               proxy_pass http://127.0.0.1:5000;
           }
       }
   }

4. Create /etc/modsecurity/modsec_includes.conf:
   Include /etc/modsecurity/modsecurity.conf
   Include /etc/modsecurity/crs/crs-setup.conf
   Include /etc/modsecurity/crs/rules/*.conf

5. Enable detection mode in /etc/modsecurity/modsecurity.conf:
   SecRuleEngine On
   SecAuditEngine On
   SecAuditLog /var/log/modsecurity/audit.log

6. Restart Nginx:
   sudo systemctl restart nginx

7. Test from CLI:
   curl -H "X-Test: test" "http://localhost:8080/search?q=' OR 1=1 --"
   # Should return 403 Forbidden if rules are active

8. Point this connector at your Nginx endpoint:
   connector = ModSecConnector(base_url="http://localhost:8080", mode="live")
─────────────────────────────────────────────────────────────────────────────
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests as http_requests

logger = logging.getLogger("encoder.modsec")


# ── OWASP CRS v3.3 Rule Simulator ────────────────────────────────────────────
# Selected high-signal rules from the CRS, converted to Python regex.
# Rule IDs match the actual CRS rule IDs where possible.

_CRS_RULES: List[Dict] = [
    # ── SQLi — REQUEST-942 ────────────────────────────────────────────────────
    {
        "id": "942100",
        "name": "SQL Injection Attack Detected via libinjection",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(\bunion\b.{0,20}\bselect\b)",
            r"(?i)(\bselect\b.{0,30}\bfrom\b)",
            r"(?i)(;\s*(drop|delete|truncate|update|insert)\b)",
        ],
        "paranoia": 1,
    },
    {
        "id": "942200",
        "name": "Detects MySQL comment/space obfuscated injections",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(\/\*.*?\*\/.*?(or|and|union|select))",
            r"(?i)(!\s*=\s*0\b)",
            r"(?i)('|\")[\s\S]{0,30}(or|and)[\s\S]{0,30}\1",
        ],
        "paranoia": 1,
    },
    {
        "id": "942270",
        "name": "Looking for basic SQL injection. Common attack string for mysql oracle and others",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)('\s*(or|and)\s+')",
            r"(?i)(or\s+\d+=\d+)",
            r"(?i)(' or '1'='1)",
            r"(?i)(admin'\s*--)",
            r"(?i)(1=1\s*(--|#|;))",
        ],
        "paranoia": 1,
    },
    {
        "id": "942370",
        "name": "Detects classic SQL injection probings 2/2",
        "category": "SQL Injection",
        "severity": "WARNING",
        "patterns": [
            r"(?i)(\bwhere\b.{0,50}\b(like|between|in)\b)",
            r"(?i)(0x[0-9a-f]{4,})",
            r"(?i)(char\s*\(\s*\d+)",
        ],
        "paranoia": 2,
    },
    # ── XSS — REQUEST-941 ─────────────────────────────────────────────────────
    {
        "id": "941100",
        "name": "XSS Attack Detected via libinjection",
        "category": "XSS",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(<\s*script[^>]*>)",
            r"(?i)(javascript\s*:)",
            r"(?i)(<\s*img[^>]+onerror\s*=)",
            r"(?i)(<\s*svg[^>]+onload\s*=)",
        ],
        "paranoia": 1,
    },
    {
        "id": "941150",
        "name": "XSS Filter - Category 2: Event Handler Vector",
        "category": "XSS",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(\bon\w+\s*=\s*['\"]?[^'\">]*['\"]?)",
            r"(?i)(document\.(cookie|location|write))",
            r"(?i)(window\.(location|open|alert))",
        ],
        "paranoia": 1,
    },
    {
        "id": "941180",
        "name": "Node-Validator Blacklist Keywords",
        "category": "XSS",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(eval\s*\()",
            r"(?i)(alert\s*\()",
            r"(?i)(String\.fromCharCode)",
            r"(?i)(atob\s*\()",
        ],
        "paranoia": 1,
    },
    # ── RFI / LFI — REQUEST-930/931 ───────────────────────────────────────────
    {
        "id": "930100",
        "name": "Path Traversal Attack (/../)",
        "category": "Path Traversal",
        "severity": "CRITICAL",
        "patterns": [
            r"(\.\./|\.\.\\)",
            r"(?i)(%2e%2e[/\\%])",
            r"(?i)(\.\.%2f)",
            r"(?i)(%252e%252e)",
            r"(?i)(\/etc\/passwd)",
            r"(?i)(\/etc\/shadow)",
            r"(?i)(\/proc\/self)",
        ],
        "paranoia": 1,
    },
    {
        "id": "930120",
        "name": "OS File Access Attempt",
        "category": "Path Traversal",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(etc/passwd)",
            r"(?i)(etc/shadow)",
            r"(?i)(boot\.ini)",
            r"(?i)(win\.ini)",
            r"(?i)(system32/cmd\.exe)",
        ],
        "paranoia": 1,
    },
    # ── Command Injection — REQUEST-932 ───────────────────────────────────────
    {
        "id": "932100",
        "name": "Remote Command Execution: Unix Command Injection",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(;|\|)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python)\b",
            r"(\`[^`]+\`)",
            r"(\$\([^)]+\))",
        ],
        "paranoia": 1,
    },
    {
        "id": "932150",
        "name": "Remote Command Execution: Direct Unix Command Execution",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(/bin/(bash|sh|zsh|csh)\b)",
            r"(?i)(chmod\s+[0-7]+\s)",
            r"(?i)(/etc/cron)",
            r"(?i)(>>\s*/etc/)",
        ],
        "paranoia": 1,
    },
    # ── CRLF / Header Injection — REQUEST-943 ─────────────────────────────────
    {
        "id": "943100",
        "name": "Possible Session Fixation Attack",
        "category": "Header Injection",
        "severity": "WARNING",
        "patterns": [
            r"(%0d%0a|%0a%0d|\r\n|\n\r)",
            r"(?i)(%0d|%0a)",
            r"(?i)(set-cookie\s*:)",
        ],
        "paranoia": 1,
    },
    # ── SSRF — REQUEST-934 ────────────────────────────────────────────────────
    {
        "id": "934100",
        "name": "Server-Side Request Forgery",
        "category": "SSRF",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(http://169\.254\.169\.254)",
            r"(?i)(file:///)",
            r"(?i)(gopher://)",
            r"(?i)(dict://)",
            r"(?i)(http://(localhost|127\.0\.0\.1|0\.0\.0\.0|0x7f|2130706433))",
        ],
        "paranoia": 1,
    },
    # ── XXE — REQUEST-944 ─────────────────────────────────────────────────────
    {
        "id": "944100",
        "name": "Remote Command Execution: Suspicious XML Entities",
        "category": "XXE",
        "severity": "CRITICAL",
        "patterns": [
            r"(?i)(<!DOCTYPE\b.*\[)",
            r"(?i)(<!ENTITY\b.*SYSTEM\b)",
            r"(?i)(<!ENTITY\b.*PUBLIC\b)",
        ],
        "paranoia": 1,
    },
    # ── Scanner Detection — REQUEST-913 ───────────────────────────────────────
    {
        "id": "913100",
        "name": "Found User-Agent associated with security scanner",
        "category": "Scanner",
        "severity": "WARNING",
        "patterns": [
            r"(?i)(sqlmap|nikto|nessus|openvas|masscan|nmap|dirbuster|gobuster)",
        ],
        "paranoia": 1,
    },
]


# ── Result Dataclasses ────────────────────────────────────────────────────────

@dataclass
class ModSecResult:
    """Result of inspecting a payload through ModSecurity (real or simulated)."""
    payload: str
    blocked: bool
    status_code: int             # 403 if blocked, 200 if bypassed
    matched_rules: List[dict] = field(default_factory=list)
    response_time_ms: float = 0.0
    mode: str = "simulate"       # "live" or "simulate"
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "payload_preview": self.payload[:100] + ("..." if len(self.payload) > 100 else ""),
            "blocked": self.blocked,
            "status": "BLOCKED" if self.blocked else "BYPASSED",
            "status_code": self.status_code,
            "matched_rules": self.matched_rules,
            "response_time_ms": round(self.response_time_ms, 2),
            "mode": self.mode,
            "error": self.error,
        }


@dataclass
class ModSecReport:
    """Summary report of batch ModSecurity testing."""
    total_tested: int
    blocked: int
    bypassed: int
    bypass_rate: float
    mode: str
    results: List[ModSecResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_tested": self.total_tested,
            "blocked": self.blocked,
            "bypassed": self.bypassed,
            "bypass_rate_pct": round(self.bypass_rate, 2),
            "mode": self.mode,
            "results": [r.to_dict() for r in self.results],
        }


# ── ModSecurity Connector ─────────────────────────────────────────────────────

class ModSecConnector:
    """
    Tests payloads against ModSecurity.

    mode="simulate" — Uses OWASP CRS rules implemented in Python.
                      No external server needed. Fast, offline-capable.

    mode="live"     — Sends HTTP GET requests to base_url with the payload
                      injected into a configurable parameter.
                      Requires a real ModSecurity-protected endpoint.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        mode: str = "simulate",
        param_name: str = "q",
        timeout_sec: float = 5.0,
        paranoia_level: int = 1,
    ):
        self.base_url = base_url.rstrip("/")
        self.mode = mode
        self.param_name = param_name
        self.timeout_sec = timeout_sec
        self.paranoia_level = paranoia_level

        # Pre-compile CRS patterns at init time
        self._compiled_rules = self._compile_rules()
        logger.info("ModSecConnector ready (mode=%s paranoia=%d)", mode, paranoia_level)

    def _compile_rules(self) -> List[dict]:
        compiled = []
        for rule in _CRS_RULES:
            if rule.get("paranoia", 1) > self.paranoia_level:
                continue
            patterns = []
            for p in rule["patterns"]:
                try:
                    patterns.append(re.compile(p))
                except re.error as e:
                    logger.warning("Rule %s bad pattern: %s", rule["id"], e)
            if patterns:
                compiled.append({**rule, "compiled": patterns})
        return compiled

    # ── Single-payload inspection ─────────────────────────────────────────────

    def inspect(self, payload: str) -> ModSecResult:
        """Inspect a payload and return a ModSecResult."""
        if self.mode == "live":
            return self._inspect_live(payload)
        return self._inspect_simulate(payload)

    def _inspect_simulate(self, payload: str) -> ModSecResult:
        """Apply compiled OWASP CRS rules in-process (no network)."""
        t0 = time.perf_counter()
        matched_rules = []

        for rule in self._compiled_rules:
            for pattern in rule["compiled"]:
                if pattern.search(payload):
                    matched_rules.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                    })
                    break  # one hit per rule is sufficient

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        blocked = len(matched_rules) > 0

        return ModSecResult(
            payload=payload,
            blocked=blocked,
            status_code=403 if blocked else 200,
            matched_rules=matched_rules,
            response_time_ms=elapsed_ms,
            mode="simulate",
        )

    def _inspect_live(self, payload: str) -> ModSecResult:
        """Send payload to a real ModSecurity endpoint via HTTP GET."""
        url = f"{self.base_url}/?{self.param_name}={payload}"
        t0 = time.perf_counter()
        try:
            resp = http_requests.get(
                url,
                timeout=self.timeout_sec,
                allow_redirects=False,
                headers={"User-Agent": "WAFBypassLab/2.0 Research"},
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            blocked = resp.status_code in (403, 406, 501)
            return ModSecResult(
                payload=payload,
                blocked=blocked,
                status_code=resp.status_code,
                matched_rules=[],        # ModSec doesn't return rule details in HTTP
                response_time_ms=elapsed_ms,
                mode="live",
            )
        except http_requests.exceptions.ConnectionError:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ModSecResult(
                payload=payload,
                blocked=False,
                status_code=0,
                response_time_ms=elapsed_ms,
                mode="live",
                error="Connection refused — is ModSecurity running at " + self.base_url + "?",
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ModSecResult(
                payload=payload,
                blocked=False,
                status_code=0,
                response_time_ms=elapsed_ms,
                mode="live",
                error=str(exc),
            )

    # ── Batch testing ─────────────────────────────────────────────────────────

    def batch_test(self, payloads: List[str],
                   rate_per_second: float = 10.0) -> ModSecReport:
        """
        Test multiple payloads against ModSecurity.

        Args:
            payloads:        List of payload strings to test
            rate_per_second: Max request rate for live mode (ignored in simulate)

        Returns:
            ModSecReport with per-payload results and summary statistics
        """
        results: List[ModSecResult] = []
        delay = 1.0 / rate_per_second if rate_per_second > 0 and self.mode == "live" else 0

        for payload in payloads:
            result = self.inspect(payload)
            results.append(result)
            if delay:
                time.sleep(delay)

        total = len(results)
        blocked_count = sum(1 for r in results if r.blocked)
        bypassed_count = total - blocked_count
        bypass_rate = (bypassed_count / total * 100) if total > 0 else 0.0

        return ModSecReport(
            total_tested=total,
            blocked=blocked_count,
            bypassed=bypassed_count,
            bypass_rate=bypass_rate,
            mode=self.mode,
            results=results,
        )

    # ── Utility ───────────────────────────────────────────────────────────────

    def get_rule_list(self) -> List[dict]:
        """Return the active CRS rules in this connector."""
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "category": r["category"],
                "severity": r["severity"],
                "paranoia_level": r.get("paranoia", 1),
                "pattern_count": len(r.get("patterns", [])),
            }
            for r in _CRS_RULES
            if r.get("paranoia", 1) <= self.paranoia_level
        ]

    def set_mode(self, mode: str, base_url: Optional[str] = None) -> bool:
        """Switch between 'live' and 'simulate' modes."""
        if mode not in ("live", "simulate"):
            return False
        self.mode = mode
        if base_url:
            self.base_url = base_url.rstrip("/")
        logger.info("ModSecConnector mode set to %s", mode)
        return True

    def get_installation_guide(self) -> str:
        """Return the ModSecurity installation guide as a string."""
        return __doc__
