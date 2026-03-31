"""
cloud_waf_mock.py
Mock simulators for common proprietary Cloud WAFs (Cloudflare, AWS WAF).
"""

import re
import time
from dataclasses import dataclass, field
from typing import List

@dataclass
class CloudWAFResult:
    payload: str
    blocked: bool
    waf_name: str
    status_code: int
    matched_rules: List[dict] = field(default_factory=list)
    response_time_ms: float = 0.0

    def to_dict(self):
        return {
            "payload_preview": self.payload[:100] + ("..." if len(self.payload) > 100 else ""),
            "blocked": self.blocked,
            "status": "BLOCKED" if self.blocked else "BYPASSED",
            "waf_name": self.waf_name,
            "status_code": self.status_code,
            "matched_rules": self.matched_rules,
            "response_time_ms": round(self.response_time_ms, 2)
        }

@dataclass
class CloudWAFReport:
    total_tested: int
    blocked: int
    bypassed: int
    bypass_rate: float
    waf_name: str
    results: List[CloudWAFResult] = field(default_factory=list)

    def to_dict(self):
        return {
            "total_tested": self.total_tested,
            "blocked": self.blocked,
            "bypassed": self.bypassed,
            "bypass_rate_pct": round(self.bypass_rate, 2),
            "waf_name": self.waf_name,
            "results": [r.to_dict() for r in self.results],
        }

CLOUDFLARE_RULES = [
    {"id": "CF-SQLi", "name": "Cloudflare SQLi Core Rule", "patterns": [r"(?i)(\bunion\b.{0,10}\bselect\b)", r"(?i)(\/\*!)", r"(?i)sleep\(\d+\)"]},
    {"id": "CF-XSS", "name": "Cloudflare XSS Browser Integrity", "patterns": [r"(?i)<script>", r"(?i)javascript:", r"(?i)on\w+\s*="]},
    {"id": "CF-LFI", "name": "Cloudflare Path Traversal", "patterns": [r"\.\.\/\.\.\/", r"(?i)\/etc\/passwd"]},
]

AWS_WAF_RULES = [
    {"id": "AWS-Core-SQLi", "name": "AWS Managed Rules - SQLi", "patterns": [r"(?i)\bselect\b.*\bfrom\b", r"(?i)or\s+1=1", r"(?i)WAITFOR\s+DELAY"]},
    {"id": "AWS-Core-XSS", "name": "AWS Managed Rules - XSS", "patterns": [r"(?i)<\s*svg.*onload", r"(?i)alert\("]},
    {"id": "AWS-Bot", "name": "AWS Bot Control", "patterns": [r"(?i)(curl|python-requests|sqlmap)"]},
]

class CloudWAFSimulator:
    def __init__(self, waf_type="cloudflare"):
        self.waf_type = waf_type
        self.waf_name = "Cloudflare" if waf_type == "cloudflare" else "AWS WAF"
        self.rules = self._compile_rules(CLOUDFLARE_RULES if waf_type == "cloudflare" else AWS_WAF_RULES)
        self.block_code = 1020 if waf_type == "cloudflare" else 403

    def _compile_rules(self, ruleset):
        compiled = []
        for r in ruleset:
            compiled_patterns = [re.compile(p) for p in r["patterns"]]
            compiled.append({**r, "compiled": compiled_patterns})
        return compiled

    def inspect(self, payload: str) -> CloudWAFResult:
        t0 = time.perf_counter()
        matched_rules = []

        for rule in self.rules:
            for pattern in rule["compiled"]:
                if pattern.search(payload):
                    matched_rules.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                    })
                    break

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        blocked = len(matched_rules) > 0

        return CloudWAFResult(
            payload=payload,
            blocked=blocked,
            waf_name=self.waf_name,
            status_code=self.block_code if blocked else 200,
            matched_rules=matched_rules,
            response_time_ms=elapsed_ms,
        )

    def batch_test(self, payloads: List[str]) -> CloudWAFReport:
        results = []
        for p in payloads:
            results.append(self.inspect(p))
            
        total = len(results)
        blocked = sum(1 for r in results if r.blocked)
        bypassed = total - blocked
        rate = (bypassed / total * 100) if total > 0 else 0.0

        return CloudWAFReport(
            total_tested=total,
            blocked=blocked,
            bypassed=bypassed,
            bypass_rate=rate,
            waf_name=self.waf_name,
            results=results
        )
