"""
waf_engine.py
author: Prashant Sharma

Standalone WAF simulation engine. Regex-based, not ML-based,
not ModSecurity. That's intentional — we're simulating the kind of
signature WAF you'd see on a shared hosting environment or a basic
cloud WAF, not a full RASP or behavioral analysis system.

If you need to test against ModSecurity CRS rules specifically,
spin up a real ModSec instance and run payloads through it.
This is for fast, local iteration.

Known rough edge: the regex patterns get compiled fresh per inspect()
call. Should cache them. Works fine at our scale but it's wasteful.

NOTE: Persistent storage added (Mar 2026) — custom rules and
toggle states now save to waf_state.json.
"""

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("encoder.waf")


@dataclass
class WAFRule:
    """A single WAF detection rule."""
    rule_id: str
    category: str
    description: str
    patterns: List[str]
    confidence: float
    enabled: bool = True
    hit_count: int = 0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "description": self.description,
            "confidence": self.confidence,
            "enabled": self.enabled,
            "hit_count": self.hit_count,
        }


@dataclass
class WAFResult:
    """Result of inspecting an HTTP request."""
    allowed: bool
    matched_rules: List[dict] = field(default_factory=list)
    highest_confidence: float = 0.0
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "matched_rules": self.matched_rules,
            "highest_confidence": self.highest_confidence,
            "details": self.details,
        }


class WAFEngine:
    """Web Application Firewall engine with configurable rules."""

    _PERSIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_state.json")

    def __init__(self):
        self.rules: List[WAFRule] = self._load_default_rules()
        self._total_inspected = 0
        self._total_blocked = 0
        self._recent_blocks: List[dict] = []
        self._load_persisted_state()

    @staticmethod
    def _load_default_rules() -> List[WAFRule]:
        return [
            WAFRule(
                rule_id="WAF-001",
                category="SQL Injection",
                description="Detects common SQL injection patterns",
                patterns=[
                    r"(?i)(\bunion\b\s+\bselect\b)",
                    r"(?i)(\bor\b\s+1\s*=\s*1)",
                    r"(?i)(\band\b\s+1\s*=\s*1)",
                    r"(?i)(drop\s+table)",
                    r"(?i)(insert\s+into)",
                    r"(?i)(delete\s+from)",
                    r"(?i)(update\s+\w+\s+set)",
                    r"(?i)('\s*;\s*--)",
                    r"(?i)('\s*or\s+')",
                    r"(?i)(;\s*drop\b)",
                    r"(?i)(1'\s*or\s*'1'\s*=\s*'1)",
                    r"(?i)(admin'\s*--)",
                ],
                confidence=0.95,
            ),
            WAFRule(
                rule_id="WAF-002",
                category="Cross-Site Scripting (XSS)",
                description="Detects XSS payload patterns",
                patterns=[
                    r"(?i)(<\s*script[^>]*>)",
                    r"(?i)(javascript\s*:)",
                    r"(?i)(\bon\w+\s*=)",
                    r"(?i)(document\.\s*(cookie|location|write))",
                    r"(?i)(alert\s*\()",
                    r"(?i)(eval\s*\()",
                    r"(?i)(<\s*img[^>]+onerror)",
                    r"(?i)(<\s*svg[^>]+onload)",
                    r"(?i)(<\s*iframe)",
                ],
                confidence=0.90,
            ),
            WAFRule(
                rule_id="WAF-003",
                category="Path Traversal",
                description="Detects directory traversal attempts",
                patterns=[
                    r"(\.\.\\/)",
                    r"(\.\.\\\\)",
                    r"(?i)(%2e%2e[/\\\\%])",
                    r"(?i)(\/etc\/passwd)",
                    r"(?i)(\/etc\/shadow)",
                    r"(?i)(c:\\\\windows)",
                    r"(?i)(boot\.ini)",
                    r"(?i)(\/proc\/self)",
                ],
                confidence=0.90,
            ),
            WAFRule(
                rule_id="WAF-004",
                category="Command Injection",
                description="Detects OS command injection patterns",
                patterns=[
                    r"(;\s*ls\b)",
                    r"(;\s*cat\b)",
                    r"(;\s*rm\b)",
                    r"(;\s*wget\b)",
                    r"(;\s*curl\b)",
                    r"(\|\s*whoami)",
                    r"(\|\s*id\b)",
                    r"(&&\s*cat\b)",
                    r"(`[^`]+`)",
                    r"(\$\([^)]+\))",
                ],
                confidence=0.92,
            ),
            WAFRule(
                rule_id="WAF-005",
                category="Header Injection",
                description="Detects HTTP header injection and CRLF",
                patterns=[
                    r"(%0d%0a)",
                    r"(\r\n)",
                    r"(%0d|%0a)",
                    r"(?i)(set-cookie\s*:)",
                    r"(?i)(x-forwarded-for\s*:\s*127)",
                ],
                confidence=0.85,
            ),
        ]

    def inspect(self, method: str = "GET", url: str = "/",
                headers: Optional[Dict[str, str]] = None,
                query_params: Optional[Dict[str, str]] = None,
                body: str = "") -> WAFResult:
        """Inspect an HTTP request against all enabled rules."""
        self._total_inspected += 1

        parts = [url, body]
        if query_params:
            parts.extend(query_params.values())
        if headers:
            parts.extend(headers.values())

        inspection_text = " ".join(str(p) for p in parts)
        matched: List[dict] = []
        highest_conf = 0.0

        for rule in self.rules:
            if not rule.enabled:
                continue
            for pattern in rule.patterns:
                try:
                    if re.search(pattern, inspection_text):
                        rule.hit_count += 1
                        matched.append({
                            "rule_id": rule.rule_id,
                            "category": rule.category,
                            "confidence": rule.confidence,
                            "pattern_matched": pattern,
                        })
                        highest_conf = max(highest_conf, rule.confidence)
                        break
                except re.error:
                    continue

        if matched:
            self._total_blocked += 1
            categories = ", ".join(set(m["category"] for m in matched))
            result = WAFResult(
                allowed=False,
                matched_rules=matched,
                highest_confidence=highest_conf,
                details=f"Blocked: {categories} detected in {method} {url}",
            )
            block_record = {
                "timestamp": time.time(),
                "method": method,
                "url": url,
                "matched_rules": [m["category"] for m in matched],
                "confidence": highest_conf,
            }
            self._recent_blocks.append(block_record)
            if len(self._recent_blocks) > 100:
                self._recent_blocks = self._recent_blocks[-100:]
            return result

        return WAFResult(allowed=True)

    def enable_rule(self, rule_id: str) -> bool:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                self._save_persisted_state()
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                self._save_persisted_state()
                return True
        return False

    def get_rules(self) -> List[dict]:
        return [r.to_dict() for r in self.rules]

    def get_stats(self) -> dict:
        return {
            "total_inspected": self._total_inspected,
            "total_blocked": self._total_blocked,
            "block_rate": round(self._total_blocked / max(1, self._total_inspected) * 100, 1),
            "rules": self.get_rules(),
            "recent_blocks": self._recent_blocks[-20:],
        }

    def add_rule(self, rule_id: str, category: str, description: str,
                 patterns: list, confidence: float = 0.8) -> bool:
        """Add a custom WAF rule. Returns False if rule_id exists or patterns invalid."""
        if any(r.rule_id == rule_id for r in self.rules):
            return False
        for p in patterns:
            try:
                re.compile(p, re.IGNORECASE)
            except re.error:
                return False
        self.rules.append(WAFRule(
            rule_id=rule_id, category=category, description=description,
            patterns=patterns, confidence=min(1.0, max(0.0, confidence)), enabled=True,
        ))
        self._save_persisted_state()
        return True

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a WAF rule by ID."""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                self.rules.pop(i)
                self._save_persisted_state()
                return True
        return False

    def reset_stats(self):
        """Reset inspection counters and rule hit counts."""
        self._total_inspected = 0
        self._total_blocked = 0
        for rule in self.rules:
            rule.hit_count = 0

    # ── Persistence ───────────────────────────────────────────

    def _save_persisted_state(self) -> None:
        """Save custom rules and toggle states to waf_state.json."""
        try:
            default_ids = {r.rule_id for r in self._load_default_rules()}
            state = {
                "toggles": {
                    r.rule_id: r.enabled
                    for r in self.rules
                },
                "custom_rules": [
                    {
                        "rule_id": r.rule_id,
                        "category": r.category,
                        "description": r.description,
                        "patterns": r.patterns,
                        "confidence": r.confidence,
                        "enabled": r.enabled,
                    }
                    for r in self.rules
                    if r.rule_id not in default_ids
                ],
            }
            with open(self._PERSIST_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception as exc:
            logger.warning("WAF state save failed: %s", exc)

    def _load_persisted_state(self) -> None:
        """Load custom rules and toggle states from waf_state.json."""
        if not os.path.exists(self._PERSIST_FILE):
            return
        try:
            with open(self._PERSIST_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)

            # Restore toggle states for default rules
            for rule in self.rules:
                if rule.rule_id in state.get("toggles", {}):
                    rule.enabled = state["toggles"][rule.rule_id]

            # Re-add persisted custom rules
            existing_ids = {r.rule_id for r in self.rules}
            for cr in state.get("custom_rules", []):
                if cr["rule_id"] not in existing_ids:
                    self.rules.append(WAFRule(
                        rule_id=cr["rule_id"],
                        category=cr.get("category", "Custom"),
                        description=cr.get("description", ""),
                        patterns=cr.get("patterns", []),
                        confidence=cr.get("confidence", 0.8),
                        enabled=cr.get("enabled", True),
                    ))
        except Exception as exc:
            logger.warning("WAF state load failed: %s", exc)
