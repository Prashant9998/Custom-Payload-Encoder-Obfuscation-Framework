"""
Test Script - Payload Encoder & Obfuscation Framework
=======================================================
Verifies all encoding techniques, chaining, variant
generation, and WAF evasion testing.
"""

import sys
import os
import io

# Force UTF-8
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload_encoder import PayloadEncoder, SAMPLE_PAYLOADS
from waf_engine import WAFEngine

passed = 0
failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[92m[PASS]\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[91m[FAIL]\033[0m {name}")


def section(name):
    print(f"\n\033[93m>> {name}\033[0m")


# ═══════════════════════════════════════════
# ENCODING TECHNIQUE TESTS
# ═══════════════════════════════════════════

encoder = PayloadEncoder()
test_payload = "' OR 1=1 --"

section("URL Encoding")
result = encoder.encode(test_payload, "url_encode")
check("URL encoding produces output", len(result.encoded) > 0)
check("URL encoding transforms payload", result.encoded != test_payload)
check("Contains %27 for single quote", "%27" in result.encoded)

section("Double URL Encoding")
result = encoder.encode(test_payload, "double_url_encode")
check("Double URL encoding produces output", len(result.encoded) > 0)
check("Contains %25 (encoded %)", "%25" in result.encoded)

section("Unicode Encoding")
result = encoder.encode(test_payload, "unicode_encode")
check("Unicode encoding produces output", len(result.encoded) > 0)
check("Contains \\u escape", "\\u" in result.encoded)

section("HTML Entity Encoding")
result = encoder.encode(test_payload, "html_entity_encode")
check("HTML entity encoding produces output", len(result.encoded) > 0)
check("Contains &#", "&#" in result.encoded)

section("Base64 Encoding")
result = encoder.encode(test_payload, "base64_encode")
check("Base64 encoding produces output", len(result.encoded) > 0)
check("Base64 does not contain original", test_payload not in result.encoded)
import base64
decoded = base64.b64decode(result.encoded).decode('utf-8')
check("Base64 decodes back to original", decoded == test_payload)

section("Hex Encoding")
result = encoder.encode(test_payload, "hex_encode")
check("Hex encoding produces output", len(result.encoded) > 0)
check("Contains \\x escape", "\\x" in result.encoded)

section("Case Alternation")
result = encoder.encode("SELECT * FROM users", "case_alternate")
check("Case alternation produces output", len(result.encoded) > 0)
check("Case differs from original", result.encoded != "SELECT * FROM users")
check("Lowercase same as original", result.encoded.lower() == "select * from users")

section("SQL Comment Injection")
result = encoder.encode("' UNION SELECT password FROM users", "comment_inject")
check("Comment injection produces output", len(result.encoded) > 0)
check("Contains /**/", "/**/" in result.encoded)

section("Whitespace Obfuscation")
result = encoder.encode("admin OR 1=1", "whitespace_obfuscate")
check("Whitespace obfuscation produces output", len(result.encoded) > 0)
check("Spaces are replaced", " " not in result.encoded or result.encoded != "admin OR 1=1")

section("Concatenation / Splitting")
result = encoder.encode("' UNION SELECT password FROM users", "concat_split")
check("Concatenation produces output", len(result.encoded) > 0)
check("Contains split marker", "'+'" in result.encoded)


# ═══════════════════════════════════════════
# CHAINING TESTS
# ═══════════════════════════════════════════

section("Chain Encoding")
result = encoder.chain_encode(test_payload, ["case_alternate", "url_encode"])
check("Chain encoding produces output", len(result.encoded) > 0)
check("Depth is 2", result.encoding_depth == 2)
check("Both techniques listed", len(result.techniques_applied) == 2)

result = encoder.chain_encode(test_payload, ["url_encode", "base64_encode"])
check("URL + Base64 chain works", len(result.encoded) > 0)
check("Chain label contains arrow", "→" in result.label)


# ═══════════════════════════════════════════
# VARIANT GENERATION TESTS
# ═══════════════════════════════════════════

section("Variant Generation")
variants = encoder.generate_variants(test_payload, count=10)
check("Generated 10 variants", len(variants) >= 5)  # may be fewer if duplicates
check("All variants have encoded content", all(v.encoded for v in variants))
check("Variants are unique", len(set(v.encoded for v in variants)) == len(variants))

variants_limited = encoder.generate_variants(test_payload, count=3, techniques=["url_encode", "hex_encode"])
check("Limited technique variants work", len(variants_limited) >= 2)


# ═══════════════════════════════════════════
# WAF INTEGRATION TESTS
# ═══════════════════════════════════════════

section("WAF Evasion - Raw Payloads Detected")
waf = WAFEngine()

evasion = encoder.test_against_waf("' OR 1=1 --", waf)
check("Raw SQL injection detected", evasion.detected is True)

evasion = encoder.test_against_waf("<script>alert(1)</script>", waf)
check("Raw XSS detected", evasion.detected is True)

evasion = encoder.test_against_waf("../../etc/passwd", waf)
check("Raw path traversal detected", evasion.detected is True)

evasion = encoder.test_against_waf("; cat /etc/passwd", waf)
check("Raw command injection detected", evasion.detected is True)


section("WAF Evasion - Clean Requests Pass Through")
evasion = encoder.test_against_waf("Hello World", waf)
check("Clean text allowed", evasion.detected is False)

evasion = encoder.test_against_waf("SELECT product_name FROM products", waf)
# This may or may not be detected depending on WAF patterns
check("Normal SQL keyword (benign) handled", evasion is not None)


section("WAF Evasion - Batch Test Report")
variants = encoder.generate_variants("' OR 1=1 --", count=8)
report = encoder.batch_test(variants, waf)
check("Batch report has results", report.total_tested > 0)
check("Total = blocked + bypassed", report.total_tested == report.total_blocked + report.total_bypassed)
check("Evasion rate is percentage", 0 <= report.evasion_rate <= 100)
print(f"    └─ Evasion rate: {report.evasion_rate:.1f}% ({report.total_bypassed}/{report.total_tested} bypassed)")


# ═══════════════════════════════════════════
# SAMPLE PAYLOADS TESTS
# ═══════════════════════════════════════════

section("Sample Payloads")
check("SQLi samples exist", len(SAMPLE_PAYLOADS.get("sqli", [])) > 0)
check("XSS samples exist", len(SAMPLE_PAYLOADS.get("xss", [])) > 0)
check("CMDi samples exist", len(SAMPLE_PAYLOADS.get("cmdi", [])) > 0)
check("Path traversal samples exist", len(SAMPLE_PAYLOADS.get("path_traversal", [])) > 0)

samples = encoder.get_sample_payloads("sqli")
check("get_sample_payloads returns correct category", "sqli" in samples)

all_samples = encoder.get_sample_payloads("all")
check("get_sample_payloads('all') returns all categories", len(all_samples) >= 4)


# ═══════════════════════════════════════════
# HISTORY TESTS
# ═══════════════════════════════════════════

section("Encoding History")
history = encoder.get_history()
check("History has entries", len(history) > 0)
check("History entries have required fields", all("original" in h and "encoded" in h for h in history))

encoder.clear_history()
check("History cleared", len(encoder.get_history()) == 0)


# ═══════════════════════════════════════════
# ERROR HANDLING TESTS
# ═══════════════════════════════════════════

section("Error Handling")
try:
    encoder.encode("test", "nonexistent_technique")
    check("Invalid technique raises error", False)
except ValueError:
    check("Invalid technique raises ValueError", True)

try:
    encoder.chain_encode("test", ["url_encode", "nonexistent"])
    check("Invalid chain technique raises error", False)
except ValueError:
    check("Invalid chain technique raises ValueError", True)


# ═══════════════════════════════════════════
# TECHNIQUES REGISTRY TESTS
# ═══════════════════════════════════════════

section("Techniques Registry")
techniques = encoder.get_techniques()
check("11 techniques registered", len(techniques) == 11)
check("Each technique has id", all("id" in t for t in techniques))
check("Each technique has name", all("name" in t for t in techniques))
check("Each technique has description", all("description" in t for t in techniques))

# ═══════════════════════════════════════════
# ROT47 ENCODING TESTS
# ═══════════════════════════════════════════

section("ROT47 Encoding")
rot47_payload = "' OR 1=1 --"
rot47_result = encoder.encode(rot47_payload, "rot47_encode")
check("ROT47 encoding produces output", len(rot47_result.encoded) > 0)
check("ROT47 transforms payload", rot47_result.encoded != rot47_payload)
check("ROT47 is reversible (double-apply)", encoder.encode(rot47_result.encoded, "rot47_encode").encoded == rot47_payload)
check("ROT47 preserves spaces (non-printable)", " " in rot47_result.encoded)  # spaces (ord 32) are left unchanged

section("ROT47 in Variant Generation")
rot47_variants = encoder.generate_variants("SELECT * FROM users", count=5, techniques=["rot47_encode"])
check("ROT47 variants generated", len(rot47_variants) >= 1)
check("ROT47 variant has technique listed", any("rot47_encode" in v.techniques_applied for v in rot47_variants))

# ═══════════════════════════════════════════
# NULL-BYTE INJECTION EDGE CASE TESTS
# ═══════════════════════════════════════════

from payload_encoder import PayloadMutator
section("Null Byte Injection Edge Cases")
mutator = PayloadMutator()

# Normal case
nb_result = mutator.mutate("' OR 1=1 --", "null_byte_inject")
check("Null byte injection mutates payload", nb_result["mutated"] != nb_result["original"])
check("Null bytes inserted before quote", "%00'" in nb_result["mutated"])
check("Null bytes inserted before dash", "%00-" in nb_result["mutated"])

# Edge case: payload with no special characters
nb_plain = mutator.mutate("hello world", "null_byte_inject")
check("Null byte: plain payload unchanged", nb_plain["mutated"] == "hello world")

# Edge case: payload with all target special chars
special = "\"';<>-"
nb_special = mutator.mutate(special, "null_byte_inject")
check("Null bytes injected before all special chars", nb_special["mutated"].count("%00") == len(special))

# Edge case: empty payload
nb_empty = mutator.mutate("", "null_byte_inject")
check("Null byte: empty payload stays empty", nb_empty["mutated"] == "")


# ═══════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════

print("\n" + "=" * 60)
print("\033[96m  Payload Encoder Test Summary\033[0m")
print("=" * 60)
print(f"\n  \033[92m[PASS]\033[0m {passed} tests")
if failed:
    print(f"  \033[91m[FAIL]\033[0m {failed} tests")
    print(f"\n  \033[91mSOME TESTS FAILED\033[0m")
else:
    print(f"\n  \033[92mALL TESTS PASSED\033[0m ✔")
print()
