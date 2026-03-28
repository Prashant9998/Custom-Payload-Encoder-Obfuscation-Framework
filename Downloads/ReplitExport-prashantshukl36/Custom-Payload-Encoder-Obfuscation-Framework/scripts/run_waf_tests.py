#!/usr/bin/env python3
"""
scripts/run_waf_tests.py
Standalone WAF testing script.

Generates payloads, tests them against the WAF engine(s), and outputs a full report.
Supports: built-in regex WAF, OWASP CRS simulator, and real ModSecurity endpoint.

Usage:
    python scripts/run_waf_tests.py --payload "' OR 1=1 --" --waf regex
    python scripts/run_waf_tests.py --category sqli --waf crs --count 30
    python scripts/run_waf_tests.py --category xss --waf live --modsec-url http://localhost:8080
    python scripts/run_waf_tests.py --all-categories --waf both --output report.json
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


ATTACK_CATEGORIES = [
    "sqli", "xss", "cmdi", "path_traversal",
    "header_injection", "ssrf", "xxe", "template_injection",
]


def parse_args():
    p = argparse.ArgumentParser(description="WAF Bypass Lab — WAF Test Runner")

    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--payload", help="Custom payload to test")
    g.add_argument("--category", choices=ATTACK_CATEGORIES,
                   help="Test sample payloads from this attack category")
    g.add_argument("--all-categories", action="store_true",
                   help="Test all attack categories")

    p.add_argument("--count", type=int, default=20,
                   help="Number of encoded variants per payload (default: 20)")
    p.add_argument("--waf", choices=["regex", "crs", "both", "live"], default="both",
                   help="WAF engine to test against (default: both)")
    p.add_argument("--modsec-url", default="http://localhost:8080",
                   help="ModSecurity endpoint URL (for --waf live)")
    p.add_argument("--paranoia", type=int, default=1, choices=[1, 2, 3, 4],
                   help="OWASP CRS paranoia level (default: 1)")
    p.add_argument("--rate", type=float, default=10.0,
                   help="Requests per second for live testing (default: 10)")
    p.add_argument("--output", help="Save report to JSON file")
    p.add_argument("--verbose", action="store_true", help="Show per-payload results")
    return p.parse_args()


def test_against_regex_waf(encoder, waf_engine, variants) -> dict:
    """Test encoded variants against the built-in regex WAF."""
    from payload_encoder import EvasionResult

    report = encoder.batch_test(variants, waf_engine)
    return {
        "waf": "Regex WAF",
        "total": report.total_tested,
        "blocked": report.total_blocked,
        "bypassed": report.total_bypassed,
        "bypass_rate_pct": round(report.evasion_rate, 2),
        "results": [r.to_dict() for r in report.results],
    }


def test_against_crs(modsec_connector, variants) -> dict:
    """Test encoded variants against the OWASP CRS simulator."""
    payloads = [v.encoded for v in variants]
    labels = {v.encoded: v.label for v in variants}

    report = modsec_connector.batch_test(payloads)
    return {
        "waf": "OWASP CRS Simulator",
        "mode": "simulate",
        "total": report.total_tested,
        "blocked": report.blocked,
        "bypassed": report.bypassed,
        "bypass_rate_pct": round(report.bypass_rate, 2),
        "results": [
            {**r.to_dict(), "technique": labels.get(r.payload, "")}
            for r in report.results
        ],
    }


def test_against_live(modsec_connector, variants, rate) -> dict:
    """Test encoded variants against a real ModSecurity endpoint."""
    payloads = [v.encoded for v in variants]
    labels = {v.encoded: v.label for v in variants}

    report = modsec_connector.batch_test(payloads, rate_per_second=rate)
    return {
        "waf": "ModSecurity (Live)",
        "mode": "live",
        "total": report.total_tested,
        "blocked": report.blocked,
        "bypassed": report.bypassed,
        "bypass_rate_pct": round(report.bypass_rate, 2),
        "results": [
            {**r.to_dict(), "technique": labels.get(r.payload, "")}
            for r in report.results
        ],
    }


def print_waf_result(waf_result: dict, verbose: bool = False):
    """Print a formatted WAF test result."""
    print(f"\n  WAF: {waf_result['waf']}")
    print(f"  Total tested:  {waf_result['total']}")
    print(f"  Blocked:       {waf_result['blocked']}  "
          f"({100 - waf_result['bypass_rate_pct']:.1f}% detection rate)")
    print(f"  Bypassed:      {waf_result['bypassed']}  "
          f"({waf_result['bypass_rate_pct']:.1f}% bypass rate)")

    if verbose and waf_result.get("results"):
        print()
        for r in waf_result["results"][:10]:
            status = r.get("status", r.get("blocked", "?"))
            if isinstance(status, bool):
                status = "BLOCKED" if status else "BYPASSED"
            tech = r.get("technique", "")
            preview = r.get("payload_preview", r.get("payload", {}).get("encoded", "?"))[:50]
            print(f"    [{status:8s}] {tech:30s}  {preview}")


def main():
    args = parse_args()

    from payload_encoder import PayloadEncoder, SAMPLE_PAYLOADS
    from waf_engine import WAFEngine
    from modsec_connector import ModSecConnector
    from metrics_engine import MetricsEngine

    encoder = PayloadEncoder()
    waf_engine = WAFEngine()
    metrics = MetricsEngine()

    # Build CRS connector
    crs_mode = "live" if args.waf == "live" else "simulate"
    modsec = ModSecConnector(
        base_url=args.modsec_url,
        mode=crs_mode,
        paranoia_level=args.paranoia,
    )

    print("\n[*] WAF Bypass Lab — Test Runner")
    print(f"[*] WAF target:   {args.waf.upper()}")
    print(f"[*] Variants/payload: {args.count}")

    # Determine payloads to test
    if args.payload:
        test_cases = [("custom", args.payload)]
    elif args.category:
        samples = SAMPLE_PAYLOADS.get(args.category, [])
        test_cases = [(args.category, s) for s in samples[:3]]
    else:
        test_cases = [
            (cat, SAMPLE_PAYLOADS[cat][0])
            for cat in ATTACK_CATEGORIES
            if cat in SAMPLE_PAYLOADS and SAMPLE_PAYLOADS[cat]
        ]

    all_waf_results = []

    for category, payload in test_cases:
        print(f"\n{'='*60}")
        print(f"Category: {category.upper()}")
        print(f"Payload:  {payload[:80]}")
        print(f"{'='*60}")

        # Generate variants
        variants = encoder.generate_variants(payload, count=args.count)
        print(f"[*] Generated {len(variants)} encoded variants")

        payload_report = {
            "category": category,
            "original_payload": payload,
            "variant_count": len(variants),
            "waf_results": [],
        }

        if args.waf in ("regex", "both"):
            t0 = time.time()
            result = test_against_regex_waf(encoder, waf_engine, variants)
            result["test_time_sec"] = round(time.time() - t0, 3)
            print_waf_result(result, verbose=args.verbose)
            payload_report["waf_results"].append(result)

            for r in result["results"]:
                encoded = r.get("payload", {}).get("encoded", "")
                metrics.record(
                    payload=encoded,
                    technique=r.get("payload", {}).get("label", ""),
                    status=r.get("status", "UNKNOWN"),
                )

        if args.waf in ("crs", "both"):
            t0 = time.time()
            result = test_against_crs(modsec, variants)
            result["test_time_sec"] = round(time.time() - t0, 3)
            print_waf_result(result, verbose=args.verbose)
            payload_report["waf_results"].append(result)

        if args.waf == "live":
            print(f"[*] Sending to live ModSecurity at {args.modsec_url}...")
            t0 = time.time()
            result = test_against_live(modsec, variants, rate=args.rate)
            result["test_time_sec"] = round(time.time() - t0, 3)
            print_waf_result(result, verbose=args.verbose)
            payload_report["waf_results"].append(result)

        all_waf_results.append(payload_report)

    # Summary metrics
    print(f"\n{'='*60}")
    print("PERFORMANCE METRICS SUMMARY")
    print(f"{'='*60}")
    summary = metrics.get_summary()
    if summary["total_requests"] > 0:
        print(f"  Total requests:    {summary['total_requests']}")
        print(f"  Bypass rate:       {summary['bypass_rate_pct']:.1f}%")
        print(f"  Detection rate:    {summary['detection_rate_pct']:.1f}%")
        print(f"  Avg payload size:  {summary['avg_payload_size_bytes']:.0f} bytes")
        print()
        print("  Top techniques by bypass rate:")
        for rank in metrics.get_technique_ranking()[:5]:
            print(f"    {rank['technique']:35s} {rank['bypass_rate_pct']:5.1f}%  "
                  f"({rank['bypassed']}/{rank['total']})")

    # Save report
    if args.output:
        report = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "config": {
                "waf": args.waf,
                "count": args.count,
                "paranoia": args.paranoia,
            },
            "metrics_summary": summary,
            "technique_ranking": metrics.get_technique_ranking(),
            "results": all_waf_results,
        }
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to: {args.output}")

    print("\n[+] Testing complete.")


if __name__ == "__main__":
    main()
