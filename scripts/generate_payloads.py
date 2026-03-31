#!/usr/bin/env python3
"""
scripts/generate_payloads.py
Standalone payload generation script.

Generates encoded + mutated attack payload variants and saves them to files.

Usage:
    python scripts/generate_payloads.py --payload "' OR 1=1 --" --count 30
    python scripts/generate_payloads.py --category sqli --count 50 --output payloads.json
    python scripts/generate_payloads.py --all-categories --count 20 --format csv

Output formats: json, csv, txt
"""

import argparse
import csv
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
    p = argparse.ArgumentParser(description="WAF Bypass Lab — Payload Generator")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--payload", help="Custom payload to encode/mutate")
    g.add_argument("--category", choices=ATTACK_CATEGORIES,
                   help="Use a sample payload from this category")
    g.add_argument("--all-categories", action="store_true",
                   help="Generate from all attack categories")

    p.add_argument("--count", type=int, default=20,
                   help="Number of variants per payload (default: 20)")
    p.add_argument("--techniques", nargs="+",
                   help="Specific encoding techniques to use (default: all)")
    p.add_argument("--include-mutations", action="store_true",
                   help="Also generate mutated (not just encoded) variants")
    p.add_argument("--output", help="Output file path (default: stdout)")
    p.add_argument("--format", choices=["json", "csv", "txt"], default="json",
                   help="Output format (default: json)")
    p.add_argument("--verbose", action="store_true", help="Print progress")
    return p.parse_args()


def generate_for_payload(encoder, mutator, payload: str, count: int,
                          techniques=None, include_mutations=False,
                          verbose=False):
    """Generate encoded + optional mutated variants for one payload."""
    results = []

    if verbose:
        print(f"  [*] Generating {count} encoded variants...")

    # Encoded variants
    variants = encoder.generate_variants(payload, count=count, techniques=techniques)
    for v in variants:
        results.append({
            "type": "encoded",
            "original": v.original,
            "result": v.encoded,
            "technique": v.label,
            "encoding_depth": v.encoding_depth,
        })

    if include_mutations:
        if verbose:
            print(f"  [*] Generating mutation variants...")
        mutations = mutator.generate_mutations(payload, count=count // 2)
        for m in mutations:
            results.append({
                "type": "mutation",
                "original": m["original"],
                "result": m["mutated"],
                "technique": m["mutation_type"],
                "encoding_depth": 1,
            })

    return results


def write_json(results: list, output_path=None):
    data = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_variants": len(results),
        "variants": results,
    }
    out = json.dumps(data, indent=2)
    if output_path:
        with open(output_path, "w") as f:
            f.write(out)
    else:
        print(out)


def write_csv(results: list, output_path=None):
    fieldnames = ["type", "technique", "encoding_depth", "original", "result"]
    if output_path:
        with open(output_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(results)
        print(f"[+] Saved {len(results)} variants to {output_path}")
    else:
        import io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(results)
        print(buf.getvalue())


def write_txt(results: list, output_path=None):
    lines = [r["result"] for r in results]
    content = "\n".join(lines)
    if output_path:
        with open(output_path, "w") as f:
            f.write(content + "\n")
        print(f"[+] Saved {len(results)} payloads to {output_path}")
    else:
        print(content)


def main():
    args = parse_args()

    from payload_encoder import PayloadEncoder, PayloadMutator, SAMPLE_PAYLOADS
    encoder = PayloadEncoder()
    mutator = PayloadMutator()

    all_results = []

    if args.payload:
        payloads_to_process = [("custom", args.payload)]
    elif args.category:
        samples = SAMPLE_PAYLOADS.get(args.category, [])
        if not samples:
            print(f"[!] No samples for category: {args.category}")
            sys.exit(1)
        # Take the first sample as representative
        payloads_to_process = [(args.category, samples[0])]
    else:
        # All categories
        payloads_to_process = [
            (cat, SAMPLE_PAYLOADS[cat][0])
            for cat in ATTACK_CATEGORIES
            if cat in SAMPLE_PAYLOADS and SAMPLE_PAYLOADS[cat]
        ]

    print(f"\n[*] WAF Bypass Lab — Payload Generator")
    print(f"[*] Processing {len(payloads_to_process)} payload(s), {args.count} variants each")

    for category, payload in payloads_to_process:
        if args.verbose:
            print(f"\n[*] Category: {category}")
            print(f"[*] Payload:   {payload[:80]}")

        results = generate_for_payload(
            encoder, mutator, payload,
            count=args.count,
            techniques=args.techniques,
            include_mutations=args.include_mutations,
            verbose=args.verbose,
        )

        for r in results:
            r["category"] = category

        all_results.extend(results)

    print(f"[+] Total variants generated: {len(all_results)}")

    # Write output
    writers = {"json": write_json, "csv": write_csv, "txt": write_txt}
    writers[args.format](all_results, args.output)


if __name__ == "__main__":
    main()
