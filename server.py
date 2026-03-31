"""
server.py — Flask web server for WAF Bypass Lab
author: Prashant Sharma

Fairly standard Flask setup. Single-file server, no blueprints,
no ORM, no complexity I don't need right now.

Running in debug mode intentionally — this is a local tool,
not production. Don't expose this to the internet.

Port 5001 because 5000 conflicts with AirPlay on macOS.
"""

import os
import sys
import json
import time
import threading
import uuid
import tempfile
import shutil

from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from payload_encoder import PayloadEncoder, PayloadDecoder, PayloadMutator
from waf_engine import WAFEngine
from ai_waf_engine import AIWAFEngine
from live_tester import LiveTester
from ml_engine import MLEngine
from metrics_engine import MetricsEngine
from modsec_connector import ModSecConnector
from dataset_utils import (
    generate_synthetic, preprocess, class_balance_report,
    check_dataset_file, load_unswnb15, unsw_stream_chunks,
    probe_unswnb15_columns,
)
from cloud_waf_mock import CloudWAFSimulator

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024  # allow 2 GB uploads
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))



# ── Background training job store ─────────────────────────────────────────────
# Maps job_id -> {"status", "progress", "rows_read", "total_rows_est",
#                  "message", "result"}
_train_jobs: dict = {}
_train_jobs_lock = threading.Lock()

# Uploads directory for large dataset files
UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)

# Shared instances
encoder = PayloadEncoder()
decoder = PayloadDecoder()
mutator = PayloadMutator()
waf_engine = WAFEngine()
ai_waf = AIWAFEngine()
live_tester = LiveTester()
ml_engine = MLEngine()         # Multi-model ML engine (RF, XGBoost, LR)
metrics_engine = MetricsEngine()  # Performance metrics tracker
modsec = ModSecConnector(mode="simulate", paranoia_level=1)  # OWASP CRS simulator


# ══════════════════════════════════════════════════════════
# PAGES
# ══════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")




# ══════════════════════════════════════════════════════════
# ENCODER API
# ══════════════════════════════════════════════════════════

@app.route("/api/techniques")
def api_techniques():
    """List all available encoding techniques."""
    return jsonify(encoder.get_techniques())


@app.route("/api/samples")
def api_samples():
    """Get sample payloads by category."""
    category = request.args.get("category", "all")
    return jsonify(encoder.get_sample_payloads(category))


@app.route("/api/encode", methods=["POST"])
def api_encode():
    """Encode a payload with a single technique."""
    data = request.json or {}
    payload = data.get("payload", "")
    technique = data.get("technique", "")

    if not payload or not technique:
        return jsonify({"success": False, "message": "payload and technique required"}), 400

    try:
        result = encoder.encode(payload, technique)
        return jsonify({"success": True, "result": result.to_dict()})
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400


@app.route("/api/chain-encode", methods=["POST"])
def api_chain_encode():
    """Chain-encode a payload with multiple techniques."""
    data = request.json or {}
    payload = data.get("payload", "")
    techniques = data.get("techniques", [])

    if not payload or not techniques:
        return jsonify({"success": False, "message": "payload and techniques required"}), 400

    try:
        result = encoder.chain_encode(payload, techniques)
        return jsonify({"success": True, "result": result.to_dict()})
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400


@app.route("/api/generate", methods=["POST"])
def api_generate():
    """Generate encoded variants of a payload."""
    data = request.json or {}
    payload = data.get("payload", "")
    count = min(data.get("count", 10), 50)  # cap at 50
    techniques = data.get("techniques", None)

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    variants = encoder.generate_variants(payload, count=count, techniques=techniques)
    return jsonify({
        "success": True,
        "count": len(variants),
        "variants": [v.to_dict() for v in variants],
    })


@app.route("/api/test", methods=["POST"])
def api_test():
    """Test a single payload against WAF."""
    data = request.json or {}
    payload = data.get("payload", "")

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    result = encoder.test_against_waf(payload, waf_engine)
    return jsonify({"success": True, "result": result.to_dict()})


@app.route("/api/batch-test", methods=["POST"])
def api_batch_test():
    """Generate variants and test all against WAF."""
    data = request.json or {}
    payload = data.get("payload", "")
    count = min(data.get("count", 10), 50)
    techniques = data.get("techniques", None)

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    # Generate variants
    variants = encoder.generate_variants(payload, count=count, techniques=techniques)

    # Test all against WAF
    report = encoder.batch_test(variants, waf_engine)

    return jsonify({"success": True, "report": report.to_dict()})


@app.route("/api/waf/stats")
def api_waf_stats():
    """Get WAF engine statistics."""
    return jsonify(waf_engine.get_stats())


@app.route("/api/waf/rules")
def api_waf_rules():
    """Get all WAF rules."""
    return jsonify(waf_engine.get_rules())


@app.route("/api/waf/toggle-rule", methods=["POST"])
def api_waf_toggle_rule():
    """Toggle a WAF rule on/off."""
    data = request.json or {}
    rule_id = data.get("rule_id", "")
    enabled = data.get("enabled", True)

    if enabled:
        ok = waf_engine.enable_rule(rule_id)
    else:
        ok = waf_engine.disable_rule(rule_id)

    return jsonify({"success": ok, "rule_id": rule_id, "enabled": enabled})


@app.route("/api/history")
def api_history():
    """Get encoding history."""
    return jsonify(encoder.get_history())


# ══════════════════════════════════════════════════════════
# DECODER API (Feature 1)
# ══════════════════════════════════════════════════════════

@app.route("/api/decode", methods=["POST"])
def api_decode():
    """Decode a payload with auto-detection or specific encoding."""
    data = request.json or {}
    payload = data.get("payload", "")
    encoding_type = data.get("encoding_type", "auto")

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    result = decoder.decode(payload, encoding_type)
    return jsonify({"success": True, "result": result})


@app.route("/api/detect", methods=["POST"])
def api_detect():
    """Detect encoding types in a payload."""
    data = request.json or {}
    payload = data.get("payload", "")

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    detections = decoder.detect_encodings(payload)
    return jsonify({"success": True, "detections": detections})


# ══════════════════════════════════════════════════════════
# EXPORT API (Feature 2)
# ══════════════════════════════════════════════════════════

@app.route("/api/export/json", methods=["POST"])
def api_export_json():
    """Export batch test report as JSON download."""
    data = request.json or {}
    report_data = data.get("report", {})

    if not report_data:
        return jsonify({"success": False, "message": "report data required"}), 400

    export = {
        "framework": "Payload Encoder & Obfuscation Framework",
        "version": "1.0.0",
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "report": report_data,
    }

    json_str = json.dumps(export, indent=2)
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=evasion_report.json"},
    )


@app.route("/api/export/csv", methods=["POST"])
def api_export_csv():
    """Export batch test results as CSV download."""
    data = request.json or {}
    results = data.get("results", [])

    if not results:
        return jsonify({"success": False, "message": "results required"}), 400

    lines = ["#,Status,Technique,Encoded Payload,Confidence,Matched Rules"]
    for i, r in enumerate(results, 1):
        payload_info = r.get("payload", {})
        status = r.get("status", "UNKNOWN")
        technique = payload_info.get("label", "N/A")
        encoded = payload_info.get("encoded", "").replace('"', '""')
        confidence = r.get("confidence", 0)
        rules = "; ".join(m.get("category", "") for m in r.get("matched_rules", []))
        lines.append(f'{i},{status},"{technique}","{encoded}",{confidence},"{rules}"')

    csv_str = "\n".join(lines)
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=evasion_report.csv"},
    )


@app.route("/api/export/html", methods=["POST"])
def api_export_html():
    """Export batch test report as styled HTML download."""
    data = request.json or {}
    report_data = data.get("report", {})
    results = report_data.get("results", [])

    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Evasion Report</title>",
        "<style>",
        "body{font-family:'Segoe UI',sans-serif;background:#0a0e1a;color:#e0e0e0;padding:40px;max-width:1200px;margin:0 auto}",
        "h1{color:#00e5ff;border-bottom:2px solid #1a1f36;padding-bottom:16px}",
        "h2{color:#7c4dff;margin-top:32px}",
        ".summary{display:flex;gap:24px;margin:24px 0}",
        ".stat{background:#12172b;border:1px solid #1e2642;border-radius:12px;padding:20px 32px;text-align:center}",
        ".stat .number{font-size:32px;font-weight:700}",
        ".stat .label{font-size:12px;text-transform:uppercase;color:#8892b0;margin-top:4px}",
        ".blocked .number{color:#ff5252} .bypassed .number{color:#ff9100} .rate .number{color:#00e5ff}",
        "table{width:100%;border-collapse:collapse;margin-top:16px}",
        "th{background:#1a1f36;padding:12px;text-align:left;font-size:13px;text-transform:uppercase;color:#8892b0}",
        "td{padding:10px 12px;border-bottom:1px solid #1e2642;font-size:13px}",
        ".status-blocked{color:#ff5252;font-weight:700} .status-bypassed{color:#69f0ae;font-weight:700}",
        "code{background:#12172b;padding:2px 6px;border-radius:4px;font-size:12px;word-break:break-all}",
        "</style></head><body>",
        "<h1>🔐 Evasion Test Report</h1>",
        f"<p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</p>",
        "<h2>Summary</h2>",
        "<div class='summary'>",
        f"<div class='stat'><div class='number'>{report_data.get('total_tested', 0)}</div><div class='label'>Total Tested</div></div>",
        f"<div class='stat blocked'><div class='number'>{report_data.get('total_blocked', 0)}</div><div class='label'>Blocked</div></div>",
        f"<div class='stat bypassed'><div class='number'>{report_data.get('total_bypassed', 0)}</div><div class='label'>Bypassed</div></div>",
        f"<div class='stat rate'><div class='number'>{report_data.get('evasion_rate', 0):.1f}%</div><div class='label'>Evasion Rate</div></div>",
        "</div>",
        "<h2>Detailed Results</h2>",
        "<table><thead><tr><th>#</th><th>Status</th><th>Technique</th><th>Encoded Payload</th><th>Confidence</th></tr></thead><tbody>",
    ]

    for i, r in enumerate(results, 1):
        payload_info = r.get("payload", {})
        status = r.get("status", "UNKNOWN")
        status_class = "status-blocked" if status == "BLOCKED" else "status-bypassed"
        technique = payload_info.get("label", "N/A")
        encoded = payload_info.get("encoded", "")[:100]
        confidence = r.get("confidence", 0)
        html_parts.append(
            f"<tr><td>{i}</td><td class='{status_class}'>{status}</td>"
            f"<td>{technique}</td><td><code>{encoded}</code></td>"
            f"<td>{confidence:.0%}</td></tr>"
        )

    html_parts.append("</tbody></table></body></html>")

    return Response(
        "".join(html_parts),
        mimetype="text/html",
        headers={"Content-Disposition": "attachment;filename=evasion_report.html"},
    )


# ══════════════════════════════════════════════════════════
# CUSTOM WAF RULES API (Feature 3)
# ══════════════════════════════════════════════════════════

@app.route("/api/waf/add-rule", methods=["POST"])
def api_waf_add_rule():
    """Add a custom WAF rule."""
    data = request.json or {}
    rule_id = data.get("rule_id", "").strip()
    category = data.get("category", "Custom").strip()
    description = data.get("description", "").strip()
    patterns = data.get("patterns", [])
    confidence = float(data.get("confidence", 0.8))

    if not rule_id or not patterns:
        return jsonify({"success": False, "message": "rule_id and patterns required"}), 400

    ok = waf_engine.add_rule(rule_id, category, description, patterns, confidence)
    if ok:
        return jsonify({"success": True, "message": f"Rule {rule_id} added"})
    else:
        return jsonify({"success": False, "message": f"Rule {rule_id} already exists or patterns invalid"}), 400


@app.route("/api/waf/delete-rule", methods=["POST"])
def api_waf_delete_rule():
    """Delete a WAF rule."""
    data = request.json or {}
    rule_id = data.get("rule_id", "")

    ok = waf_engine.delete_rule(rule_id)
    return jsonify({"success": ok, "rule_id": rule_id})


@app.route("/api/waf/reset-stats", methods=["POST"])
def api_waf_reset_stats():
    """Reset WAF statistics."""
    waf_engine.reset_stats()
    return jsonify({"success": True})


# ══════════════════════════════════════════════════════════
# MUTATION API (Feature 4)
# ══════════════════════════════════════════════════════════

@app.route("/api/mutations")
def api_mutations():
    """List available mutation types."""
    return jsonify(mutator.get_mutations())


@app.route("/api/mutate", methods=["POST"])
def api_mutate():
    """Apply a mutation to a payload."""
    data = request.json or {}
    payload = data.get("payload", "")
    mutation_type = data.get("mutation_type", "")

    if not payload or not mutation_type:
        return jsonify({"success": False, "message": "payload and mutation_type required"}), 400

    try:
        result = mutator.mutate(payload, mutation_type)
        return jsonify({"success": True, "result": result})
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400


@app.route("/api/generate-mutations", methods=["POST"])
def api_generate_mutations():
    """Generate multiple diverse mutations of a payload."""
    data = request.json or {}
    payload = data.get("payload", "")
    count = min(data.get("count", 10), 30)

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    results = mutator.generate_mutations(payload, count=count)
    return jsonify({"success": True, "count": len(results), "mutations": results})


# ══════════════════════════════════════════════════════════
# AI WAF ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.route("/api/ai-test", methods=["POST"])
def api_ai_test():
    """Classify a payload (or list of payloads) with the AI WAF."""
    data = request.json or {}
    payloads = data.get("payloads") or [data.get("payload", "")]
    if not any(payloads):
        return jsonify({"success": False, "message": "payload required"}), 400
    results = [ai_waf.classify(p).to_dict() for p in payloads if p]
    return jsonify({"success": True, "results": results})


@app.route("/api/ai-stats", methods=["GET"])
def api_ai_stats():
    """Return AI WAF model training statistics."""
    return jsonify({"success": True, "stats": ai_waf.get_stats()})


# ══════════════════════════════════════════════════════════
# LIVE TARGET TESTING ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.route("/api/live-test", methods=["POST"])
def api_live_test():
    """
    Fire encoded payload variants at a real HTTP target.
    Expects JSON:
    {
        "url_template": "http://target.com/search?q=[PAYLOAD]",
        "payload": "' OR 1=1 --",
        "count": 15,
        "techniques": ["url_encode", "base64_encode"],   (optional)
        "rate_per_second": 2.0,
        "method": "GET",
        "authorized": true    (user must explicitly confirm authorization)
    }
    """
    data = request.json or {}
    url_template = data.get("url_template", "")
    payload = data.get("payload", "")
    count = min(int(data.get("count", 15)), 100)
    techniques = data.get("techniques") or None
    rate = float(data.get("rate_per_second", 2.0))
    method = data.get("method", "GET").upper()
    authorized = data.get("authorized", False)

    if not authorized:
        return jsonify({
            "success": False,
            "message": "You must confirm authorization to test this target."
        }), 403

    if not url_template or not payload:
        return jsonify({"success": False, "message": "url_template and payload required"}), 400

    is_valid, err = live_tester.validate_url(url_template)
    if not is_valid:
        return jsonify({"success": False, "message": err}), 400

    # Generate variants to test
    try:
        variants_obj = encoder.generate_variants(payload, count=count, techniques=techniques)
        variants = [{"encoded": v.encoded, "techniques_applied": v.techniques_applied} for v in variants_obj]
    except Exception as e:
        return jsonify({"success": False, "message": f"Variant generation failed: {e}"}), 500

    rate = max(0.5, min(rate, 20.0))   # cap: 0.5–20 req/sec
    report = live_tester.run(
        url_template=url_template,
        variants=variants,
        original_payload=payload,
        rate_per_second=rate,
        method=method,
    )
    return jsonify({"success": True, "report": report.to_dict()})


@app.route("/api/live-validate-url", methods=["POST"])
def api_live_validate():
    """Validate a URL template before running the full live test."""
    data = request.json or {}
    url = data.get("url_template", "")
    valid, msg = live_tester.validate_url(url)
    return jsonify({"valid": valid, "message": msg})


# ══════════════════════════════════════════════════════════
# ML ENGINE ENDPOINTS (Multi-model: RF, XGBoost, LR)
# ══════════════════════════════════════════════════════════

@app.route("/api/ml/classify", methods=["POST"])
def api_ml_classify():
    """Classify a payload with all three ML models and return ensemble + per-model votes."""
    data = request.json or {}
    payload = data.get("payload", "")
    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    result = ml_engine.classify(payload)
    return jsonify({"success": True, "result": result.to_dict()})


@app.route("/api/ml/batch-classify", methods=["POST"])
def api_ml_batch_classify():
    """Classify a list of payloads with the ML ensemble."""
    data = request.json or {}
    payloads = data.get("payloads", [])
    if not payloads:
        return jsonify({"success": False, "message": "payloads list required"}), 400
    payloads = payloads[:100]  # cap at 100

    results = ml_engine.batch_classify(payloads)
    return jsonify({"success": True, "count": len(results), "results": results})


@app.route("/api/ml/metrics")
def api_ml_metrics():
    """Return per-model training metrics (accuracy, F1, AUC, training time, etc.)."""
    return jsonify({"success": True, "metrics": ml_engine.get_metrics()})


@app.route("/api/ml/comparison")
def api_ml_comparison():
    """Return model comparison table for display in the dashboard."""
    return jsonify({
        "success": True,
        "comparison": ml_engine.get_comparison_table(),
        "best_model": ml_engine.get_best_model(),
        "available_models": ml_engine.get_available_models(),
    })


@app.route("/api/ml/retrain-synthetic", methods=["POST"])
def api_ml_retrain_synthetic():
    """Retrain all ML models on a freshly generated synthetic dataset."""
    data = request.json or {}
    n_attack = min(int(data.get("n_attack", 500)), 2000)
    n_clean = min(int(data.get("n_clean", 500)), 2000)

    texts, labels = generate_synthetic(n_attack=n_attack, n_clean=n_clean)
    texts = preprocess(texts)
    balance = class_balance_report(labels)

    success = ml_engine.retrain(texts, labels)
    if success:
        return jsonify({
            "success": True,
            "message": f"Retrained on {len(texts)} samples",
            "balance": balance,
            "metrics": ml_engine.get_metrics(),
        })
    else:
        return jsonify({"success": False, "message": "Retraining failed"}), 500


@app.route("/api/ml/model-classify", methods=["POST"])
def api_ml_model_classify():
    """Classify a payload using a specific named model."""
    data = request.json or {}
    payload = data.get("payload", "")
    model_name = data.get("model", "")
    if not payload or not model_name:
        return jsonify({"success": False, "message": "payload and model required"}), 400

    result = ml_engine.classify_with_model(payload, model_name)
    return jsonify({"success": True, "result": result})


# ══════════════════════════════════════════════════════════
# METRICS ENGINE ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.route("/api/metrics/summary")
def api_metrics_summary():
    """Return aggregated performance metrics for all recorded requests."""
    return jsonify({"success": True, "summary": metrics_engine.get_summary()})


@app.route("/api/metrics/recent")
def api_metrics_recent():
    """Return the most recent N request metrics."""
    n = min(int(request.args.get("n", 50)), 200)
    return jsonify({"success": True, "records": metrics_engine.get_recent(n)})


@app.route("/api/metrics/technique-ranking")
def api_metrics_technique_ranking():
    """Return techniques ranked by bypass rate."""
    return jsonify({
        "success": True,
        "ranking": metrics_engine.get_technique_ranking(),
    })


@app.route("/api/metrics/clear", methods=["POST"])
def api_metrics_clear():
    """Clear all recorded metrics."""
    metrics_engine.clear()
    return jsonify({"success": True, "message": "Metrics cleared"})


@app.route("/api/metrics/system")
def api_metrics_system():
    """Return system information and psutil availability."""
    return jsonify({"success": True, "system": metrics_engine.is_available()})


@app.route("/api/metrics/batch-record", methods=["POST"])
def api_metrics_batch_record():
    """
    Record metrics for a completed batch test run.
    Accepts the results array from /api/batch-test or /api/modsec/batch-test.
    """
    data = request.json or {}
    results = data.get("results", [])
    recorded = 0
    for r in results[:200]:
        payload_info = r.get("payload", {})
        encoded = payload_info.get("encoded", r.get("payload_preview", ""))
        technique = payload_info.get("label", r.get("technique", "unknown"))
        status = r.get("status", "UNKNOWN")
        rt_ms = r.get("response_time_ms", 0.0)
        metrics_engine.record(payload=encoded, technique=technique,
                              status=status, response_time_ms=rt_ms)
        recorded += 1
    return jsonify({"success": True, "recorded": recorded})


# ══════════════════════════════════════════════════════════
# MODSECURITY / OWASP CRS ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.route("/api/modsec/inspect", methods=["POST"])
def api_modsec_inspect():
    """Inspect a single payload against the OWASP CRS simulator or live ModSec."""
    data = request.json or {}
    payload = data.get("payload", "")
    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    result = modsec.inspect(payload)
    return jsonify({"success": True, "result": result.to_dict()})


@app.route("/api/modsec/batch-test", methods=["POST"])
def api_modsec_batch_test():
    """
    Generate encoded variants of a payload and test all against the OWASP CRS.

    Accepts: { payload, count, techniques, paranoia_level }
    """
    data = request.json or {}
    payload = data.get("payload", "")
    count = min(int(data.get("count", 20)), 100)
    techniques = data.get("techniques") or None
    paranoia = int(data.get("paranoia_level", 1))

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    # Adjust paranoia level if requested
    if paranoia != modsec.paranoia_level:
        modsec.paranoia_level = paranoia
        modsec._compiled_rules = modsec._compile_rules()

    # Generate variants
    variants = encoder.generate_variants(payload, count=count, techniques=techniques)
    payloads_to_test = [v.encoded for v in variants]
    technique_map = {v.encoded: v.label for v in variants}

    # Test against CRS
    report = modsec.batch_test(payloads_to_test)

    # Record metrics
    for r in report.results:
        tech = technique_map.get(r.payload, "unknown")
        metrics_engine.record(
            payload=r.payload,
            technique=tech,
            status="BLOCKED" if r.blocked else "BYPASSED",
            response_time_ms=r.response_time_ms,
        )

    return jsonify({
        "success": True,
        "report": report.to_dict(),
        "technique_map": technique_map,
    })


@app.route("/api/modsec/rules")
def api_modsec_rules():
    """Return the list of active OWASP CRS rules in the current connector."""
    return jsonify({
        "success": True,
        "rules": modsec.get_rule_list(),
        "paranoia_level": modsec.paranoia_level,
        "mode": modsec.mode,
    })


@app.route("/api/modsec/set-mode", methods=["POST"])
def api_modsec_set_mode():
    """Switch the ModSecurity connector between simulate and live mode."""
    data = request.json or {}
    mode = data.get("mode", "simulate")
    base_url = data.get("base_url", None)
    paranoia = data.get("paranoia_level", None)

    ok = modsec.set_mode(mode, base_url)
    if paranoia is not None:
        modsec.paranoia_level = int(paranoia)
        modsec._compiled_rules = modsec._compile_rules()

    return jsonify({
        "success": ok,
        "mode": modsec.mode,
        "paranoia_level": modsec.paranoia_level,
    })


@app.route("/api/modsec/installation-guide")
def api_modsec_installation_guide():
    """Return the ModSecurity installation guide."""
    from modsec_connector import __doc__ as guide
    return jsonify({"success": True, "guide": guide})


# ══════════════════════════════════════════════════════════
# CLOUD WAF SIMULATOR ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.route("/api/cloudwaf/inspect", methods=["POST"])
def api_cloudwaf_inspect():
    """Inspect a payload against a mock Cloud WAF."""
    data = request.json or {}
    payload = data.get("payload", "")
    waf_type = data.get("waf_type", "cloudflare")
    
    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    waf_sim = CloudWAFSimulator(waf_type=waf_type)
    result = waf_sim.inspect(payload)
    return jsonify({"success": True, "result": result.to_dict()})

@app.route("/api/cloudwaf/batch-test", methods=["POST"])
def api_cloudwaf_batch_test():
    """Generate encoded variants of a payload and test all against a Cloud WAF mock."""
    data = request.json or {}
    payload = data.get("payload", "")
    count = min(int(data.get("count", 20)), 100)
    techniques = data.get("techniques") or None
    waf_type = data.get("waf_type", "cloudflare")

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    waf_sim = CloudWAFSimulator(waf_type=waf_type)

    # Generate variants
    variants = encoder.generate_variants(payload, count=count, techniques=techniques)
    payloads_to_test = [v.encoded for v in variants]
    technique_map = {v.encoded: v.label for v in variants}

    # Test against Cloud WAF
    report = waf_sim.batch_test(payloads_to_test)

    # Record metrics
    for r in report.results:
        tech = technique_map.get(r.payload, "unknown")
        metrics_engine.record(
            payload=r.payload,
            technique=tech,
            status="BLOCKED" if r.blocked else "BYPASSED",
            response_time_ms=r.response_time_ms,
        )

    return jsonify({
        "success": True,
        "report": report.to_dict(),
        "technique_map": technique_map,
    })


# ══════════════════════════════════════════════════════════
# DATASET UTILITIES ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.route("/api/dataset/generate-synthetic", methods=["POST"])
def api_dataset_generate_synthetic():
    """Generate a synthetic labelled dataset and return basic stats."""
    data = request.json or {}
    n_attack = min(int(data.get("n_attack", 200)), 1000)
    n_clean = min(int(data.get("n_clean", 200)), 1000)
    seed = int(data.get("seed", 42))

    texts, labels = generate_synthetic(n_attack=n_attack, n_clean=n_clean, seed=seed)
    balance = class_balance_report(labels)

    return jsonify({
        "success": True,
        "balance": balance,
        "sample_attack": texts[:3],
        "sample_clean": texts[n_attack:n_attack + 3],
    })


@app.route("/api/dataset/check-file", methods=["POST"])
def api_dataset_check_file():
    """Check if a dataset file exists and return basic info."""
    data = request.json or {}
    path = data.get("path", "")
    if not path:
        return jsonify({"success": False, "message": "path required"}), 400
    info = check_dataset_file(path)
    return jsonify({"success": True, "info": info})


@app.route("/api/dataset/retrain-csic2010", methods=["POST"])
def api_dataset_retrain_csic2010():
    """Load CSIC 2010 dataset files and retrain ML models."""
    data = request.json or {}
    normal_path = data.get("normal_path", "")
    attack_path = data.get("attack_path", "")

    if not normal_path or not attack_path:
        return jsonify({"success": False,
                        "message": "normal_path and attack_path required"}), 400

    from dataset_utils import load_csic2010
    texts, labels = load_csic2010(normal_path, attack_path)

    if len(texts) < 50:
        return jsonify({
            "success": False,
            "message": f"Too few samples loaded ({len(texts)}). Check file paths.",
        }), 400

    texts = preprocess(texts)
    balance = class_balance_report(labels)
    success = ml_engine.retrain(texts, labels)

    return jsonify({
        "success": success,
        "samples_loaded": len(texts),
        "balance": balance,
        "metrics": ml_engine.get_metrics() if success else {},
    })


# ── UNSW-NB15 Large-file support ─────────────────────────────────────────────

@app.route("/api/dataset/probe-unswnb15", methods=["POST"])
def api_dataset_probe_unswnb15():
    """
    Inspect a UNSW-NB15 CSV without loading it.
    Returns column names, detected label column, size, and a few sample rows.
    Use this first to validate the file before triggering a full retrain.
    """
    data = request.json or {}
    path = data.get("path", "").strip()
    if not path:
        return jsonify({"success": False, "message": "path required"}), 400

    info = probe_unswnb15_columns(path)
    return jsonify({"success": info.get("error") is None, "info": info})


@app.route("/api/dataset/upload-unswnb15", methods=["POST"])
def api_dataset_upload_unswnb15():
    """
    Upload a UNSW-NB15 CSV file to the server.
    Returns the server-side path to use with retrain-unswnb15-start.
    Supports multipart/form-data with a field named "file".
    The file is saved to the uploads/ directory.
    """
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file field in request"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"success": False, "message": "Empty filename"}), 400

    # Only allow CSV
    if not f.filename.lower().endswith(".csv"):
        return jsonify({"success": False, "message": "Only .csv files accepted"}), 400

    safe_name = f"unswnb15_{uuid.uuid4().hex[:8]}.csv"
    dest = os.path.join(UPLOADS_DIR, safe_name)

    try:
        f.save(dest)
        size_mb = round(os.path.getsize(dest) / 1024 / 1024, 1)
        info = probe_unswnb15_columns(dest)
        return jsonify({
            "success": True,
            "path": dest,
            "filename": safe_name,
            "size_mb": size_mb,
            "columns": info.get("columns", []),
            "detected_label_col": info.get("detected_label_col"),
            "row_count_est": info.get("row_count_est"),
        })
    except Exception as exc:
        if os.path.exists(dest):
            os.remove(dest)
        return jsonify({"success": False, "message": str(exc)}), 500


@app.route("/api/dataset/retrain-unswnb15-start", methods=["POST"])
def api_dataset_retrain_unswnb15_start():
    """
    Start a background training job from a UNSW-NB15 CSV file.

    Accepts:
      { path, label_col, max_samples, chunk_size }

    Returns immediately with a job_id. Poll /api/dataset/train-job/<job_id>
    to check progress and get results when done.
    """
    data = request.json or {}
    path = data.get("path", "").strip()
    label_col = data.get("label_col", "label")
    max_samples = int(data.get("max_samples", 200_000))
    chunk_size = min(int(data.get("chunk_size", 50_000)), 100_000)

    if not path:
        return jsonify({"success": False, "message": "path required"}), 400
    if not os.path.exists(path):
        return jsonify({"success": False, "message": f"File not found: {path}"}), 400

    job_id = uuid.uuid4().hex[:12]

    with _train_jobs_lock:
        _train_jobs[job_id] = {
            "status": "queued",
            "progress": 0,
            "rows_read": 0,
            "total_rows_est": 0,
            "message": "Job queued",
            "result": None,
        }

    def _train_worker():
        """Run chunked UNSW-NB15 training in a background thread."""
        def _progress_cb(rows_read: int, total_est: int):
            pct = round(rows_read / max(1, total_est) * 100, 1) if total_est else 0
            with _train_jobs_lock:
                _train_jobs[job_id].update({
                    "status": "loading",
                    "rows_read": rows_read,
                    "total_rows_est": total_est,
                    "progress": min(pct, 90),  # reserve 10% for training
                    "message": f"Reading rows… {rows_read:,} / {total_est:,}",
                })

        all_texts: list = []
        all_labels: list = []

        try:
            with _train_jobs_lock:
                _train_jobs[job_id]["status"] = "loading"
                _train_jobs[job_id]["message"] = "Opening CSV file…"

            for chunk_texts, chunk_labels in unsw_stream_chunks(
                path,
                chunk_size=chunk_size,
                label_col=label_col,
                max_samples=max_samples,
                progress_cb=_progress_cb,
            ):
                all_texts.extend(chunk_texts)
                all_labels.extend(chunk_labels)

            with _train_jobs_lock:
                _train_jobs[job_id].update({
                    "status": "preprocessing",
                    "progress": 90,
                    "rows_read": len(all_texts),
                    "message": f"Preprocessing {len(all_texts):,} samples…",
                })

            all_texts = preprocess(all_texts)
            balance = class_balance_report(all_labels)

            with _train_jobs_lock:
                _train_jobs[job_id].update({
                    "status": "training",
                    "progress": 93,
                    "message": "Training RF + XGBoost + LR models…",
                })

            ok = ml_engine.retrain(all_texts, all_labels)

            with _train_jobs_lock:
                _train_jobs[job_id].update({
                    "status": "done" if ok else "error",
                    "progress": 100,
                    "message": "Training complete!" if ok else "Training failed",
                    "result": {
                        "samples": len(all_texts),
                        "balance": balance,
                        "metrics": ml_engine.get_metrics() if ok else {},
                    },
                })

        except Exception as exc:
            with _train_jobs_lock:
                _train_jobs[job_id].update({
                    "status": "error",
                    "progress": 0,
                    "message": str(exc),
                    "result": None,
                })

    t = threading.Thread(target=_train_worker, daemon=True)
    t.start()

    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/dataset/train-job/<job_id>")
def api_dataset_train_job_status(job_id: str):
    """Poll the status of a background training job."""
    with _train_jobs_lock:
        job = _train_jobs.get(job_id)

    if not job:
        return jsonify({"success": False, "message": "Job not found"}), 404

    return jsonify({"success": True, "job": job})


@app.route("/api/dataset/uploaded-files")
def api_dataset_uploaded_files():
    """List all previously uploaded dataset files in the uploads/ directory."""
    files = []
    try:
        for fname in os.listdir(UPLOADS_DIR):
            fpath = os.path.join(UPLOADS_DIR, fname)
            if os.path.isfile(fpath) and fname.endswith(".csv"):
                files.append({
                    "filename": fname,
                    "path": fpath,
                    "size_mb": round(os.path.getsize(fpath) / 1024 / 1024, 1),
                })
    except Exception:
        pass
    return jsonify({"success": True, "files": files})


@app.route("/api/dataset/delete-file", methods=["POST"])
def api_dataset_delete_file():
    """Delete an uploaded dataset file."""
    data = request.json or {}
    path = data.get("path", "").strip()

    # Safety: only allow deleting from the uploads directory
    if not path or not path.startswith(UPLOADS_DIR):
        return jsonify({"success": False, "message": "Invalid path"}), 400
    if not os.path.exists(path):
        return jsonify({"success": False, "message": "File not found"}), 404

    os.remove(path)
    return jsonify({"success": True, "message": "File deleted"})


# ══════════════════════════════════════════════════════════
# COMBINED / RESEARCH ENDPOINTS
# ══════════════════════════════════════════════════════════

@app.route("/api/research/full-test", methods=["POST"])
def api_research_full_test():
    """
    Run a comprehensive evasion test against all three WAF engines simultaneously.
    Returns results from: Regex WAF + OWASP CRS + ML ensemble — side-by-side.
    """
    data = request.json or {}
    payload = data.get("payload", "")
    count = min(int(data.get("count", 15)), 50)
    techniques = data.get("techniques") or None

    if not payload:
        return jsonify({"success": False, "message": "payload required"}), 400

    # Generate variants once
    variants = encoder.generate_variants(payload, count=count, techniques=techniques)

    # 1. Regex WAF
    regex_report = encoder.batch_test(variants, waf_engine)

    # 2. OWASP CRS simulator
    payloads_list = [v.encoded for v in variants]
    crs_report = modsec.batch_test(payloads_list)

    # 3. ML ensemble
    ml_results = ml_engine.batch_classify(payloads_list)
    ml_blocked = sum(1 for r in ml_results if r.get("label") == "ATTACK")

    # Record metrics
    for i, v in enumerate(variants):
        crs_r = crs_report.results[i] if i < len(crs_report.results) else None
        status = "BYPASSED"
        if regex_report.results[i].detected if i < len(regex_report.results) else False:
            status = "BLOCKED"
        metrics_engine.record(
            payload=v.encoded,
            technique=v.label,
            status=status,
        )

    return jsonify({
        "success": True,
        "payload": payload,
        "variant_count": len(variants),
        "regex_waf": {
            "total": regex_report.total_tested,
            "blocked": regex_report.total_blocked,
            "bypassed": regex_report.total_bypassed,
            "bypass_rate_pct": round(regex_report.evasion_rate, 2),
        },
        "owasp_crs": {
            "total": crs_report.total_tested,
            "blocked": crs_report.blocked,
            "bypassed": crs_report.bypassed,
            "bypass_rate_pct": round(crs_report.bypass_rate, 2),
        },
        "ml_ensemble": {
            "total": len(ml_results),
            "blocked": ml_blocked,
            "bypassed": len(ml_results) - ml_blocked,
            "bypass_rate_pct": round((len(ml_results) - ml_blocked) / max(1, len(ml_results)) * 100, 2),
        },
        "variant_details": [
            {
                "encoded": v.encoded[:120],
                "technique": v.label,
                "regex_status": "BLOCKED" if (i < len(regex_report.results) and regex_report.results[i].detected) else "BYPASSED",
                "crs_status": "BLOCKED" if (i < len(crs_report.results) and crs_report.results[i].blocked) else "BYPASSED",
                "ml_status": ml_results[i].get("label", "?") if i < len(ml_results) else "?",
            }
            for i, v in enumerate(variants)
        ],
    })


# ══════════════════════════════════════════════════════════
# START
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "=" * 60)
    print("  WAF Bypass Lab — Payload Encoder Framework")
    print(f"  Open http://0.0.0.0:{port} in your browser")
    print("=" * 60 + "\n")
    app.run(debug=False, host="0.0.0.0", port=port)
