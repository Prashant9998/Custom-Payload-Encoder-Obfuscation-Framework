"""
metrics_engine.py
Performance metrics tracker for WAF bypass experiments.

Tracks per-request:
  - Payload size (bytes)
  - Response time (ms)
  - CPU usage estimate (psutil)
  - Memory delta (psutil)

Aggregates across a batch:
  - Bypass rate / Detection rate
  - Technique effectiveness ranking
  - Size vs evasion correlation
"""

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


# ── Per-request record ────────────────────────────────────────────────────────

@dataclass
class RequestMetric:
    """Metrics for a single payload test request."""
    payload: str
    technique: str
    payload_size_bytes: int
    response_time_ms: float
    status: str                   # "BLOCKED" or "BYPASSED"
    cpu_percent: float = 0.0
    memory_delta_kb: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "payload_preview": self.payload[:80] + ("..." if len(self.payload) > 80 else ""),
            "technique": self.technique,
            "payload_size_bytes": self.payload_size_bytes,
            "response_time_ms": round(self.response_time_ms, 2),
            "status": self.status,
            "cpu_percent": round(self.cpu_percent, 1),
            "memory_delta_kb": round(self.memory_delta_kb, 2),
            "timestamp": round(self.timestamp, 3),
        }


# ── Metrics Engine ────────────────────────────────────────────────────────────

class MetricsEngine:
    """
    Collects and aggregates performance metrics for WAF bypass experiments.

    Thread-safe — multiple test threads can log metrics concurrently.
    """

    def __init__(self, window_size: int = 500):
        self._lock = threading.Lock()
        self._records: List[RequestMetric] = []
        self._window_size = window_size   # keep last N records

    # ── Measurement helpers ───────────────────────────────────────────────────

    def _get_cpu(self) -> float:
        if not _PSUTIL_AVAILABLE:
            return 0.0
        return psutil.cpu_percent(interval=None)

    def _get_memory_mb(self) -> float:
        if not _PSUTIL_AVAILABLE:
            return 0.0
        proc = psutil.Process()
        return proc.memory_info().rss / 1024 / 1024

    # ── Logging ───────────────────────────────────────────────────────────────

    def start_request(self) -> dict:
        """
        Call before sending a payload to a WAF.
        Returns a context dict to pass into finish_request().
        """
        ctx = {
            "t_start": time.perf_counter(),
            "cpu_before": self._get_cpu(),
            "mem_before_mb": self._get_memory_mb(),
        }
        return ctx

    def finish_request(self, ctx: dict, payload: str, technique: str,
                       status: str) -> RequestMetric:
        """
        Call after the WAF response is received.
        Records timing, size, and resource usage.
        """
        elapsed_ms = (time.perf_counter() - ctx["t_start"]) * 1000.0
        cpu_now = self._get_cpu()
        mem_now = self._get_memory_mb()

        record = RequestMetric(
            payload=payload,
            technique=technique,
            payload_size_bytes=len(payload.encode("utf-8", errors="replace")),
            response_time_ms=elapsed_ms,
            status=status,
            cpu_percent=(ctx["cpu_before"] + cpu_now) / 2.0,
            memory_delta_kb=(mem_now - ctx["mem_before_mb"]) * 1024.0,
        )

        with self._lock:
            self._records.append(record)
            if len(self._records) > self._window_size:
                self._records = self._records[-self._window_size:]

        return record

    def record(self, payload: str, technique: str, status: str,
               response_time_ms: float = 0.0) -> RequestMetric:
        """
        Convenience method: record a metric without a timing context.
        Useful when response time was measured externally (e.g. live_tester).
        """
        record = RequestMetric(
            payload=payload,
            technique=technique,
            payload_size_bytes=len(payload.encode("utf-8", errors="replace")),
            response_time_ms=response_time_ms,
            status=status,
            cpu_percent=self._get_cpu(),
            memory_delta_kb=0.0,
        )
        with self._lock:
            self._records.append(record)
            if len(self._records) > self._window_size:
                self._records = self._records[-self._window_size:]
        return record

    # ── Aggregation ───────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        """Aggregate metrics across all records in the current window."""
        with self._lock:
            records = list(self._records)

        if not records:
            return {
                "total_requests": 0,
                "bypassed": 0,
                "blocked": 0,
                "bypass_rate_pct": 0.0,
                "detection_rate_pct": 0.0,
                "avg_response_time_ms": 0.0,
                "p50_response_time_ms": 0.0,
                "p95_response_time_ms": 0.0,
                "avg_payload_size_bytes": 0.0,
                "max_payload_size_bytes": 0,
                "avg_cpu_percent": 0.0,
                "technique_stats": {},
                "size_buckets": {},
            }

        bypassed = [r for r in records if r.status == "BYPASSED"]
        blocked = [r for r in records if r.status == "BLOCKED"]
        total = len(records)

        times = sorted(r.response_time_ms for r in records)
        sizes = [r.payload_size_bytes for r in records]

        # Technique effectiveness
        technique_stats: Dict[str, dict] = defaultdict(lambda: {"total": 0, "bypassed": 0})
        for r in records:
            technique_stats[r.technique]["total"] += 1
            if r.status == "BYPASSED":
                technique_stats[r.technique]["bypassed"] += 1

        for tech, stats in technique_stats.items():
            t = stats["total"]
            b = stats["bypassed"]
            stats["bypass_rate_pct"] = round(b / t * 100, 1) if t else 0.0

        # Payload size buckets
        buckets = {"0-50B": 0, "51-200B": 0, "201-500B": 0, "500+B": 0}
        for s in sizes:
            if s <= 50:
                buckets["0-50B"] += 1
            elif s <= 200:
                buckets["51-200B"] += 1
            elif s <= 500:
                buckets["201-500B"] += 1
            else:
                buckets["500+B"] += 1

        def _percentile(lst, pct):
            if not lst:
                return 0.0
            idx = int(len(lst) * pct / 100)
            return lst[min(idx, len(lst) - 1)]

        return {
            "total_requests": total,
            "bypassed": len(bypassed),
            "blocked": len(blocked),
            "bypass_rate_pct": round(len(bypassed) / total * 100, 2),
            "detection_rate_pct": round(len(blocked) / total * 100, 2),
            "avg_response_time_ms": round(sum(times) / len(times), 2),
            "p50_response_time_ms": round(_percentile(times, 50), 2),
            "p95_response_time_ms": round(_percentile(times, 95), 2),
            "avg_payload_size_bytes": round(sum(sizes) / len(sizes), 1),
            "max_payload_size_bytes": max(sizes),
            "avg_cpu_percent": round(
                sum(r.cpu_percent for r in records) / total, 1
            ),
            "technique_stats": dict(technique_stats),
            "size_buckets": buckets,
        }

    def get_recent(self, n: int = 50) -> List[dict]:
        """Return the most recent N request metrics."""
        with self._lock:
            records = list(self._records[-n:])
        return [r.to_dict() for r in reversed(records)]

    def get_technique_ranking(self) -> List[dict]:
        """Return techniques ranked by bypass rate (highest first)."""
        summary = self.get_summary()
        tech_stats = summary.get("technique_stats", {})
        ranked = sorted(
            [{"technique": k, **v} for k, v in tech_stats.items()],
            key=lambda x: x.get("bypass_rate_pct", 0),
            reverse=True,
        )
        return ranked

    def clear(self) -> None:
        """Clear all recorded metrics."""
        with self._lock:
            self._records.clear()

    def is_available(self) -> dict:
        """Return system info and psutil availability."""
        info = {
            "psutil_available": _PSUTIL_AVAILABLE,
            "records_in_window": len(self._records),
        }
        if _PSUTIL_AVAILABLE:
            info["cpu_count"] = psutil.cpu_count()
            info["total_memory_gb"] = round(
                psutil.virtual_memory().total / 1024 ** 3, 2
            )
        return info
