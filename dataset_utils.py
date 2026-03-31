"""
dataset_utils.py
Dataset loading and preprocessing utilities.

Supports:
  - CSIC 2010 HTTP Dataset (web attack traffic)
  - UNSW-NB15 Network Intrusion Dataset (streamed in chunks for large files)
  - Synthetic dataset generation (CSIC 2010 style)

CSIC 2010 Dataset download:
  http://www.isi.csic.es/dataset/
  Files: normalTrafficTraining.txt, anomalousTrafficTest.txt

UNSW-NB15 Dataset download:
  https://research.unsw.edu.au/projects/unsw-nb15-dataset
  Files: UNSW-NB15_1.csv through UNSW-NB15_4.csv
  Label column: "label"  (0 = normal, 1 = attack)

Usage:
  from dataset_utils import load_csic2010, load_unswnb15, generate_synthetic
  texts, labels = load_csic2010("normalTraffic.txt", "anomalousTraffic.txt")
  from ml_engine import MLEngine
  engine = MLEngine()
  engine.retrain(texts, labels)
"""

import csv
import gc
import logging
import os
import re
import urllib.parse
from typing import Callable, Generator, Iterator, List, Optional, Tuple

logger = logging.getLogger("encoder.dataset_utils")


# ── CSIC 2010 HTTP Dataset Loader ────────────────────────────────────────────

def load_csic2010(
    normal_path: str,
    anomalous_path: str,
    max_normal: int = 5000,
    max_anomalous: int = 5000,
) -> Tuple[List[str], List[int]]:
    """
    Load and preprocess the CSIC 2010 HTTP Dataset.

    The dataset contains raw HTTP requests stored in plain text.
    Normal requests are label 0, anomalous (attack) are label 1.

    Args:
        normal_path:    Path to normalTrafficTraining.txt or normalTrafficTest.txt
        anomalous_path: Path to anomalousTrafficTest.txt
        max_normal:     Max normal samples to load (prevents class imbalance)
        max_anomalous:  Max attack samples to load

    Returns:
        Tuple of (texts, labels) ready for MLEngine.retrain()
    """
    def _parse_http_file(filepath: str, label: int, max_samples: int) -> Tuple[List[str], List[int]]:
        texts, labels = [], []
        try:
            with open(filepath, "r", encoding="latin-1", errors="replace") as f:
                current_request = []
                for line in f:
                    line = line.rstrip("\n")
                    if line.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
                        if current_request and len(texts) < max_samples:
                            payload = _extract_payload_from_request(current_request)
                            if payload:
                                texts.append(payload)
                                labels.append(label)
                        current_request = [line]
                    else:
                        current_request.append(line)

                # last request
                if current_request and len(texts) < max_samples:
                    payload = _extract_payload_from_request(current_request)
                    if payload:
                        texts.append(payload)
                        labels.append(label)

        except FileNotFoundError:
            logger.error("CSIC 2010 file not found: %s", filepath)
        except Exception as exc:
            logger.error("CSIC 2010 parse error: %s", exc)

        return texts, labels

    def _extract_payload_from_request(lines: List[str]) -> Optional[str]:
        """Extract query string + body from an HTTP request block."""
        parts = []

        # First line: "GET /path?query HTTP/1.1"
        first = lines[0] if lines else ""
        if "?" in first:
            qs = first.split("?", 1)[1].split(" ")[0]
            parts.append(urllib.parse.unquote(qs))

        # Body: lines after the blank line
        body_start = False
        for line in lines[1:]:
            if line == "" and not body_start:
                body_start = True
                continue
            if body_start and line:
                parts.append(urllib.parse.unquote(line))
                break  # only take first body line

        combined = " ".join(parts).strip()
        return combined if len(combined) > 3 else None

    normal_texts, normal_labels = _parse_http_file(normal_path, 0, max_normal)
    attack_texts, attack_labels = _parse_http_file(anomalous_path, 1, max_anomalous)

    texts = normal_texts + attack_texts
    labels = normal_labels + attack_labels

    logger.info(
        "CSIC 2010 loaded: %d normal, %d attack, total=%d",
        len(normal_texts), len(attack_texts), len(texts),
    )
    return texts, labels


# ── UNSW-NB15 Loader ─────────────────────────────────────────────────────────

# Default textual/categorical columns found in UNSW-NB15 CSV files.
# Numeric columns are intentionally excluded — the ML pipeline uses TF-IDF
# which needs string tokens, not raw numbers.
_UNSW_FEATURE_COLS = [
    "proto", "service", "state", "attack_cat",
    "ct_srv_src", "ct_state_ttl",
]


def _row_to_text(row: dict, feature_cols: List[str], label_col: str) -> Tuple[str, int]:
    """Convert a single CSV row into a (text, label) pair."""
    parts = []
    for col in feature_cols:
        val = row.get(col, "").strip()
        if val and val not in ("-", "0", "", "None", "nan"):
            parts.append(f"{col}={val}")

    # Also include srcip/dstip protocol context if present
    if row.get("proto", ""):
        pass  # already captured above
    if row.get("attack_cat", "").strip() not in ("", "Normal", "-", "None"):
        parts.append(f"attack={row['attack_cat'].strip()}")

    text = " ".join(parts).strip()

    try:
        label = 1 if int(float(row.get(label_col, "0"))) != 0 else 0
    except (ValueError, TypeError):
        label = 0

    return text, label


def unsw_stream_chunks(
    csv_path: str,
    chunk_size: int = 50_000,
    label_col: str = "label",
    feature_cols: Optional[List[str]] = None,
    max_samples: Optional[int] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> Generator[Tuple[List[str], List[int]], None, None]:
    """
    Generator: stream UNSW-NB15 CSV in chunks of `chunk_size` rows.

    Designed for large files (1-2 GB) — reads one chunk at a time and
    yields (texts, labels) without ever holding the full file in RAM.

    Args:
        csv_path:    Path to UNSW-NB15_*.csv
        chunk_size:  Rows per yielded chunk (default 50 000, ~10-15 MB RAM)
        label_col:   Column containing the binary label (default "label")
        feature_cols: Columns to convert to text tokens (None = auto)
        max_samples: Hard cap on total rows read (None = no limit)
        progress_cb: Optional callback(rows_read, total_rows_est) for UI updates

    Yields:
        (texts, labels) tuple for each chunk
    """
    if feature_cols is None:
        feature_cols = _UNSW_FEATURE_COLS

    # Estimate total rows for progress reporting (fast line count)
    total_rows_est = 0
    if progress_cb:
        try:
            with open(csv_path, "rb") as f:
                total_rows_est = sum(1 for _ in f)
        except Exception:
            total_rows_est = 0

    rows_read = 0
    chunk_texts: List[str] = []
    chunk_labels: List[int] = []

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)

            # Handle files that might have no header (rare, but defensive)
            if reader.fieldnames is None:
                logger.error("UNSW-NB15: CSV has no header row — %s", csv_path)
                return

            for row in reader:
                if max_samples and rows_read >= max_samples:
                    break

                text, label = _row_to_text(row, feature_cols, label_col)
                if text:
                    chunk_texts.append(text)
                    chunk_labels.append(label)

                rows_read += 1
                if progress_cb and rows_read % 10_000 == 0:
                    progress_cb(rows_read, total_rows_est)

                if len(chunk_texts) >= chunk_size:
                    yield chunk_texts, chunk_labels
                    chunk_texts = []
                    chunk_labels = []
                    gc.collect()

        # Yield remaining rows in the last partial chunk
        if chunk_texts:
            yield chunk_texts, chunk_labels

    except FileNotFoundError:
        logger.error("UNSW-NB15 file not found: %s", csv_path)
    except Exception as exc:
        logger.error("UNSW-NB15 stream error: %s", exc)


def load_unswnb15(
    csv_path: str,
    label_col: str = "label",
    feature_cols: Optional[List[str]] = None,
    max_samples: int = 100_000,
) -> Tuple[List[str], List[int]]:
    """
    Load up to `max_samples` rows from an UNSW-NB15 CSV.

    For very large files (>500k rows) use unsw_stream_chunks() instead
    so the data is processed incrementally without loading everything into RAM.

    Args:
        csv_path:    Path to UNSW-NB15_*.csv
        label_col:   Binary label column (0=normal, 1=attack)
        feature_cols: Columns to encode as text tokens (None = auto-select)
        max_samples: Maximum rows to load

    Returns:
        Tuple of (texts, labels) ready for MLEngine.retrain()
    """
    all_texts: List[str] = []
    all_labels: List[int] = []

    for texts, labels in unsw_stream_chunks(
        csv_path,
        chunk_size=min(max_samples, 50_000),
        label_col=label_col,
        feature_cols=feature_cols,
        max_samples=max_samples,
    ):
        all_texts.extend(texts)
        all_labels.extend(labels)
        if len(all_texts) >= max_samples:
            break

    attack_count = sum(all_labels)
    logger.info(
        "UNSW-NB15 loaded: %d normal, %d attack, total=%d",
        len(all_labels) - attack_count, attack_count, len(all_texts),
    )
    return all_texts, all_labels


def probe_unswnb15_columns(csv_path: str, sample_rows: int = 5) -> dict:
    """
    Read just the header + a few rows of a UNSW-NB15 CSV.
    Returns column names, detected label column, and sample data.
    Useful for validating a file before kicking off a full retrain.
    """
    result = {
        "columns": [],
        "sample_rows": [],
        "detected_label_col": None,
        "row_count_est": None,
        "size_mb": None,
        "error": None,
    }

    try:
        stat = os.stat(csv_path)
        result["size_mb"] = round(stat.st_size / 1024 / 1024, 1)
    except Exception:
        pass

    # Estimate row count from file size
    try:
        with open(csv_path, "rb") as f:
            raw_lines = sum(1 for _ in f)
        result["row_count_est"] = max(0, raw_lines - 1)  # subtract header
    except Exception:
        pass

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            result["columns"] = list(reader.fieldnames or [])

            # Detect label column: common names in UNSW-NB15
            for candidate in ("label", "Label", "class", "Class", "attack"):
                if candidate in result["columns"]:
                    result["detected_label_col"] = candidate
                    break

            for i, row in enumerate(reader):
                if i >= sample_rows:
                    break
                result["sample_rows"].append(dict(row))

    except FileNotFoundError:
        result["error"] = f"File not found: {csv_path}"
    except Exception as exc:
        result["error"] = str(exc)

    return result


# ── Synthetic Dataset Generator ───────────────────────────────────────────────

def generate_synthetic(
    n_attack: int = 500,
    n_clean: int = 500,
    seed: int = 42,
) -> Tuple[List[str], List[int]]:
    """
    Generate a synthetic labelled dataset modelled on CSIC 2010 patterns.

    Useful for quick experiments without the full dataset download.
    The generated samples are variations on known attack patterns and
    realistic benign web request values.

    Args:
        n_attack: Number of attack samples to generate
        n_clean:  Number of clean samples to generate
        seed:     Random seed for reproducibility

    Returns:
        Tuple of (texts, labels)
    """
    import random
    random.seed(seed)

    # Attack templates with slots filled randomly
    attack_templates = [
        # SQLi
        "' OR {n}={n} --",
        "UNION SELECT {col},NULL,NULL FROM {table}--",
        "'; DROP TABLE {table}--",
        "' AND SLEEP({n})--",
        "' OR '{word}'='{word}",
        "1' WAITFOR DELAY '0:0:{n}'--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,{func}()))--",
        "admin'/*",
        "' HAVING 1=1--",
        "1; EXEC sp_makewebtask 'cmd.asp','SELECT 1'--",
        # XSS
        "<script>{func}(1)</script>",
        "<img src=x onerror={func}({n})>",
        "<svg onload={func}(document.cookie)>",
        "'><script>{func}(1)</script>",
        "<{tag} on{event}={func}({n})>",
        "javascript:{func}(document.cookie)",
        "\"><img src='x' onerror='{func}({n})'>",
        # Command injection
        "; {cmd} /etc/passwd",
        "| {cmd}",
        "`{cmd}`",
        "$({cmd})",
        "; {cmd} -c 1 evil.com",
        "&& cat /etc/{file}",
        # Path traversal
        "../../{n}/etc/{file}",
        "%2e%2e%2f%2e%2e%2fetc%2f{file}",
        "....//....//etc/{file}",
        "..%252f..%252fetc%252f{file}",
        # CRLF
        "value%0d%0aSet-Cookie: {word}=true",
        "%0a{word}:{n}",
    ]

    clean_templates = [
        "search for {word} products",
        "user email {word}@example.com",
        "product id {n} in category {word}",
        "sort by {word} {word2}",
        "page {n} of {n2}",
        "name={word}&age={n}&city={word2}",
        "q={word}+{word2}&lang=en&limit={n}",
        "GET /api/v1/{word}/{n} HTTP/1.1",
        "order_id=ORD-{n}-{n2}&status={word}",
        "filter[{word}]={word2}&filter[price]={n}",
        "date_from=2024-01-0{n}&date_to=2024-12-0{n2}",
        "{word}@{word2}.com",
        "price_min={n}&price_max={n2}&in_stock=true",
        "comment: great {word} service",
        "transaction id TXN-{word}-{n}",
        "ZIP code {n}{n2} country US",
        "username {word}_{n} is available",
        "please {word} my subscription to {word2} tier",
        "I have {n} items in my cart",
        "the product weighs {n}.{n2} kg",
    ]

    words = ["shoes", "laptop", "book", "user", "admin", "product",
             "premium", "active", "asc", "desc", "true", "blue",
             "gold", "silver", "standard", "basic", "pro", "new",
             "old", "cheap", "expensive", "small", "large", "fast"]
    words2 = ["category", "brand", "color", "price", "date", "name",
              "email", "phone", "address", "city", "country", "region",
              "type", "status", "format", "size", "weight", "volume"]
    tags = ["body", "details", "marquee", "input", "form", "div", "span"]
    events = ["load", "click", "mouseover", "focus", "change", "error"]
    funcs = ["alert", "eval", "confirm", "prompt", "console.log"]
    cmds = ["cat", "ls", "id", "whoami", "curl", "wget", "nc"]
    files = ["passwd", "shadow", "hosts", "crontab", "fstab"]
    tables = ["users", "accounts", "admin", "orders", "sessions", "tokens"]
    cols = ["username", "password", "email", "token", "id", "secret"]
    sqlfuncs = ["version", "user", "database", "@@version"]

    def fill(template: str) -> str:
        n = random.randint(1, 99)
        n2 = random.randint(1, 99)
        return (template
                .replace("{n}", str(n))
                .replace("{n2}", str(n2))
                .replace("{word}", random.choice(words))
                .replace("{word2}", random.choice(words2))
                .replace("{tag}", random.choice(tags))
                .replace("{event}", random.choice(events))
                .replace("{func}", random.choice(funcs))
                .replace("{cmd}", random.choice(cmds))
                .replace("{file}", random.choice(files))
                .replace("{table}", random.choice(tables))
                .replace("{col}", random.choice(cols))
                .replace("{sqlfunc}", random.choice(sqlfuncs)))

    attack_texts = [fill(random.choice(attack_templates)) for _ in range(n_attack)]
    clean_texts = [fill(random.choice(clean_templates)) for _ in range(n_clean)]

    texts = attack_texts + clean_texts
    labels = [1] * n_attack + [0] * n_clean

    logger.info("Generated synthetic dataset: %d attack, %d clean", n_attack, n_clean)
    return texts, labels


# ── Preprocessing helpers ─────────────────────────────────────────────────────

def preprocess(texts: List[str]) -> List[str]:
    """
    Light preprocessing: URL-decode and normalise whitespace.
    Does NOT remove attack patterns — the model needs them.
    """
    cleaned = []
    for t in texts:
        # Decode percent-encoded sequences
        try:
            t = urllib.parse.unquote(t)
        except Exception:
            pass
        # Collapse whitespace
        t = re.sub(r"\s+", " ", t).strip()
        cleaned.append(t)
    return cleaned


def class_balance_report(labels: List[int]) -> dict:
    """Return class distribution statistics."""
    total = len(labels)
    attack = sum(labels)
    clean = total - attack
    return {
        "total": total,
        "attack": attack,
        "clean": clean,
        "attack_pct": round(attack / total * 100, 1) if total else 0,
        "clean_pct": round(clean / total * 100, 1) if total else 0,
        "balanced": abs(attack - clean) / max(1, total) < 0.2,
    }


def check_dataset_file(path: str) -> dict:
    """Check if a dataset file exists and return basic info."""
    if not os.path.exists(path):
        return {"exists": False, "path": path}

    size = os.path.getsize(path)
    with open(path, "r", encoding="latin-1", errors="replace") as f:
        line_count = sum(1 for _ in f)

    return {
        "exists": True,
        "path": path,
        "size_mb": round(size / 1024 / 1024, 2),
        "line_count": line_count,
    }
