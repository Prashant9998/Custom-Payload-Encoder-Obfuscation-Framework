# Custom Payload Encoder & Obfuscation Framework

> A red-team research toolkit for testing WAF bypass techniques through systematic payload encoding, obfuscation, and mutation — built for fast local iteration. Not commercial. Not basic.

---

## Overview / The Problem This Solves

Manual WAF bypass testing is tedious: encode a payload by hand, paste it into Burp, wait, repeat. There was no tool that combined fast multi-technique encoding, a simulation WAF you could configure yourself, and a batch tester that gives you an evasion rate immediately. So this was built.

Started as a 200-line script. Added a WAF engine to catch variants in-house. Added a web UI because nobody wants to touch a CLI mid-engagement. Added a decoder to reverse-engineer unfamiliar encoded payloads. Now it does all of that in one place.

---

## Tool Scope & Focus

This tool simulates signature-based WAFs (regex/pattern matching), not:
- Behavioral analysis systems
- Machine learning-based WAFs
- ModSecurity CRS full ruleset

It is intentionally simple at the detection layer so you can isolate *encoding* effectiveness, not fight the WAF engine itself.

---

## Project Objective

1. **Encode** — Transform payloads using one or more of 11 techniques
2. **Mutate** — Deeply rewrite payload logic (synonyms, CHAR(), null bytes)
3. **Decode** — Auto-detect and reverse unknown encoded strings
4. **Test** — Run payloads against a configurable local WAF engine
5. **Report** — Export evasion results as JSON, CSV, or HTML

---

## Payload Categories

| Category | Example Payloads |
|---|---|
| SQL Injection | `' OR 1=1 --`, `UNION SELECT`, `admin'--` |
| Cross-Site Scripting (XSS) | `<script>alert(1)</script>`, `<img onerror=...>` |
| Command Injection | `; ls -la`, `\| cat /etc/passwd`, `$(whoami)` |
| Path Traversal | `../../etc/passwd`, `%2e%2e%2f` |
| Header Injection | `%0d%0aSet-Cookie: admin=true` |

---

## Payload Logic & Design

### Encoding Techniques (11 built-in)

1. **URL Encoding** — `%XX` hex sequences
2. **Double URL Encoding** — `%25XX` to bypass single-decode filters
3. **Unicode Encoding** — `\uXXXX` escape sequences
4. **HTML Entity Encoding** — `&#xNN;` hex entities
5. **Base64 Encoding** — full payload as Base64 string
6. **Hex Encoding** — `\xNN` notation per character
7. **Case Alternation** — `sElEcT`, `UnIoN`
8. **SQL Comment Injection** — `SE/**/LECT`
9. **Whitespace Obfuscation** — spaces → `%09`, `%0a`, `\t`
10. **Concatenation / Splitting** — `'SEL'+'ECT'`
11. **ROT47 Encoding** — rotate printable ASCII by 47 positions

### Mutation Engine (6 strategies)

1. **Keyword Synonym Replacement** — `OR` → `||`, `UNION ALL`
2. **Comment Padding** — `/*!50000 SELECT*/`
3. **Numeric Obfuscation** — `1=1` → `2>1`, `CHAR(49)=CHAR(49)`
4. **Char-Code Building** — `CHAR()` for SQL, `String.fromCharCode()` for JS
5. **Null Byte Injection** — `%00` before special characters
6. **Full Mutation** — apply all strategies in combination

---

## Workflow Interface & Architecture

```
Browser UI (index.html + app.js + app.css)
         ↕ REST API (Flask)
    server.py  ─────────────┐
         ↕                  ↕
payload_encoder.py     waf_engine.py
(encoder, decoder,     (rules, inspect,
 mutator)               persist: waf_state.json)
```

**Tabs:**
- ⚡ **Encoder Studio** — single or chained encoding with WAF test
- 🔓 **Decoder** — auto-detect encoding type and reverse it
- 🧬 **Mutations** — deep payload transformation beyond encoding
- 🧪 **Batch Test** — generate N variants, fire all, get evasion rate
- 🛡 **WAF Rules** — toggle rules, add custom regex rules (persisted)
- 📦 **Samples** — click-to-load attack payload library

---

## Supported Target Platforms

- Applications using signature-based WAFs (ModSecurity lite, AWS WAF, Cloudflare basic, etc.)
- Any HTTP endpoint accepting GET/POST parameters
- APIs accepting JSON body with string values

---

## Quickstart

```bash
pip install -r requirements.txt
python server.py
# Open http://127.0.0.1:5001
```

No Docker. No config files. Just runs.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/techniques` | List 11 encoding techniques |
| POST | `/api/encode` | Encode with one technique |
| POST | `/api/chain-encode` | Apply multiple techniques in sequence |
| POST | `/api/generate` | Generate N encoded variants |
| POST | `/api/test` | Test a single payload against WAF |
| POST | `/api/batch-test` | Generate + test N variants |
| POST | `/api/decode` | Decode a payload (auto or specific) |
| POST | `/api/detect` | Detect encoding type in a payload |
| POST | `/api/mutate` | Apply a mutation strategy |
| GET | `/api/mutations` | List available mutation types |
| GET | `/api/waf/rules` | List WAF rules and hit counts |
| POST | `/api/waf/add-rule` | Add a custom regex WAF rule |
| POST | `/api/waf/delete-rule` | Delete a custom rule |
| POST | `/api/waf/toggle-rule` | Enable/disable a rule |
| GET | `/api/waf/stats` | WAF inspection statistics |
| POST | `/api/export/json` | Export batch report as JSON |
| POST | `/api/export/csv` | Export batch results as CSV |
| POST | `/api/export/html` | Export styled HTML report |
| GET | `/api/samples` | Sample payloads by category |
| GET | `/api/history` | Recent encoding history |

---

## Running the Tests

```bash
cd tests
python test_payload_encoder.py
```

**68 tests. All should pass.** Covers:
- All 11 encoding techniques individually
- Chain encoding (2–3 layers)
- Variant generation (single and limited technique sets)
- WAF evasion detection on raw and encoded payloads
- Batch test report accuracy
- Decoder auto-detection
- Mutation strategies (all 6 types, including null-byte edge cases)
- ROT47 encode + reversibility verification
- Error handling for invalid technique names

---

## Features Roadmap

- [x] 11 encoding techniques (ROT47 added)
- [x] Chained encoding (2–3 layer depth)
- [x] Standalone WAF engine with 5 default rulesets
- [x] Custom WAF rules (persistent across restarts)
- [x] Batch evasion testing with evasion rate metric
- [x] Export: JSON, CSV, HTML reports
- [x] Decoder with auto-detection and step-by-step view
- [x] Mutation engine (6 strategies)
- [x] ROT47 encoding and decoding support
- [x] Null byte injection edge case test coverage
- [ ] Chain length cap (prevent nonsensically long payloads)
- [ ] ROT13 and ROT13-5 variants
- [ ] Async batch processing for large variant sets

---

## Known Limitations

- WAF engine is purely regex-based — no semantic or ML analysis
- Chained encoding can produce very long payloads (no cap enforced yet)
- Export HTML is functional but minimal in styling

---

## Project Structure

```
.
├── payload_encoder.py    # Core engine: PayloadEncoder, PayloadDecoder, PayloadMutator
├── waf_engine.py         # WAF simulation engine (with persistence)
├── server.py             # Flask API routes
├── requirements.txt      # flask
├── waf_state.json        # Auto-generated: persists WAF rule toggles and custom rules
├── static/
│   ├── app.css           # All styling + animations
│   └── app.js            # Frontend logic + canvas background
├── templates/
│   └── index.html        # Single-page dashboard
└── tests/
    └── test_payload_encoder.py   # 68 tests
```

---

## License

MIT. Use it for authorized testing only.

---

*Built by [@Prashant9998](https://github.com/Prashant9998) — maintained in spare time.*
