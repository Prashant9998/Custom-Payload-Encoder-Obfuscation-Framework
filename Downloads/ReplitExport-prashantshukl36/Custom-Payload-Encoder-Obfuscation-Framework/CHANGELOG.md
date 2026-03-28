# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

---

## [2.0.0] — 2026-03-10

This was a big one. Basically rewrote the frontend from scratch and added three new backend engines.

### Added
- **Decoder engine** (`PayloadDecoder`) — auto-detects and reverses URL/base64/hex/unicode/HTML-entity encoding. Handles multi-layer encoding by stripping one layer at a time.
- **Mutation engine** (`PayloadMutator`) — six mutation strategies that go beyond encoding: synonym replacement, SQL comment padding, numeric obfuscation, char-code building, null-byte injection, and randomized case mixing.
- **Custom WAF rule builder** — add your own regex-based rules at runtime via the UI or API. Rules are toggleable. Hit counts tracked per rule.
- **Export system** — batch test reports downloadable as JSON, CSV, or a self-contained HTML file.
- `/api/decode`, `/api/detect`, `/api/mutate`, `/api/mutations`, `/api/generate-mutations` endpoints
- `/api/waf/add-rule`, `/api/waf/delete-rule`, `/api/waf/toggle-rule`, `/api/waf/reset-stats`
- `/api/export/json`, `/api/export/csv`, `/api/export/html`
- Complete dashboard redesign — dark cyberpunk aesthetic with canvas particle animation in background, glassmorphism cards, animated stats counters
- Quick-load payload pills in Encoder, Mutations, and Batch Test tabs
- Sample payloads library (SQLi, XSS, CMDi, Path Traversal, Header Injection)
- 3D card tilt effect on technique/mutation selector cards (mouse tracking)

### Changed
- Frontend split from one inline `<script>` block into external `static/app.js` and `static/app.css` — the original single-file approach was getting unmaintainable
- WAFEngine now tracks `hit_count` per rule separately from total inspection stats
- Batch test now generates chain-encoded variants in addition to single-technique variants

### Fixed
- `chain-encode` endpoint was returning 500 if only one technique was provided. Now returns the single-encode result instead of erroring.
- Stats row was not refreshing after WAF tests — now calls `loadStats()` after every test operation

---

## [1.2.0] — 2026-02-18

### Added
- Chain encoding support (`/api/chain-encode`) — apply multiple techniques sequentially
- `/api/samples` endpoint with categorized attack payload library
- Batch test now shows confidence scores per result

### Changed
- WAF inspect now returns matched rule details, not just a boolean
- Dashboard tabs are now keyboard-accessible (Tab + Enter)

### Fixed
- URL encoding wasn't encoding `+` signs correctly in some edge cases
- HTML entity encoding was double-encoding ampersands when input contained `&amp;`

---

## [1.1.0] — 2026-01-30

### Added
- WAF Engine (`waf_engine.py`) — standalone regex-based detection engine with 5 default rulesets
- `/api/test` endpoint — test any payload string directly against the active WAF rules
- `/api/batch-test` for automated multi-variant testing
- Evasion rate calculation in batch test results

### Changed
- Switched from returning plain strings to `EncodedPayload` dataclass — makes it easier to carry metadata through the pipeline

---

## [1.0.0] — 2026-01-12

Initial version. Just the encoder and a very rough web UI.

### Added
- 10 encoding techniques in `PayloadEncoder`
- Basic Flask server with `/api/encode` and `/api/techniques`
- Minimal single-page dashboard (honestly it was kind of ugly)
- pytest suite covering all encoding methods
