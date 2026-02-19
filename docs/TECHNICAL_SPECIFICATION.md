# Phishing Email Detection — Technical Specification

Architecture, contracts, and design decisions for the backend and Gmail addon. Single source of truth for implementation.

---

## 1. Output Schema

Response JSON (exact structure):

```json
{
  "label": "Phishing" | "Suspicious" | "Safe",
  "confidence": 0.0,
  "reasons": ["string"],
  "signals": { "rule_id": 0.0 },
  "metadata": {}
}
```

| Field        | Type     | Required | Description |
|-------------|----------|----------|-------------|
| `label`     | enum     | Yes      | Verdict: `Phishing`, `Suspicious`, `Safe`. |
| `confidence`| float    | Yes      | Aggregate score in [0, 1]. |
| `reasons`   | string[] | Yes      | Human-readable explanations, ordered by relevance. |
| `signals`   | object   | Yes      | rule_id → score in [0, 1]. |
| `metadata` | object   | No       | Optional: `processing_ms`, `feed_last_updated`, etc. |

---

## 2. Modules

| Module            | Responsibility |
|-------------------|----------------|
| **Parsing**       | Raw email → **ParsedEmail** (subject, body_plain, body_html, links, sender, sender_domain, headers). |
| **Detection Engine** | Orchestrator: runs rules (and optional ML/LLM), delegates to Aggregator, returns result. |
| **Rules**         | Each rule: ParsedEmail → RuleResult (score [0,1], reasons). No side effects. |
| **Aggregator**    | Weighted combination of rule scores + configurable thresholds → Verdict, confidence, reasons, signals. |
| **ML / LLM (optional)** | Optional scorers called by engine; output treated as extra weighted signal. |
| **API**           | `POST /scan`, `GET /health`; optional `/docs`. |

All modules stateless per request; config read-only.

---

## 3. Rule Framework

**Interface:** each rule has `id: str` and `evaluate(parsed: ParsedEmail) -> RuleResult | None`.

**RuleResult:** `rule_id`, `score` in [0, 1], `reasons: list[str]`.

**Input:** Rules receive only **ParsedEmail** (§4). No raw bytes; external data via injectable dependencies.

**Weighting:** Configurable weight per rule (default 1.0). Aggregation: weighted average of scores, then clamp to [0,1]. Thresholds: `confidence >= phishing_threshold` → Phishing; `>= suspicious_threshold` → Suspicious; else Safe. All in config (e.g. `core/constants`); no magic numbers in rules.

**Initial rules:** links, sender, language, html (and e.g. openphish when reputation DB is used).

---

## 4. Parsing

**Input:** Raw RFC email from API (client sends full message; all parsing in backend).

**ParsedEmail fields:**

| Field             | Type     | Description |
|-------------------|----------|-------------|
| subject           | str      | Decoded subject. |
| body_plain        | str      | Plain text (text/plain or stripped). |
| body_html         | str \| None | HTML part if present. |
| links             | list[str] or list[ExtractedLink] | Normalized URLs (and optional display text). |
| sender_email     | str      | From addr-spec. |
| sender_domain    | str      | Domain part, lowercase. |
| sender_display_name, reply_to | str \| None | Optional. |
| headers           | dict[str, str] | Relevant headers. |

**Normalization:** UTF-8; domain lowercase; links deduplicated/normalized; line breaks `\n`. Missing/invalid fields → safe defaults.

---

## 5. Integration & API

**Data flow:** API → parse raw → ParsedEmail → Engine runs rules (and optional ML/LLM) → Aggregator → DetectionResult → JSON response.

**API:**
- **POST /scan** — Body: `{ "raw": "<full RFC email>" }`. Response: schema §1. Errors: 400, 422, 500.
- **GET /health** — 200, e.g. `{"status": "ok"}`.

**Optional ML/LLM:** Engine may call ML (feature vector) or LLM (sanitized text); scores fed into Aggregator like rules; metadata e.g. `llm_used`. Failure → fallback to rules-only, do not fail request.

---

## 6. Testing

- **Unit:** Parsing (fixtures → ParsedEmail); each rule (ParsedEmail → RuleResult); Aggregator (RuleResults → Verdict/confidence). Cover thresholds and edge cases.
- **Integration:** POST /scan with fixture emails; assert schema §1 and status 200.
- Fixtures in `tests/fixtures/`; mock LLM/external calls. No real API keys in tests.

---

## 7. Constraints

- **Out of scope (initial):** ML training, production LLM, DB persistence, auth.
- **Security:** No logging of email content or PII; request body size limits; secrets in env only.
- **Failure:** Rule exception → treat as score 0 (or skip); ML/LLM failure → rules-only result + metadata.

---

## 8. Extensions

- **New rule:** Implement interface, add to engine’s rule list, add weight in config.
- **ML/LLM:** Optional modules; config (enable, paths, timeouts) in core/settings. No magic numbers in logic.
