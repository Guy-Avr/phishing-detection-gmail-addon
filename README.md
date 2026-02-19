# phishing-detection-gmail-addon

Technical design: [docs/TECHNICAL_SPECIFICATION.md](docs/TECHNICAL_SPECIFICATION.md)

## Running the project

### 1. Go to the backend folder

```bash
cd backend
```

### 2. Create a virtual environment (venv)

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

**Windows (PowerShell):**
```powershell
.\.venv\Scripts\Activate.ps1
```

**Windows (CMD):**
```cmd
.venv\Scripts\activate.bat
```

**Linux / macOS:**
```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the server

```bash
uvicorn app.main:app --reload
```

The app will be available at **http://127.0.0.1:8000**

- API docs (Swagger): http://127.0.0.1:8000/docs

### Run tests

From the `backend` folder (with venv activated):

```bash
pytest
```

### How scoring works

All tuning is in `backend/app/core/constants.py`.

**1. Final confidence (0?1)**  
Links, sender, language, html always run and return a score (0 when no signals); openphish is added only when a link matches the threat feed.  
`confidence = clamp( (sum of score_i * rule_weight_i) / (sum of rule_weight_i) , 0, 1)`  
Rule weights: `RULE_WEIGHTS` (links, sender, language, html, openphish), default 1.0 each.

**Override:** If any email link is in the OpenPhish feed ? **confidence = 1.0** and **verdict = Phishing** (regardless of other rules).

**2. Verdict**  
- confidence >= 0.7 ? **Phishing**  
- confidence >= 0.4 and < 0.7 ? **Suspicious**  
- else ? **Safe**  
Thresholds: `PHISHING_THRESHOLD`, `SUSPICIOUS_THRESHOLD`.

**3. Per-rule score (0?1)**

| Rule | Logic | Tuning in constants |
|------|--------|----------------------|
| **links** | Sum of weights per signal, cap 1.0. Signals: IP host (0.5), shortener (0.3), anchor mismatch (0.5). Mismatch = display text looks like a URL but href points elsewhere; plain "click me" is not counted. | `LINK_WEIGHT_*`, `SHORTENER_DOMAINS` |
| **html** | Sum of weights per signal, cap 1.0. Signals: form (0.3), hidden input (0.55), inline JS (0.3), script tag (0.4). | `HTML_WEIGHT_*`, `SUSPICIOUS_JS_ATTRS` |
| **language** | Ratio of urgency phrases to word count; higher ratio ? higher score. | `URGENCY_PHRASES` |
| **sender** | Sum of weights per signal, cap 1.0. **Exact** brand on free email (e.g. paypal@gmail.com) = 0.5. **Distorted** name = 1.0: local part (e.g. paypa1) or domain (e.g. paypa1.com, natflix.com) similar to brand but not exact. | `SENDER_WEIGHT_*`, `FREE_EMAIL_DOMAINS`, `KNOWN_BRANDS`, `BRAND_SIMILARITY_THRESHOLD` |
| **openphish** | If any email link is in the threat-feed DB ? score 1.0 and confidence is forced to 1.0. | Feed path: `PHISH_DB_PATH` |

**4. Response**  
`signals` = each rule's score; `reasons` = lines from rules that fired, ordered by score.

### OpenPhish threat feed

The scanner checks links against a local SQLite DB of known phishing URLs (OpenPhish Community Feed). The DB path is set via `PHISH_DB_PATH` (default: `data/phish_urls.db`).

**The feed updates automatically** while the server is running: first run 30 seconds after startup, then every 12 hours (configurable via `FEED_UPDATE_INTERVAL_HOURS` in `app/core/constants.py`).

To update manually (e.g. without starting the server, or to force an update), from the `backend` folder:

```bash
python -m app.tasks.update_phish_feed
```

You should see something like: `Updated phish DB: 12345 URLs, last_updated=2025-02-19T...`

**Check that it works (no SQLite knowledge needed):**

From the `backend` folder, after running the update once:

```bash
python -c "import sqlite3; c=sqlite3.connect('data/phish_urls.db'); r=c.execute('SELECT last_updated, urls_count FROM feed_metadata WHERE id=1').fetchone(); print('Last updated:', r[0], '| URLs in DB:', r[1]); print('Sample URL:', c.execute('SELECT url FROM phish_urls LIMIT 1').fetchone()[0])"
```

- If the DB exists and was updated: you get `Last updated: ... | URLs in DB: <number>` and a sample URL.
- If the DB is missing or empty: run `python -m app.tasks.update_phish_feed` first (it creates the file and downloads the feed).

After the first run, scan responses may include `metadata.feed_last_updated` with the last feed update time.
