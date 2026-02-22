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

### Gmail Add-on

The add-on lives in the `addon/` folder and works with the backend scan API. It does not run any detection itself; it sends the current email's raw content to `POST /scan` and shows the result (label, confidence, reasons, and optional LLM opinion).

**Working with localhost:** The add-on runs on Google's servers and can only call **HTTPS** URLs. You cannot use `http://127.0.0.1:8000` directly. Use **ngrok** (or another tunnel) to expose your local backend over HTTPS, then set `BACKEND_URL` to that URL.

**Setup**

1. **Backend + tunnel (for localhost)**  
   - Start the backend: `cd backend && uvicorn app.main:app --reload` (listens on `http://127.0.0.1:8000`).  
   - In another terminal, run **ngrok**: `ngrok http 8000`.  
   - Copy the **HTTPS** URL ngrok shows (e.g. `https://abc123.ngrok-free.app`). You will use it as `BACKEND_URL`.

2. **Create an Apps Script project**  
   - Go to [script.google.com](https://script.google.com) and create a new project.  
   - In **Project Settings**, enable **Show appsscript.json manifest file in editor**.

3. **Copy add-on files**  
   - Replace the default `Code.gs` with the contents of `addon/Code.gs`.  
   - Replace the default `appsscript.json` with the contents of `addon/appsscript.json` (so you get `oauthScopes`, `urlFetchWhitelist`, and `addOns`).

4. **Set the backend URL**  
   - In the Apps Script editor: **Project Settings** → **Script Properties** → Add property `BACKEND_URL`.  
   - **Local (via ngrok):** set value to your ngrok HTTPS URL, e.g. `https://abc123.ngrok-free.app` (no trailing slash).  
   - **Deployed backend:** set value to your API base URL, e.g. `https://your-backend.example.com`.  
   - If you don't set `BACKEND_URL`, the add-on falls back to `http://127.0.0.1:8000` (which will fail from Google's servers).

5. **Install the add-on in Gmail**  
   - **Deploy** → **Test deployments** → **Install** → **Done**.  
   - Open Gmail, open a **single email**, open the add-on from the right panel, click **Scan for Phishing**.  
   - On first use, approve the permissions (including external requests).

**UI**

- **Result**: label (Phishing / Suspicious / Safe) with a short color hint (Red / Orange / Green).  
- **Confidence**: percentage.  
- **Reasons**: list of explanations from the backend.  
- If the backend used the LLM (for Suspicious emails), **LLM opinion** is shown: LLM label, confidence, and reasons.

**Manifest notes**

- `oauthScopes` includes `script.external_request` so the add-on can call `UrlFetchApp.fetch` to your backend.  
- `urlFetchWhitelist` allows only **HTTPS** prefixes (e.g. `https://*.ngrok.io/`, `https://*.ngrok-free.app/`, `https://*.ngrok-free.dev/`). Google does not allow `http://localhost` in the whitelist.

**Using ngrok (localhost)**

To use the add-on with the backend running on your machine, expose it over HTTPS with ngrok:

1. **Install ngrok**  
   - Download from [ngrok.com](https://ngrok.com) (free sign-up) or install via package manager (e.g. `choco install ngrok` on Windows, `brew install ngrok` on macOS).

2. **First-time setup (authtoken)**  
   - Sign up at [dashboard.ngrok.com](https://dashboard.ngrok.com) and copy your **Authtoken**.  
   - In a terminal: `ngrok config add-authtoken YOUR_TOKEN`.  
   - Without this, ngrok may exit immediately or show an error.

3. **Run ngrok**  
   - Start the backend in one terminal: `cd backend && uvicorn app.main:app --reload`.  
   - In a **second terminal** (keep it open): run `ngrok http 8000`.  
   - Do not run ngrok by double-clicking; use an already-open terminal so you can see the URL and any errors.

4. **Copy the HTTPS URL**  
   - ngrok prints a line like: `Forwarding   https://xxxx.ngrok-free.app -> http://localhost:8000` (or `ngrok-free.dev`, `ngrok.io`).  
   - Copy the **HTTPS** URL (e.g. `https://coleman-xxx.ngrok-free.dev`).

5. **Configure the add-on**  
   - In Apps Script: **Project Settings** → **Script Properties** → set `BACKEND_URL` to that URL (no trailing slash).  
   - If your URL is on **ngrok-free.dev**, ensure `appsscript.json` includes `"https://*.ngrok-free.dev/"` in `urlFetchWhitelist` (the repo version already has it).

6. **Keep ngrok running**  
   - Leave the ngrok terminal open while testing. Closing it stops the tunnel and the add-on will no longer reach your backend.

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

### LLM (optional)

When the **rule-based verdict is Suspicious** (confidence between 0.4 and 0.7), the backend can optionally call an LLM to analyze the email (subject, sender, body) and return a second opinion. The **final label and confidence stay rule-based**; the LLM result is returned only in `metadata` for the addon to display (e.g. ?LLM thinks: Phishing (0.8)?).

**When the LLM runs:** only if the aggregator verdict is **Suspicious**. Safe and Phishing verdicts do not trigger the LLM.

**Choose one provider** via environment variable (in `.env` or `backend/.env`):

| Env variable   | Description |
|----------------|-------------|
| `LLM_PROVIDER` | `ollama` (default) or `gemini` |

**Ollama** (local):

| Variable         | Default                  | Description        |
|------------------|--------------------------|--------------------|
| `OLLAMA_URL`     | `http://localhost:11434` | Ollama API base    |
| `OLLAMA_MODEL`   | `llama2`                 | Model name         |
| `LLM_TIMEOUT_SEC`| `30`                     | Request timeout (s)|

**Gemini** (Google):

| Variable         | Default            | Description        |
|------------------|--------------------|--------------------|
| `GEMINI_API_KEY` | (required)         | API key            |
| `GEMINI_MODEL`   | `gemini-1.5-flash` | Model name         |
| `LLM_TIMEOUT_SEC`| `30`               | Request timeout (s)|

**Response when LLM ran:** in `metadata` you get:

- `llm_used`: `true`
- `llm_confidence`: 0?1 risk score from the model
- `llm_label`: `"safe"` / `"suspicious"` / `"phishing"` (derived from `llm_confidence` using the same thresholds: ?0.7 ? phishing, ?0.4 ? suspicious, else safe)
- `llm_reasons`: short explanation lines from the model (e.g. `["LLM (ollama): Urgent language.", ...]`)

If the LLM is not invoked (verdict Safe/Phishing) or the call fails, `llm_used` is `false` and `llm_confidence` / `llm_label` / `llm_reasons` are omitted. The rule-based result is unchanged.

**Logging:** when the server runs with default logging, you?ll see lines such as:

- `LLM: invoking (verdict=Suspicious)`
- `LLM: result provider=ollama risk_score=0.65 reasons_count=2`
- On failure: `LLM: no provider succeeded, using rule-only result` or `LLM: invocation failed, using rule-only result: ...`
