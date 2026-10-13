# PromptShield AI (Phase 1: Chrome Extension MVP)

> **Local-First, Zero-Telemetry Prompt Protection Guardrail for AI Web Interfaces**

**PromptShield AI** is a Chrome Manifest V3 extension that inspects prompts typed into ChatGPT (`chatgpt.com` / `chat.openai.com`) locally in real-time, alerts users to sensitive data exposure, and blocks high-risk submissions before they leave the browser.

---

## Architecture & Project Structure

```
inotech/
├── extension/                     # Chrome Manifest V3 Extension
│   ├── manifest.json              # Extension metadata, permissions & content scripts
│   ├── icons/                     # Extension toolbar & store icons
│   │   ├── icon16.png
│   │   ├── icon48.png
│   │   └── icon128.png
│   ├── background/
│   │   └── service_worker.js      # Background worker (badge updates & storage initialization)
│   ├── content/
│   │   ├── content.js             # Event capture interception, IME handling & DOM observer
│   │   ├── detector.js            # Standalone zero-dependency regex & heuristic detection engine
│   │   ├── ui.js                  # Accessible in-page warning modal & composer highlight
│   │   └── content.css            # Dark/light mode adaptive styling
│   ├── popup/
│   │   ├── popup.html             # Status indicator, master toggle & incident log
│   │   ├── popup.css              # Modern cybersecurity dark-theme styling
│   │   └── popup.js               # Storage synchronization controller
│   ├── rules/
│   │   └── default_rules.js       # Rule catalog with category & severity metadata
│   └── sandbox/
│       └── test-harness.html      # Extension-packaged ChatGPT simulation sandbox
├── tests/
│   ├── detector.test.js           # Unit tests for positive vectors & false positives
│   ├── submission-paths.test.js   # Regression tests for event paths & control discrimination
│   ├── test-harness.html          # Standalone test sandbox for local web serving
│   ├── serve-harness.js           # Zero-dependency local HTTP test server
│   └── create-icons.js            # Icon generator script
├── docs/
│   ├── ARCHITECTURE.md            # In-depth system design & event capture mechanics
│   └── THREAT_MODEL.md            # Threat model, limitations & uninspected vectors
├── package.json                   # Test runner scripts (Node.js 18+ native test runner)
├── .env.example                   # Configuration template for future backend phases
└── README.md                      # Project documentation & manual test guide
```

---

## Security & Privacy Guarantees

1. **Zero Outbound Telemetry**: The extension runs 100% locally. It makes zero HTTP/HTTPS/WebSocket requests.
2. **Ephemeral RAM Evaluation**: Prompts are scanned in ephemeral memory during event capture and discarded immediately.
3. **No Secret Persistence**: Incident logs in `chrome.storage.local` store only the rule ID, timestamp, and masked previews (e.g., `sk-proj-****...`). Raw prompts and plaintext secrets are never written to disk or storage.
4. **Assistive Endpoint Guardrail**: Not a tamper-proof enterprise control. See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for full boundary disclosures.

---

## How to Load the Extension in Chrome (Developer Mode)

Follow these steps to install and test the extension in Google Chrome:

1. Open **Google Chrome**.
2. In the URL address bar, navigate to:
   ```text
   chrome://extensions/
   ```
3. In the top-right corner of the Extensions page, enable the **Developer mode** toggle switch.
4. Click the **Load unpacked** button that appears in the top-left toolbar.
5. In the file picker dialog, navigate to the project directory and select the `extension` folder:
   ```text
   C:\Users\mohds\OneDrive\Desktop\inotech\extension
   ```
6. Verify that **PromptShield AI** appears in your extensions list with version `1.0.0` and status enabled.
7. Click the extension puzzle icon in the Chrome toolbar and pin **PromptShield AI** for easy access.

---

## Automated Verification

The test suite runs using Node's native test runner (zero external npm dependencies required):

```powershell
npm test
```

### Actual Test Results (Verified)
```text
> promptshield-ai@1.0.0 test
> node --test tests/*.test.js

✔ PromptShield AI - Detection Engine Unit Tests (10.08ms)
  ✔ Synthetic Positive Vectors (Critical & High Risk - Must Block) (6.20ms)
    ✔ should detect synthetic OpenAI project API key and flag CRITICAL
    ✔ should detect standard synthetic OpenAI API key
    ✔ should detect synthetic AWS Access Key ID
    ✔ should detect synthetic GitHub personal access token
    ✔ should detect Google Cloud API key
    ✔ should detect Slack OAuth token
    ✔ should detect multiline RSA private key blocks
    ✔ should detect database connection strings containing credentials
    ✔ should detect plaintext password assignments in code prompts
  ✔ False Positives Resistance (Safe Content - Must NOT Block) (1.69ms)
    ✔ should allow benign technical questions without alerts
    ✔ should allow code reading environment variables (process.env / os.getenv)
    ✔ should allow JavaScript process.env lookups
    ✔ should allow documentation placeholders and angle-bracket templates
    ✔ should allow placeholder dummy strings like sk-xxxx...
    ✔ should allow general security discussions mentioning password hashing
  ✔ Edge Cases and Input Robustness (1.65ms)
    ✔ should gracefully handle empty strings, null, and whitespace
    ✔ should handle multiline prompts with multiple mixed violations

✔ PromptShield AI - Submission Paths Regression Tests (6.64ms)
  ✔ Control Target Discrimination (Send vs Non-Send) (4.27ms)
    ✔ should identify ChatGPT send-button by data-testid="send-button"
    ✔ should identify Send button by aria-label="Send prompt"
    ✔ should identify nested child SVG clicked inside send button
    ✔ MUST NOT identify attachment button as send button
    ✔ MUST NOT identify voice/mic button as send button
    ✔ MUST NOT identify generic settings or search button as send button
  ✔ Keyboard Event Path Discrimination (1.70ms)
    ✔ should evaluate clean Enter key for submission interception
    ✔ MUST NOT intercept Shift+Enter (must allow multiline prompt creation)
    ✔ MUST NOT intercept during active IME composition (CJK character input)
    ✔ MUST NOT intercept other keys like Tab, Space, Backspace, or Escape

Total: 27 passing tests (0 failures, 119ms)
```

---

## Manual Verification Walkthrough

You can test PromptShield in two environments:

### Option A: Using the Packaged Extension Sandbox (Recommended)
1. Click the PromptShield extension icon in your Chrome toolbar.
2. Click the **Open Test Sandbox** button at the bottom of the popup.
3. This opens `chrome-extension://<EXTENSION_ID>/sandbox/test-harness.html`.

### Option B: Using the Local Web Server
1. Start the local server:
   ```powershell
   npm run serve
   ```
2. Open Chrome and navigate to:
   ```text
   http://localhost:8080/test-harness.html
   ```

### Manual Test Cases Matrix

| Test Case | Steps | Expected Result |
| :--- | :--- | :--- |
| **1. Benign Prompt Submission** | Click **"Safe Vector"** button (or type "Explain how DNS works"). Press **Enter** or click **Send**. | Prompt submits normally. Event console shows `[SUBMITTED]`. No alert appears. |
| **2. Synthetic OpenAI Key Interception** | Click **"Synthetic OpenAI Key"** button. Press **Enter**. | Submission is **blocked**. In-page PromptShield modal displays: `[CRITICAL - BLOCKED] OpenAI API Key`. No submission event in console. |
| **3. Synthetic AWS Key via Mouse Click** | Click **"Synthetic AWS Access Key"**. Click the circular **Send** button with mouse. | Submission is **blocked** via mouse click path. Modal appears with `AWS Access Key ID`. |
| **4. Multiline Private Key Block** | Click **"Synthetic Private Key Block"**. Press **Enter**. | Submission is **blocked**. Modal displays `Private Key Block (SEC-001)`. |
| **5. Multiline Navigation (Shift+Enter)** | Click into composer. Hold **Shift** and press **Enter** 3 times. | Newlines are inserted normally. Submission is **NOT** blocked. |
| **6. Attachment & Voice Non-Interference** | Click the **"Attach File"** paperclip button or **"Voice"** button. | Click fires normally. Event console records `[ATTACHMENT]` / `[VOICE]`. PromptShield does not interfere. |
| **7. False Positive Resistance** | Click **"Environment Variable Lookup"** (`const key = process.env.OPENAI_API_KEY;`). Press **Enter**. | Submits cleanly without false alerts. |
| **8. Dynamic DOM Remount Resilience** | Click **"Simulate SPA Navigation"**. Wait 400ms for composer to remount. Paste a synthetic OpenAI key and press Enter. | MutationObserver successfully re-binds; submission is blocked. |
| **9. Master Switch Toggle** | Open extension popup. Toggle **Real-Time Protection** to **Paused**. Attempt to send a synthetic key. | Prompt submits normally when paused. Re-enabling toggle restores blocking. |
| **10. Local Redacted Audit Log** | Open extension popup. Inspect the **Recent Redacted Incidents** section. | Displays blocked incidents with rule name, timestamp, and severity. Confirms **zero raw secrets or prompts** were stored. |
#   P r o m p t S h i e l d  
 