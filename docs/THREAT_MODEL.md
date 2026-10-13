# PromptShield AI - Threat Model & Security Boundaries

## 1. System Classification: Assistive Endpoint Guardrail

> [!CAUTION]
> **PromptShield AI is an assistive client-side guardrail, NOT a tamper-proof enterprise security boundary.**
> It is designed to prevent accidental, inadvertent data leakage by well-intentioned users copying and pasting credentials or tokens into AI chat prompts. It cannot and does not guarantee containment against a determined adversary possessing local access to the workstation.

---

## 2. Security Assumptions

1. **Host Environment**: The operating system and Chrome browser executable are presumed uncompromised.
2. **Intent**: The primary threat actor addressed is the **honest-but-careless user** who unintentionally pastes proprietary API keys, database credentials, or private keys into an AI assistant.
3. **Local Storage**: Data written to `chrome.storage.local` is isolated to the extension's sandbox by Chrome's security model, but can be viewed by local administrative users.

---

## 3. Explicitly Uninspected Vectors & Limitations

PromptShield AI Phase 1 does **NOT** inspect or protect against the following vectors:

### A. File Attachments & Uploads
- **Vector**: A user clicks the paperclip icon or drags and drops a file (e.g. `.env`, `.pem`, `id_rsa`, `.json`, or Python scripts containing hardcoded credentials) into the ChatGPT upload area.
- **Status**: **Uninspected**. PromptShield Phase 1 only inspects the text composer. Files uploaded via multi-part form data or binary FileReader streams are not parsed.

### B. Voice / Audio Dictation
- **Vector**: A user speaks sensitive credentials into the microphone via ChatGPT's voice mode or web speech transcription.
- **Status**: **Uninspected**. Audio transcription streams bypass text composer keydown interception.

### C. Client-Side Bypasses & Tampering
- **Vector**: A user or local script disables the extension via `chrome://extensions/`, launches Chrome in Incognito/Guest mode where the extension is not enabled, or opens DevTools to disable JavaScript or override DOM event listeners.
- **Status**: **Unpreventable on Client**. Any client-side extension can be disabled or modified by a user with local device access. True enterprise containment requires network-level proxies (CASB/SSE) or enterprise-managed browser policies.

### D. Interface Volatility & Novel UI Variants
- **Vector**: OpenAI updates ChatGPT's DOM hierarchy, migrates from `#prompt-textarea` to an unmapped shadow DOM root, or introduces novel interaction surfaces (e.g., Canvas, Custom GPT configuration panels, API playground).
- **Status**: **Potential Blind Spot**. While PromptShield uses fallback selectors and `MutationObserver`, rapid third-party UI redesigns require ongoing regression testing.

### E. Adversarial Obfuscation
- **Vector**: A user encodes secrets in Base64 (`c2stcHJvai...`), hex strings, ROT13, or character-spaced formats (`s k - p r o j - ...`).
- **Status**: **Out of Scope for Regex Engine**. Pattern-based regex engines target standard token formats.

---

## 4. Privacy & Data Handling Guarantees

| Requirement | Implementation in PromptShield AI |
| :--- | :--- |
| **Outbound Telemetry** | **Zero**. No external network connections (`fetch`, `xhr`, `ws`) are made. |
| **Raw Prompt Storage** | **Never**. Prompts are evaluated strictly in ephemeral RAM and immediately discarded. |
| **Detected Secret Storage** | **Never**. Secrets are sanitized via `maskSensitive()` before writing to `chrome.storage.local`. |
| **Audit Log Exposure** | Only high-level rule IDs (e.g., `SEC-001`), severity, and masked prefixes (e.g., `sk-proj-****...`) are recorded. |
