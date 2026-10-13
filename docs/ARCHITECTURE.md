# PromptShield AI - Architecture & Design Specification

## Overview

**PromptShield AI** is a client-side cybersecurity browser extension built under Chrome Manifest V3. Its purpose is to detect sensitive credentials, private keys, database connection URIs, and confidential data patterns directly within the browser tab before a prompt is transmitted to AI services like ChatGPT.

---

## Architecture Diagram

```
+-----------------------------------------------------------------------------------+
| Browser Tab (chatgpt.com / chat.openai.com / localhost sandbox)                    |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | DOM Tree (ProseMirror / ContentEditable / Form Elements)                    |  |
|  |   [#prompt-textarea]   [Attach Button]   [Voice Button]   [Send Button]     |  |
|  +-----------------------------------------------------------------------------+  |
|                               ^                                     |             |
|          1. DOM Mount Watcher |                  2. User Submission | (Capture)   |
|          (MutationObserver)   |                  [Enter / Click / Form]           |
|                               v                                     v             |
|  +-----------------------------------------------------------------------------+  |
|  | PromptShield Content Script (content.js)                                    |  |
|  |   - Filter out non-submission controls (Attach / Voice / IME / Shift+Enter) |  |
|  |   - Extract prompt text in-memory                                           |  |
|  +-----------------------------------------------------------------------------+  |
|                                       |                                           |
|                                       v                                           |
|  +-----------------------------------------------------------------------------+  |
|  | Standalone Detection Engine (detector.js)                                  |  |
|  |   - Zero-dependency Regex & Heuristic analysis                              |  |
|  |   - False-positive filtering (placeholders, process.env lookups)            |  |
|  |   - Redaction pipeline (masks credentials; secrets never retained)          |  |
|  +-----------------------------------------------------------------------------+  |
|                       /                                \                          |
|         [Safe Prompt] /                                  \ [Violation: Block]     |
|                      v                                    v                       |
|          Allow Event to Propagate                 event.preventDefault()          |
|          to ChatGPT Handlers                      event.stopImmediatePropagation()|
|                                                           |                       |
|                                                           v                       |
|                                           +-------------------------------+       |
|                                           | In-Page Alert UI (ui.js)      |       |
|                                           | - Singleton alert modal       |       |
|                                           | - Redacted snippet preview    |       |
|                                           | - Refocus on composer         |       |
|                                           +-------------------------------+       |
|                                                           |                       |
|                                                           v (Redacted only)       |
|                                           +-------------------------------+       |
|                                           | chrome.storage.local          |       |
|                                           | (Rule ID, Sev, Redacted text) |       |
|                                           +-------------------------------+       |
+-----------------------------------------------------------------------------------+
```

---

## Key Technical Decisions

### 1. Multi-Path Submission Interception (Capture Phase)
ChatGPT renders its interface via React and ProseMirror. React binds its event delegation handlers at the `root` or `document` level.
To prevent the prompt from being sent, PromptShield attaches global listeners in the **capture phase** (`useCapture: true`):
- `window.addEventListener('keydown', handleKeydownCapture, true)`
- `window.addEventListener('click', handleClickCapture, true)`
- `window.addEventListener('submit', handleSubmitCapture, true)`

When a user attempts to submit a prompt containing high-risk secrets:
1. PromptShield's capture listener intercepts the event before child nodes or bubbling listeners receive it.
2. It executes `event.preventDefault()` and `event.stopImmediatePropagation()`.
3. The submit signal never reaches ChatGPT's React event handlers.

### 2. Precise Control Discrimination
To avoid breaking legitimate user workflows, PromptShield selectively inspects only submission triggers:
- **Shift+Enter**: Ignored (allows creating multiline paragraphs).
- **IME Composition**: If `event.isComposing` or `event.keyCode === 229`, PromptShield steps aside so East Asian input methods function without interruption.
- **Attachment Button**: Explicitly excluded by `data-testid`, `aria-label`, and class heuristics.
- **Voice / Microphone Button**: Explicitly excluded.

### 3. Role of `MutationObserver`
`MutationObserver` does not intercept submissions. Instead, it serves as the **DOM attachment monitor**:
- Watches `document.body` for child list mutations with a debounce timer.
- When ChatGPT unmounts the composer during chat navigation or streaming responses and mounts a new one, PromptShield re-binds its internal references without requiring a page refresh.

### 4. Local-First & Zero-Telemetry Privacy
- The detection engine (`detector.js`) is completely standalone and zero-dependency.
- It makes **no network calls** (no `fetch`, `XMLHttpRequest`, or `WebSocket`).
- All prompt data is inspected ephemerally in RAM and garbage-collected.
- Local incident storage (`chrome.storage.local`) persists only metadata: timestamp, rule ID, and masked strings (e.g. `sk-proj-****...`).
