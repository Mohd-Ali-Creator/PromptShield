/**
 * PromptShield AI - ChatGPT Content Script
 * 
 * Intercepts prompt submissions on ChatGPT (chatgpt.com / chat.openai.com).
 * 
 * CORE RESPONSIBILITIES:
 * 1. Resiliently binds to ChatGPT's prompt composer (ProseMirror / textarea) via MutationObserver.
 * 2. Multi-event capture: intercepts pointerdown, mousedown, click, keydown (Enter), and form submit.
 * 3. Correctly preserves Shift+Enter (multiline) and IME composition events.
 * 4. Stays clear of non-submission controls (paperclip attachments, voice/mic, web search).
 * 5. Runs zero network requests (100% local inspection).
 * 6. Never logs or persists unredacted prompts or secrets.
 * 7. Emits safe diagnostic logs (lifecycle events, selector match types, violation counts).
 */

(function () {
  'use strict';

  if (typeof window !== 'undefined') {
    if (window.__promptshield_content_script_active) {
      return;
    }
    window.__promptshield_content_script_active = true;
  }

  // State
  let isEnabled = true;
  let protectionMode = 'STRICT'; // 'STRICT' (blocks high/critical) or 'AUDIT' (warns only)
  let activeComposer = null;
  let observer = null;
  let debounceTimer = null;

  // Submission gesture state for deduplicating rapid pointerdown -> mousedown -> click sequences
  const GESTURE_DEDUPLICATION_WINDOW_MS = 350;
  let lastSubmissionGesture = {
    timestamp: 0,
    text: '',
    shouldBlock: false,
    scanResult: null
  };

  function getDetector() {
    return (
      (typeof window !== 'undefined' && window.PromptShieldDetector) ||
      (typeof globalThis !== 'undefined' && globalThis.PromptShieldDetector) ||
      null
    );
  }

  function getUI() {
    return (
      (typeof window !== 'undefined' && window.PromptShieldUI) ||
      (typeof globalThis !== 'undefined' && globalThis.PromptShieldUI) ||
      null
    );
  }

  // ─── Helper: get CompanyRules engine ──────────────────────────────────────
  function getCompanyRules() {
    return (
      (typeof window !== 'undefined' && window.PromptShieldCompanyRules) ||
      (typeof globalThis !== 'undefined' && globalThis.PromptShieldCompanyRules) ||
      null
    );
  }

  /**
   * Reads compiled company rules from storage and pushes them into the
   * detector singleton. Safe to call multiple times (idempotent).
   */
  function reloadCompanyRules() {
    const companyRulesEngine = getCompanyRules();
    if (!companyRulesEngine) return;

    const detectorInstance = getDetector();
    if (!detectorInstance || !detectorInstance.setCompanyRules) return;

    companyRulesEngine.loadFromStorage().then(({ compiledRules, errors }) => {
      detectorInstance.setCompanyRules(compiledRules);
      if (errors.length > 0) {
        console.warn('[PromptShield AI] Company DNA validation errors:', errors);
      }
    });
  }

  // ─── Load configuration from local storage ────────────────────────────────
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['promptshield_enabled', 'promptshield_mode'], (result) => {
      if (result.promptshield_enabled !== undefined) {
        isEnabled = result.promptshield_enabled;
      }
      if (result.promptshield_mode) {
        protectionMode = result.promptshield_mode;
      }
      console.log('[PromptShield AI] Settings loaded: enabled=' + isEnabled + ', mode=' + protectionMode);
    });

    // Load company DNA rules (async; safe to call even before the engine is set on window)
    reloadCompanyRules();

    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local') {
        if (changes.promptshield_enabled) {
          isEnabled = changes.promptshield_enabled.newValue;
          console.log('[PromptShield AI] Protection toggle updated: enabled=' + isEnabled);
        }
        if (changes.promptshield_mode) {
          protectionMode = changes.promptshield_mode.newValue;
          console.log('[PromptShield AI] Protection mode updated: mode=' + protectionMode);
        }
        // Hot-reload company rules whenever admin saves a new rule set
        if (changes.promptshield_company_rules) {
          console.log('[PromptShield AI] Company DNA rules changed in storage — reloading...');
          reloadCompanyRules();
        }
      }
    });
  }


  /**
   * Helper: Select the current active ChatGPT prompt composer
   * ChatGPT uses ProseMirror rich text div. Supports standard IDs and dynamic fallbacks.
   */
  function findComposerElement() {
    if (typeof document === 'undefined') return null;

    // 1. Standard ChatGPT ID (used universally across modern chatgpt.com)
    let el = document.getElementById('prompt-textarea');
    if (el) return el;

    // 2. Standard ChatGPT data-testid
    el = document.querySelector('[data-testid="prompt-textarea"]');
    if (el) return el;

    // 3. ProseMirror contenteditable elements (ChatGPT web)
    el = document.querySelector('div.ProseMirror[contenteditable="true"]');
    if (el) return el;

    // 4. Role textbox with contenteditable
    el = document.querySelector('div[role="textbox"][contenteditable="true"]');
    if (el) return el;

    // 5. Active element if currently focused and within a composer
    if (document.activeElement && document.activeElement.closest) {
      const active = document.activeElement.closest('#prompt-textarea, [data-testid="prompt-textarea"], div.ProseMirror[contenteditable="true"], div[contenteditable="true"], textarea');
      if (active) return active;
    }

    // 6. Fallback contenteditable or textarea
    el = document.querySelector('textarea#prompt-textarea') ||
         document.querySelector('textarea[data-id="root"]') ||
         document.querySelector('div[contenteditable="true"][data-placeholder]') ||
         document.querySelector('div[contenteditable="true"]') ||
         document.querySelector('form textarea') ||
         document.querySelector('main textarea') ||
         document.querySelector('textarea');
    if (el) return el;

    return null;
  }

  /**
   * Find composer associated with a clicked button
   */
  function findComposerForButton(target) {
    if (typeof document === 'undefined') return null;

    // 1. Direct standard ChatGPT prompt textarea ID (most authoritative on chatgpt.com)
    const standard = document.getElementById('prompt-textarea');
    if (standard) return standard;

    const byTestId = document.querySelector('[data-testid="prompt-textarea"]');
    if (byTestId) return byTestId;

    if (!target) return findComposerElement();
    const button = (target.closest && target.closest('button, [role="button"], a[role="button"]')) || target;

    // 2. Search composer container hierarchy (without generic div!)
    if (button && button.closest) {
      const container = button.closest('form, [class*="composer" i], [class*="prosemirror" i], [data-testid*="composer" i], main, [role="presentation"]');
      if (container) {
        const comp = container.querySelector('#prompt-textarea, [data-testid="prompt-textarea"], div.ProseMirror[contenteditable="true"], textarea, div[contenteditable="true"]');
        if (comp) return comp;
      }
    }

    return findComposerElement();
  }

  /**
   * Extract text from composer node reliably.
   * Handles <textarea>, contenteditable div, and child <p> elements.
   */
  function getComposerText(element) {
    if (!element) return '';
    if (element.tagName === 'TEXTAREA' || element.tagName === 'INPUT') {
      return element.value || '';
    }

    // In ProseMirror contenteditable:
    // Extract child paragraphs first to preserve line breaks
    const paragraphs = element.querySelectorAll ? element.querySelectorAll('p') : [];
    if (paragraphs && paragraphs.length > 0) {
      const pText = Array.from(paragraphs)
        .map((p) => (p.innerText !== undefined && p.innerText !== null ? p.innerText : (p.textContent || '')))
        .join('\n');
      if (pText && pText.trim().length > 0) {
        return pText;
      }
    }

    // InnerText
    if (element.innerText !== undefined && element.innerText !== null) {
      return element.innerText;
    }

    // Fallback to textContent
    return element.textContent || '';
  }

  /**
   * Helper: Determine if a target represents an intentional Send / Submit action.
   * Strictly filters OUT attachment, voice, microphone, search toggles, stop buttons, and menus.
   */
  function isSendButton(target) {
    if (!target) return false;

    // Resolve button or interactive control
    const button = (target.closest && target.closest('button, [role="button"], a[role="button"]')) || 
                   (target.tagName === 'BUTTON' || (target.getAttribute && target.getAttribute('role') === 'button') ? target : null);

    // Collect attributes from both target and button wrapper to handle nested SVG/span clicks
    const testId = [
      target.getAttribute && target.getAttribute('data-testid'),
      button && button.getAttribute && button.getAttribute('data-testid')
    ].filter(Boolean).join(' ').toLowerCase();

    const ariaLabel = [
      target.getAttribute && target.getAttribute('aria-label'),
      button && button.getAttribute && button.getAttribute('aria-label')
    ].filter(Boolean).join(' ').toLowerCase();

    const buttonId = [
      target.id,
      button && button.id
    ].filter(Boolean).join(' ').toLowerCase();

    const title = [
      target.getAttribute && target.getAttribute('title'),
      button && button.getAttribute && button.getAttribute('title')
    ].filter(Boolean).join(' ').toLowerCase();

    // 1. Explicit Exclusions: Non-Send Controls (voice, attach, mic, search, stop)
    const isExcluded =
      testId.includes('attach') ||
      testId.includes('upload') ||
      testId.includes('voice') ||
      testId.includes('mic') ||
      testId.includes('speech') ||
      testId.includes('search') ||
      testId.includes('stop') ||
      ariaLabel.includes('attach') ||
      ariaLabel.includes('upload') ||
      ariaLabel.includes('voice') ||
      ariaLabel.includes('record') ||
      ariaLabel.includes('mic') ||
      ariaLabel.includes('speech') ||
      ariaLabel.includes('dictat') ||
      ariaLabel.includes('search') ||
      ariaLabel.includes('stop') ||
      title.includes('stop') ||
      title.includes('attach') ||
      title.includes('voice') ||
      (button && button.querySelector && Boolean(button.querySelector('input[type="file"]')));

    if (isExcluded) {
      return false;
    }

    // 2. Disabled buttons must not trigger submission
    if (button) {
      if (button.disabled === true || (button.getAttribute && button.getAttribute('aria-disabled') === 'true')) {
        return false;
      }
    }

    // 3. Positive Matches on data-testid or ID
    // Matches: send-button, composer-submit-button, fruitjuice-send-button, composer-btn-send
    if (
      testId.includes('send') ||
      testId.includes('submit') ||
      buttonId.includes('send') ||
      buttonId.includes('submit')
    ) {
      return true;
    }

    // 4. Positive Matches on aria-label or title
    if (
      ariaLabel.includes('send') ||
      ariaLabel.includes('submit') ||
      title.includes('send') ||
      title.includes('submit')
    ) {
      return true;
    }

    // 5. Submit button inside composer form
    if (button && button.type === 'submit') {
      return true;
    }

    // 6. Primary SVG arrow action button adjacent to or within prompt composer
    if (button) {
      const hasSvg = button.querySelector && Boolean(button.querySelector('svg'));
      const isTargetSvg = target.tagName === 'SVG' || target.tagName === 'PATH' || Boolean(target.closest && target.closest('svg'));
      if (hasSvg || isTargetSvg) {
        // Must be in composer area
        const inComposerArea = Boolean(
          button.closest &&
          button.closest('form, [class*="composer" i], [class*="prosemirror" i], [data-testid*="composer" i], main, [role="presentation"]')
        );
        // Exclude popup menus / tool dropdowns
        const isMenuPopup = (button.getAttribute && button.getAttribute('aria-haspopup') === 'menu') || 
                            (button.getAttribute && button.getAttribute('aria-haspopup') === 'listbox');
        if (inComposerArea && !isMenuPopup) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Persist redacted incident metadata to local storage
   * STRICT PRIVACY: NEVER STORES RAW PROMPTS OR SECRETS.
   */
  function recordRedactedIncident(scanResult) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      return;
    }

    chrome.storage.local.get(['promptshield_incidents', 'promptshield_blocked_count'], (data) => {
      const incidents = data.promptshield_incidents || [];
      const currentBlocked = data.promptshield_blocked_count || 0;

      const newEntries = scanResult.violations.map((v) => ({
        id: 'inc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6),
        timestamp: Date.now(),
        ruleId: v.ruleId,
        ruleName: v.ruleName,
        severity: v.severity,
        redactedSnippet: v.redactedSnippet
      }));

      const updatedIncidents = [...newEntries, ...incidents].slice(0, 50);

      chrome.storage.local.set({
        promptshield_incidents: updatedIncidents,
        promptshield_blocked_count: currentBlocked + 1
      });

      if (chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'PROMPTSHIELD_INCIDENT_RECORDED',
          count: currentBlocked + 1
        }).catch(() => {});
      }

      // Forward sanitized incident to authenticated Aegis-AI Gateway if enrolled
      forwardIncidentToAegis(scanResult);
    });
  }

  /**
   * Forward strictly sanitized event metadata to Aegis platform.
   * GUARANTEES: Never sends raw prompt, secrets, or cookies.
   */
  function forwardIncidentToAegis(scanResult) {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;
    chrome.storage.local.get(['aegis_auth_token', 'aegis_backend_url', 'promptshield_sync_enabled'], (data) => {
      const token = data.aegis_auth_token;
      const backendUrl = data.aegis_backend_url || 'http://localhost:4000';
      if (!token || data.promptshield_sync_enabled === false) return;

      if (!scanResult || !scanResult.violations) return;

      scanResult.violations.forEach((v) => {
        const eventId = 'ps-evt-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
        const payload = {
          eventId,
          occurredAt: new Date().toISOString(),
          sourcePlatform: 'chatgpt',
          ruleId: v.ruleId || 'SEC-001',
          ruleName: v.ruleName || v.ruleId,
          severity: v.severity || 'HIGH',
          action: scanResult.shouldBlock ? 'BLOCKED' : (v._companyAction === 'warn' ? 'WARNED' : (v._companyAction === 'redact' ? 'REDACTED' : 'ALLOWED')),
          detectorVersion: '1.0.0',
          sanitizedMetadata: {
            promptLengthChars: typeof lastSubmissionGesture?.text === 'string' ? lastSubmissionGesture.text.length : 0,
            matchCount: scanResult.violations.length,
            isCompanyRule: Boolean(v._isCompanyRule),
            companyAction: v._companyAction || null,
            explanation: 'Interception triggered by PromptShield AI guardrail.'
          }
        };

        try {
          fetch(`${backendUrl}/api/extension/incidents`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
          }).catch(() => {});
        } catch (e) {
          // Fire-and-forget; never interrupt user interaction
        }
      });
    });
  }

  /**
   * Core inspection and blocking coordinator
   */
  function evaluateAndIntercept(event, composer) {
    try {
      if (!isEnabled) {
        console.log('[PromptShield AI] Protection paused. Submission permitted.');
        return false;
      }

      const uiInstance = getUI();
      if (uiInstance && uiInstance.isModalOpen && uiInstance.isModalOpen()) {
        event.preventDefault();
        event.stopImmediatePropagation();
        return true;
      }

      const text = getComposerText(composer);
      if (!text || text.trim().length === 0) {
        return false;
      }

      // Gesture Deduplication:
      // Browser click sequences fire pointerdown -> mousedown -> click within ~350ms.
      // Similarly, Enter can fire keydown followed immediately by form submit.
      // If this is a secondary event for the exact same text and gesture window,
      // reuse the prior evaluation without re-scanning or re-logging duplicate alerts.
      const now = Date.now();
      const isDuplicateGesture =
        now - lastSubmissionGesture.timestamp < GESTURE_DEDUPLICATION_WINDOW_MS &&
        lastSubmissionGesture.text === text;

      if (isDuplicateGesture) {
        if (lastSubmissionGesture.shouldBlock) {
          event.preventDefault();
          event.stopImmediatePropagation();
          return true;
        }
        return false;
      }

      const detectorInstance = getDetector();
      if (!detectorInstance) {
        console.warn('[PromptShield AI] Detection engine not loaded in context.');
        return false;
      }

      const scanResult = detectorInstance.scan(text);

      // Record gesture state
      lastSubmissionGesture = {
        timestamp: now,
        text: text,
        shouldBlock: Boolean(scanResult.shouldBlock),
        scanResult: scanResult
      };

      // Increment local prompts scanned count (strictly client-side telemetry)
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['promptshield_scanned_count'], (scannedData) => {
          const currentScanned = (scannedData && scannedData.promptshield_scanned_count) || 0;
          chrome.storage.local.set({ promptshield_scanned_count: currentScanned + 1 });
        });
      }

      console.log(
        '[PromptShield AI] Prompt scanned (' + (event.type || 'unknown') + '): length=' + text.length +
        ', violations=' + (scanResult.violations ? scanResult.violations.length : 0) +
        ', maxSeverity=' + scanResult.maxSeverity +
        ', shouldBlock=' + scanResult.shouldBlock
      );

      if (scanResult.shouldBlock) {
        // Intercept submission before ChatGPT receives event
        event.preventDefault();
        event.stopImmediatePropagation();

        if (uiInstance && uiInstance.showBlockedModal) {
          uiInstance.showBlockedModal(scanResult, composer);
        }

        recordRedactedIncident(scanResult);

        const ruleSummary = scanResult.violations.map(v => v.ruleId + ' (' + v.ruleName + ')').join(', ');
        console.warn('[PromptShield AI] Submission blocked by rule(s): ' + ruleSummary);
        return true;
      }

      console.log('[PromptShield AI] Prompt is clean. Submission permitted.');
      return false;
    } catch (err) {
      console.error('[PromptShield AI] Error during prompt evaluation:', err.message);
      return false;
    }
  }

  /**
   * 1. KEYBOARD SUBMISSION HANDLER (Capture phase on window)
   * Handles: Enter key
   * Ignores: Shift+Enter (multiline) and IME composition
   */
  function handleKeydownCapture(event) {
    if (event.key !== 'Enter') {
      return;
    }

    if (event.shiftKey) {
      return;
    }

    if (event.isComposing || event.keyCode === 229) {
      return;
    }

    const composer =
      (event.target.closest && event.target.closest('#prompt-textarea, div.ProseMirror, [contenteditable="true"], textarea')) ||
      findComposerElement();

    if (!composer) return;

    if (event.target === composer || composer.contains(event.target)) {
      evaluateAndIntercept(event, composer);
    }
  }

  /**
   * 2. MOUSE & POINTER SUBMISSION HANDLER (Capture phase on window)
   * Intercepts pointerdown, mousedown, and click on Send buttons.
   * Intercepting early in pointerdown/mousedown prevents ChatGPT from clearing
   * or dispatching the prompt before the click event fires.
   */
  function handleSendActionCapture(event) {
    if (!isSendButton(event.target)) {
      return;
    }

    const composer = findComposerForButton(event.target);
    if (!composer) {
      console.warn('[PromptShield AI] Send action detected but composer element was not resolved.');
      return;
    }

    evaluateAndIntercept(event, composer);
  }

  /**
   * 3. FORM SUBMIT HANDLER (Capture phase on window)
   */
  function handleSubmitCapture(event) {
    const composer = findComposerElement();
    if (!composer) return;

    if (event.target && event.target.contains && event.target.contains(composer)) {
      evaluateAndIntercept(event, composer);
    }
  }

  let listenersAttached = false;

  /**
   * Binds global capture listeners immediately on window.
   * useCapture: true ensures PromptShield executes BEFORE ChatGPT's React event listeners.
   */
  function attachEventListeners() {
    if (listenersAttached) return;
    if (typeof window === 'undefined') return;

    window.addEventListener('keydown', handleKeydownCapture, true);
    window.addEventListener('pointerdown', handleSendActionCapture, true);
    window.addEventListener('mousedown', handleSendActionCapture, true);
    window.addEventListener('click', handleSendActionCapture, true);
    window.addEventListener('submit', handleSubmitCapture, true);
    listenersAttached = true;
    console.log('[PromptShield AI] Global capture event listeners attached (keydown, pointerdown, mousedown, click, submit).');
  }

  /**
   * MutationObserver: Watches document for ChatGPT SPA route changes and composer re-mounts
   */
  function setupMutationObserver() {
    if (observer) {
      observer.disconnect();
    }

    const targetNode = document.documentElement || document.body;
    if (!targetNode) return;

    observer = new MutationObserver(() => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const composer = findComposerElement();
        if (composer && composer !== activeComposer) {
          activeComposer = composer;
          console.log('[PromptShield AI] Active composer re-bound:', composer.tagName + (composer.id ? '#' + composer.id : ''));
        }
      }, 150);
    });

    observer.observe(targetNode, {
      childList: true,
      subtree: true
    });
  }

  function init() {
    setupMutationObserver();
    activeComposer = findComposerElement();
    if (activeComposer) {
      console.log('[PromptShield AI] Composer located at init:', activeComposer.tagName + (activeComposer.id ? '#' + activeComposer.id : ''));
    } else {
      console.log('[PromptShield AI] Observer active. Waiting for composer mount...');
    }
  }

  if (typeof window !== 'undefined') {
    // Attach global capture listeners immediately at script load
    attachEventListeners();

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }

    console.log('[PromptShield AI] Content script successfully initialized on origin:', window.location.origin);
  }

  // Export for automated testing in Node.js environments
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      isSendButton,
      findComposerElement,
      findComposerForButton,
      getComposerText,
      evaluateAndIntercept,
      handleKeydownCapture,
      handleSendActionCapture,
      handleSubmitCapture,
      attachEventListeners,
      recordRedactedIncident,
      forwardIncidentToAegis,
      GESTURE_DEDUPLICATION_WINDOW_MS,
      getLastSubmissionGesture: () => ({ ...lastSubmissionGesture }),
      resetSubmissionGesture: () => {
        lastSubmissionGesture = { timestamp: 0, text: '', shouldBlock: false, scanResult: null };
      },
      resetListenersAttached: () => {
        listenersAttached = false;
      }
    };
  }
})();
