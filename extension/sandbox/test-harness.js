/**
 * PromptShield AI - Test Harness Controller
 * 
 * Drives the simulated ChatGPT interface, binds vector test buttons,
 * and logs simulated submission and control events.
 * 
 * Manifest V3 CSP Compliant: Loaded via external script tag.
 */

(function () {
  'use strict';

  function getComposer() {
    return document.getElementById('prompt-textarea');
  }

  function getSendBtn() {
    return document.getElementById('sim-send-btn');
  }

  function getAttachBtn() {
    return document.getElementById('sim-attach-btn');
  }

  function getVoiceBtn() {
    return document.getElementById('sim-voice-btn');
  }

  function getConsoleBox() {
    return document.getElementById('event-console');
  }

  /**
   * Log formatted message into event console
   */
  function logEvent(type, message, cssClass = '') {
    const consoleBox = getConsoleBox();
    if (!consoleBox) return;

    const entry = document.createElement('div');
    entry.className = `log-entry ${cssClass}`;
    const time = new Date().toLocaleTimeString();
    entry.textContent = `[${time}] [${type}] ${message}`;
    consoleBox.appendChild(entry);
    consoleBox.scrollTop = consoleBox.scrollHeight;
  }

  /**
   * Set text into contenteditable composer with caret positioning and visual feedback
   */
  function setComposerText(text, vectorTitle = '') {
    const comp = getComposer();
    if (!comp) {
      console.error('[PromptShield Sandbox] Composer element #prompt-textarea not found');
      return;
    }

    comp.innerText = text;

    // Dispatch input and change events so external observers register the update
    comp.dispatchEvent(new Event('input', { bubbles: true }));
    comp.dispatchEvent(new Event('change', { bubbles: true }));

    // Focus composer
    comp.focus();

    // Position cursor at end of text
    try {
      const range = document.createRange();
      const sel = window.getSelection();
      range.selectNodeContents(comp);
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);
    } catch (err) {
      // Ignore range errors
    }

    // Flash composer border briefly for immediate visual confirmation
    comp.style.outline = '2px solid #3b82f6';
    setTimeout(() => {
      comp.style.outline = '';
    }, 250);

    const titleStr = vectorTitle ? ` "${vectorTitle}"` : '';
    logEvent('VECTOR_LOADED', `Loaded vector${titleStr} (${text.length} chars) into composer. Press Enter or click Send to test.`, 'control');
  }

  /**
   * Native ChatGPT submission receiver.
   * If PromptShield intercepts the submission in capture phase,
   * this handler will NEVER be reached!
   */
  function handleNativeSubmit() {
    const comp = getComposer();
    if (!comp) return;

    const text = comp.innerText.trim();
    if (!text) {
      logEvent('EMPTY', 'Prompt is empty - no submission dispatched.');
      return;
    }

    const preview = text.length > 50 ? text.substring(0, 50) + '...' : text;
    logEvent('SUBMITTED', `Prompt sent to AI model (${text.length} chars): "${preview}"`, 'success');

    // Clear composer on successful submission
    comp.innerText = '';
    comp.dispatchEvent(new Event('input', { bubbles: true }));
  }

  /**
   * Bind simulated ChatGPT native bubbling event listeners to composer & buttons
   */
  function bindChatGPTListeners() {
    const comp = getComposer();
    const sBtn = getSendBtn();
    const aBtn = getAttachBtn();
    const vBtn = getVoiceBtn();

    if (comp) {
      // Native keydown handler (runs bubbling phase after capture phase)
      comp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
          e.preventDefault();
          handleNativeSubmit();
        }
      });

      // Paste event listener
      comp.addEventListener('paste', (e) => {
        const clipboardData = (e.clipboardData || window.clipboardData);
        const pastedText = clipboardData ? clipboardData.getData('text') : '';
        logEvent('PASTE', `Pasted ${pastedText.length} characters into composer.`, 'paste');
      });
    }

    if (sBtn) {
      sBtn.addEventListener('click', (e) => {
        e.preventDefault();
        handleNativeSubmit();
      });
    }

    if (aBtn) {
      aBtn.addEventListener('click', () => {
        logEvent('ATTACHMENT', 'File upload dialog clicked (Non-submission control verified: NOT intercepted).', 'control');
      });
    }

    if (vBtn) {
      vBtn.addEventListener('click', () => {
        logEvent('VOICE', 'Voice recording toggled (Non-submission control verified: NOT intercepted).', 'control');
      });
    }
  }

  /**
   * Attach click handlers to all test vector cards
   */
  function bindVectorCards() {
    const vectorConfigs = [
      {
        id: 'vec-safe',
        title: 'Benign Prompt',
        prompt: 'Explain the difference between TCP and UDP in computer networks.'
      },
      {
        id: 'vec-openai',
        title: 'Synthetic OpenAI Key',
        prompt: 'Here is my OpenAI API key for debugging: sk-proj-TEST1234567890abcdef1234567890abcdef12345678'
      },
      {
        id: 'vec-aws',
        title: 'Synthetic AWS Access Key',
        prompt: 'Connect with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and secret key.'
      },
      {
        id: 'vec-privkey',
        title: 'Synthetic Private Key Block',
        prompt: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y8KxN...[SYNTHETIC TEST RSA KEY BLOCK]...
-----END RSA PRIVATE KEY-----`
      },
      {
        id: 'vec-db',
        title: 'Database URI with Password',
        prompt: 'DATABASE_URL="postgres://admin:SuperSecretPass123@prod-db.internal:5432/main"'
      },
      {
        id: 'vec-pass',
        title: 'Plaintext Password Assignment',
        prompt: 'db_password = "ProductionPassword99!"'
      },
      {
        id: 'vec-fp-env',
        title: 'Environment Variable Lookup (Safe)',
        prompt: `const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) throw new Error("Missing API Key");`
      },
      {
        id: 'vec-fp-placeholder',
        title: 'Documentation Placeholder (Safe)',
        prompt: 'openai_api_key = "<your-api-key-here>"'
      }
    ];

    vectorConfigs.forEach(({ id, title, prompt }) => {
      const btn = document.getElementById(id);
      if (btn) {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          setComposerText(prompt, title);
        });
      } else {
        console.warn(`[PromptShield Sandbox] Button with id "${id}" not found.`);
      }
    });

    // Company Data DNA vector cards
    const dnaVectors = [
      {
        id: 'vec-dna-falcon',
        title: 'Project Falcon Code (DNA Block)',
        prompt: 'Reviewing Q3 roadmap. Codeword: PROJECT-FALCON-7Q must not leave this building.'
      },
      {
        id: 'vec-dna-client',
        title: 'Client Demo Code (DNA Block)',
        prompt: 'Demo prep notes: CLIENT-DEMO-4821 slides and pricing deck attached.'
      },
      {
        id: 'vec-dna-release',
        title: 'Confidential Release Marker (DNA Warn)',
        prompt: 'INTERNAL-RELEASE-CONFIDENTIAL: Do not share this release note externally.'
      },
      {
        id: 'vec-dna-disabled',
        title: 'Disabled Rule Prompt (Should NOT trigger)',
        prompt: 'Testing disabled rule marker: DISABLED-RULE-XYZ99 should pass through freely.'
      }
    ];

    dnaVectors.forEach(({ id, title, prompt }) => {
      const btn = document.getElementById(id);
      if (btn) {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          setComposerText(prompt, title);
        });
      } else {
        console.warn(`[PromptShield Sandbox] DNA button with id "${id}" not found.`);
      }
    });

    // Dynamic SPA Navigation Simulation
    const remountBtn = document.getElementById('btn-remount-dom');
    const composerHost = document.getElementById('composer-host');
    if (remountBtn && composerHost) {
      const originalFormHtml = composerHost.innerHTML;

      remountBtn.addEventListener('click', (e) => {
        e.preventDefault();
        composerHost.innerHTML = '<div style="padding: 24px; color: #fbbf24; text-align: center; font-weight: 500;">Simulating ChatGPT SPA chat navigation / composer unmount...</div>';
        logEvent('DOM_EVENT', 'Composer unmounted from DOM (Simulating route change).', 'control');

        setTimeout(() => {
          composerHost.innerHTML = originalFormHtml;
          bindChatGPTListeners();
          logEvent('DOM_EVENT', 'New composer remounted into DOM. PromptShield MutationObserver re-binds automatically.', 'control');
        }, 350);
      });
    }

    // Clear Console Button
    const clearBtn = document.getElementById('clear-console-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const box = getConsoleBox();
        if (box) box.innerHTML = '';
      });
    }
  }

  /**
   * Seeds synthetic Company Data DNA rules into chrome.storage.local for sandbox testing.
   * These rules match the synthetic test vectors used in the automated test suite.
   * Only runs in extension contexts where chrome.storage is available.
   */
  function seedSandboxCompanyRules() {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
      logEvent('DNA', 'chrome.storage not available (non-extension origin). DNA rules require running under chrome-extension:// URL.', 'control');
      return;
    }

    const sandboxRules = [
      {
        id: 'CDR-001',
        name: 'Project Falcon Codename',
        description: 'Detects internal codename PROJECT-FALCON-7Q for Q3 initiative.',
        patternType: 'exact',
        pattern: 'PROJECT-FALCON-7Q',
        severity: 'CRITICAL',
        action: 'block',
        enabled: true
      },
      {
        id: 'CDR-002',
        name: 'Client Demo Reference Code',
        description: 'Detects client demo reference CLIENT-DEMO-4821.',
        patternType: 'exact',
        pattern: 'CLIENT-DEMO-4821',
        severity: 'HIGH',
        action: 'block',
        enabled: true
      },
      {
        id: 'CDR-003',
        name: 'Internal Release Confidential Marker',
        description: 'Detects INTERNAL-RELEASE-CONFIDENTIAL document header.',
        patternType: 'exact',
        pattern: 'INTERNAL-RELEASE-CONFIDENTIAL',
        severity: 'HIGH',
        action: 'warn',
        enabled: true
      },
      {
        id: 'CDR-004',
        name: 'Disabled Rule Marker',
        description: 'This rule is intentionally disabled and must never trigger.',
        patternType: 'exact',
        pattern: 'DISABLED-RULE-XYZ99',
        severity: 'MEDIUM',
        action: 'block',
        enabled: false
      }
    ];

    const engine = window.PromptShieldCompanyRules;
    if (!engine) {
      logEvent('DNA', 'PromptShieldCompanyRules engine not found on window.', 'control');
      return;
    }

    engine.saveToStorage(sandboxRules).then(({ success, errors }) => {
      if (success) {
        logEvent('DNA', 'Sandbox Company DNA rules seeded into chrome.storage (' + sandboxRules.length + ' rules). Detector will hot-reload them.', 'control');
      } else {
        logEvent('DNA', 'Failed to seed Company DNA rules: ' + errors.join('; '), 'control');
      }
    });
  }

  /**
   * Initialize test harness
   */
  function initHarness() {
    bindChatGPTListeners();
    bindVectorCards();

    // Seed Company Data DNA rules so sandbox DNA vectors work immediately
    setTimeout(() => {
      seedSandboxCompanyRules();
    }, 200);

    // Check PromptShield presence
    setTimeout(() => {
      if (window.PromptShieldDetector) {
        const rules = window.PromptShieldDetector.getCompanyRules
          ? window.PromptShieldDetector.getCompanyRules()
          : [];
        logEvent('SYSTEM', 'PromptShield Guardrail active. Built-in rules + ' + rules.length + ' Company DNA rule(s) loaded.', 'control');
      } else {
        logEvent('SYSTEM', 'PromptShield scripts loaded. Test cards ready.', 'control');
      }
    }, 600);

    console.log('[PromptShield Sandbox] Test harness initialized successfully.');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHarness);
  } else {
    initHarness();
  }
})();

