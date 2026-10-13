/**
 * PromptShield AI - Test Harness Controller (Mirrored in tests/)
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

  function setComposerText(text, vectorTitle = '') {
    const comp = getComposer();
    if (!comp) {
      console.error('[PromptShield Sandbox] Composer element #prompt-textarea not found');
      return;
    }

    comp.innerText = text;
    comp.dispatchEvent(new Event('input', { bubbles: true }));
    comp.dispatchEvent(new Event('change', { bubbles: true }));
    comp.focus();

    try {
      const range = document.createRange();
      const sel = window.getSelection();
      range.selectNodeContents(comp);
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);
    } catch (err) {}

    comp.style.outline = '2px solid #3b82f6';
    setTimeout(() => {
      comp.style.outline = '';
    }, 250);

    const titleStr = vectorTitle ? ` "${vectorTitle}"` : '';
    logEvent('VECTOR_LOADED', `Loaded vector${titleStr} (${text.length} chars) into composer. Press Enter or click Send to test.`, 'control');
  }

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

    comp.innerText = '';
    comp.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function bindChatGPTListeners() {
    const comp = getComposer();
    const sBtn = getSendBtn();
    const aBtn = getAttachBtn();
    const vBtn = getVoiceBtn();

    if (comp) {
      comp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
          e.preventDefault();
          handleNativeSubmit();
        }
      });

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
      }
    });

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

    const clearBtn = document.getElementById('clear-console-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const box = getConsoleBox();
        if (box) box.innerHTML = '';
      });
    }
  }

  function initHarness() {
    bindChatGPTListeners();
    bindVectorCards();

    setTimeout(() => {
      if (window.PromptShieldDetector) {
        logEvent('SYSTEM', 'PromptShield Guardrail active. Real-time prompt inspection is running.', 'control');
      } else {
        logEvent('SYSTEM', 'PromptShield script loaded. Test cards ready.', 'control');
      }
    }, 100);

    console.log('[PromptShield Sandbox] Test harness initialized successfully.');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHarness);
  } else {
    initHarness();
  }
})();
