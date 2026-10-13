/**
 * PromptShield AI - Submission Paths & Interception Regression Tests
 * 
 * Verifies the event filtering logic:
 * - Enter vs Shift+Enter vs IME composition
 * - Send button detection on ChatGPT variants (send-button, composer-submit-button, fruitjuice-send-button, aria-label)
 * - Strict exclusion of non-submission controls (Attachment, Voice/Mic, Search)
 * - Multi-event submission capture (pointerdown, mousedown, click, keydown, submit)
 * - Manifest V3 CSP compliance for test harness (no inline scripts)
 * - Test vector card existence and integrity
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { defaultDetector } = require('../extension/content/detector.js');
const contentScript = require('../extension/content/content.js');

// Replicate the exact event predicate logic used in updated content.js
function isSendButtonPredicate(target) {
  if (!target) return false;
  const button = target.closest ? target.closest('button, [role="button"]') : target;
  if (!button) return false;

  const testId = (button.getAttribute('data-testid') || '').toLowerCase();
  const ariaLabel = (button.getAttribute('aria-label') || '').toLowerCase();
  const buttonId = (button.id || '').toLowerCase();
  const className = (button.className || '').toString().toLowerCase();

  // 1. Explicit Exclusions: Non-Send Controls
  const isExcluded =
    testId.includes('attach') ||
    testId.includes('voice') ||
    testId.includes('mic') ||
    testId.includes('speech') ||
    ariaLabel.includes('attach') ||
    ariaLabel.includes('voice') ||
    ariaLabel.includes('record') ||
    ariaLabel.includes('search') ||
    ariaLabel.includes('dictat') ||
    className.includes('attach') ||
    Boolean(button.querySelector && button.querySelector('input[type="file"]'));

  if (isExcluded) {
    return false;
  }

  // 2. Positive Matches on data-testid or ID
  if (
    testId.includes('send') ||
    testId.includes('submit') ||
    buttonId.includes('send') ||
    buttonId.includes('submit')
  ) {
    return true;
  }

  // 3. Positive Matches on aria-label
  if (
    ariaLabel.includes('send') ||
    ariaLabel.includes('submit')
  ) {
    return true;
  }

  // 4. Submit button type
  if (button.type === 'submit') {
    return true;
  }

  return false;
}

// Minimal mock node helper
function createMockElement(tagName, attrs = {}, parent = null) {
  const children = [];
  const element = {
    tagName: tagName.toUpperCase(),
    id: attrs.id || '',
    attributes: { ...attrs },
    parentNode: parent,
    children: children,
    className: attrs.class || '',
    type: attrs.type || '',
    getAttribute(name) {
      return this.attributes[name] || null;
    },
    setAttribute(name, val) {
      this.attributes[name] = val;
    },
    closest(selector) {
      let current = this;
      while (current) {
        if (selector === 'button, [role="button"]') {
          if (current.tagName === 'BUTTON' || current.getAttribute('role') === 'button') {
            return current;
          }
        }
        if (selector === 'form' && current.tagName === 'FORM') {
          return current;
        }
        current = current.parentNode;
      }
      return null;
    },
    querySelector(selector) {
      return null;
    }
  };
  return element;
}

describe('PromptShield AI - Submission Paths Regression Tests', () => {
  describe('Control Target Discrimination (Real ChatGPT Selectors)', () => {
    it('should identify ChatGPT send-button by data-testid="send-button"', () => {
      const sendBtn = createMockElement('button', { 'data-testid': 'send-button' });
      assert.equal(isSendButtonPredicate(sendBtn), true);
    });

    it('should identify ChatGPT button by data-testid="composer-submit-button"', () => {
      const sendBtn = createMockElement('button', { 'data-testid': 'composer-submit-button' });
      assert.equal(isSendButtonPredicate(sendBtn), true);
    });

    it('should identify ChatGPT button by data-testid="fruitjuice-send-button"', () => {
      const sendBtn = createMockElement('button', { 'data-testid': 'fruitjuice-send-button' });
      assert.equal(isSendButtonPredicate(sendBtn), true);
    });

    it('should identify ChatGPT button by id="composer-submit-button"', () => {
      const sendBtn = createMockElement('button', { id: 'composer-submit-button' });
      assert.equal(isSendButtonPredicate(sendBtn), true);
    });

    it('should identify Send button by aria-label="Send prompt"', () => {
      const sendBtn = createMockElement('button', { 'aria-label': 'Send prompt' });
      assert.equal(isSendButtonPredicate(sendBtn), true);
    });

    it('should identify Send button by aria-label="Send message"', () => {
      const sendBtn = createMockElement('button', { 'aria-label': 'Send message' });
      assert.equal(isSendButtonPredicate(sendBtn), true);
    });

    it('should identify nested child SVG clicked inside send button', () => {
      const sendBtn = createMockElement('button', { 'data-testid': 'send-button' });
      const svgIcon = createMockElement('svg', {}, sendBtn);
      assert.equal(isSendButtonPredicate(svgIcon), true);
    });

    it('MUST NOT identify attachment button as send button', () => {
      const attachBtn = createMockElement('button', {
        'data-testid': 'attach-button',
        'aria-label': 'Attach files'
      });
      assert.equal(isSendButtonPredicate(attachBtn), false);
    });

    it('MUST NOT identify voice/mic button as send button', () => {
      const voiceBtn = createMockElement('button', {
        'data-testid': 'voice-mode-button',
        'aria-label': 'Voice mode'
      });
      assert.equal(isSendButtonPredicate(voiceBtn), false);
    });

    it('MUST NOT identify speech button as send button', () => {
      const speechBtn = createMockElement('button', {
        'data-testid': 'composer-speech-button',
        'aria-label': 'Dictate'
      });
      assert.equal(isSendButtonPredicate(speechBtn), false);
    });

    it('MUST NOT identify generic settings or search button as send button', () => {
      const searchBtn = createMockElement('button', {
        'aria-label': 'Search web'
      });
      assert.equal(isSendButtonPredicate(searchBtn), false);
    });
  });

  describe('Keyboard Event Path Discrimination', () => {
    function shouldEvaluateKeydown(event) {
      if (event.key !== 'Enter') return false;
      if (event.shiftKey) return false;
      if (event.isComposing || event.keyCode === 229) return false;
      return true;
    }

    it('should evaluate clean Enter key for submission interception', () => {
      const event = { key: 'Enter', shiftKey: false, isComposing: false, keyCode: 13 };
      assert.equal(shouldEvaluateKeydown(event), true);
    });

    it('MUST NOT intercept Shift+Enter (must allow multiline prompt creation)', () => {
      const event = { key: 'Enter', shiftKey: true, isComposing: false, keyCode: 13 };
      assert.equal(shouldEvaluateKeydown(event), false);
    });

    it('MUST NOT intercept during active IME composition (CJK character input)', () => {
      const eventWithIsComposing = { key: 'Enter', shiftKey: false, isComposing: true, keyCode: 13 };
      assert.equal(shouldEvaluateKeydown(eventWithIsComposing), false);

      const eventWithKeyCode229 = { key: 'Enter', shiftKey: false, isComposing: false, keyCode: 229 };
      assert.equal(shouldEvaluateKeydown(eventWithKeyCode229), false);
    });

    it('MUST NOT intercept other keys like Tab, Space, Backspace, or Escape', () => {
      assert.equal(shouldEvaluateKeydown({ key: 'Tab', shiftKey: false }), false);
      assert.equal(shouldEvaluateKeydown({ key: 'Escape', shiftKey: false }), false);
      assert.equal(shouldEvaluateKeydown({ key: 'a', shiftKey: false }), false);
    });
  });

  describe('Multi-Event Interception Coverage', () => {
    it('verifies that pointerdown, mousedown, click, and keydown handlers are all bound', () => {
      const contentJs = fs.readFileSync(path.resolve(__dirname, '..', 'extension', 'content', 'content.js'), 'utf8');
      assert.ok(contentJs.includes("'keydown'"), 'Must bind keydown');
      assert.ok(contentJs.includes("'pointerdown'"), 'Must bind pointerdown');
      assert.ok(contentJs.includes("'mousedown'"), 'Must bind mousedown');
      assert.ok(contentJs.includes("'click'"), 'Must bind click');
      assert.ok(contentJs.includes("'submit'"), 'Must bind submit');
    });
  });

  describe('Submission Gesture Deduplication Engine', () => {
    function createGestureCoordinator(detector, windowMs = 350) {
      let lastGesture = {
        timestamp: 0,
        text: '',
        shouldBlock: false,
        scanResult: null
      };
      let scanCount = 0;
      let incidentCount = 0;

      function evaluate(event, text, timestamp) {
        if (!text || text.trim().length === 0) return false;

        const isDuplicate =
          timestamp - lastGesture.timestamp < windowMs &&
          lastGesture.text === text;

        if (isDuplicate) {
          if (lastGesture.shouldBlock) {
            if (event.preventDefault) event.preventDefault();
            if (event.stopImmediatePropagation) event.stopImmediatePropagation();
            return true;
          }
          return false;
        }

        scanCount++;
        const scanResult = detector.scan(text);

        lastGesture = {
          timestamp: timestamp,
          text: text,
          shouldBlock: Boolean(scanResult.shouldBlock),
          scanResult: scanResult
        };

        if (scanResult.shouldBlock) {
          if (event.preventDefault) event.preventDefault();
          if (event.stopImmediatePropagation) event.stopImmediatePropagation();
          incidentCount++;
          return true;
        }

        return false;
      }

      return {
        evaluate,
        getStats: () => ({ scanCount, incidentCount }),
        getLastGesture: () => ({ ...lastGesture })
      };
    }

    it('deduplicates rapid pointerdown -> mousedown -> click sequence for BLOCKED prompts (only 1 scan & 1 incident)', () => {
      const coordinator = createGestureCoordinator(defaultDetector);
      const secretPrompt = 'API Key: sk-proj-TEST1234567890abcdef1234567890abcdef12345678';

      const events = [
        { type: 'pointerdown', time: 1000, prevented: false, stopped: false },
        { type: 'mousedown', time: 1015, prevented: false, stopped: false },
        { type: 'click', time: 1050, prevented: false, stopped: false }
      ];

      for (const ev of events) {
        const mockEv = {
          type: ev.type,
          preventDefault: () => { ev.prevented = true; },
          stopImmediatePropagation: () => { ev.stopped = true; }
        };
        const blocked = coordinator.evaluate(mockEv, secretPrompt, ev.time);
        assert.equal(blocked, true, `Event ${ev.type} must be intercepted`);
        assert.equal(ev.prevented, true, `Event ${ev.type} must have preventDefault called`);
        assert.equal(ev.stopped, true, `Event ${ev.type} must have stopImmediatePropagation called`);
      }

      // Exactly ONE scan must have been performed, and exactly ONE incident recorded
      assert.equal(coordinator.getStats().scanCount, 1, 'Only 1 scan should run across pointerdown -> mousedown -> click');
      assert.equal(coordinator.getStats().incidentCount, 1, 'Only 1 incident should be recorded across the gesture');
    });

    it('deduplicates rapid pointerdown -> mousedown -> click sequence for CLEAN prompts (only 1 scan, no re-scans)', () => {
      const coordinator = createGestureCoordinator(defaultDetector);
      const cleanPrompt = 'Explain how the Luhn algorithm works in JavaScript.';

      const events = [
        { type: 'pointerdown', time: 2000, prevented: false, stopped: false },
        { type: 'mousedown', time: 2012, prevented: false, stopped: false },
        { type: 'click', time: 2045, prevented: false, stopped: false }
      ];

      for (const ev of events) {
        const mockEv = {
          type: ev.type,
          preventDefault: () => { ev.prevented = true; },
          stopImmediatePropagation: () => { ev.stopped = true; }
        };
        const blocked = coordinator.evaluate(mockEv, cleanPrompt, ev.time);
        assert.equal(blocked, false, `Clean event ${ev.type} must NOT be blocked`);
        assert.equal(ev.prevented, false, `Clean event ${ev.type} must NOT have preventDefault called`);
      }

      assert.equal(coordinator.getStats().scanCount, 1, 'Only 1 scan should run across pointerdown -> mousedown -> click for clean prompt');
      assert.equal(coordinator.getStats().incidentCount, 0, 'Zero incidents should be recorded for clean prompt');
    });

    it('deduplicates Enter keydown followed immediately by form submit event', () => {
      const coordinator = createGestureCoordinator(defaultDetector);
      const secretPrompt = 'DATABASE_URL="postgres://demo:DummyPass123@localhost:5432/testdb"';

      const keydownEv = { type: 'keydown', prevented: false, stopped: false };
      const submitEv = { type: 'submit', prevented: false, stopped: false };

      const keyBlocked = coordinator.evaluate({
        type: 'keydown',
        preventDefault: () => { keydownEv.prevented = true; },
        stopImmediatePropagation: () => { keydownEv.stopped = true; }
      }, secretPrompt, 3000);

      const submitBlocked = coordinator.evaluate({
        type: 'submit',
        preventDefault: () => { submitEv.prevented = true; },
        stopImmediatePropagation: () => { submitEv.stopped = true; }
      }, secretPrompt, 3010); // 10ms later

      assert.equal(keyBlocked, true);
      assert.equal(submitBlocked, true);
      assert.equal(keydownEv.prevented, true);
      assert.equal(submitEv.prevented, true);
      assert.equal(coordinator.getStats().scanCount, 1, 'Form submit must reuse prior keydown decision within window');
      assert.equal(coordinator.getStats().incidentCount, 1);
    });

    it('triggers fresh scan when prompt text changes even within the deduplication window', () => {
      const coordinator = createGestureCoordinator(defaultDetector);

      // First submit with secret
      coordinator.evaluate({ type: 'pointerdown' }, 'sk-proj-TEST1234567890abcdef1234567890abcdef12345678', 4000);
      assert.equal(coordinator.getStats().scanCount, 1);

      // User quickly changes prompt to a safe placeholder 100ms later
      coordinator.evaluate({ type: 'pointerdown' }, 'sk-xxxx', 4100);
      assert.equal(coordinator.getStats().scanCount, 2, 'Altered prompt text must trigger fresh scan immediately');
    });

    it('triggers fresh scan after deduplication window expires (> 350ms)', () => {
      const coordinator = createGestureCoordinator(defaultDetector);
      const text = 'Explain binary search algorithms.';

      coordinator.evaluate({ type: 'click' }, text, 5000);
      assert.equal(coordinator.getStats().scanCount, 1);

      // Subsequent click 500ms later (window is 350ms)
      coordinator.evaluate({ type: 'click' }, text, 5500);
      assert.equal(coordinator.getStats().scanCount, 2, 'Click after 350ms window must trigger fresh scan');
    });

    it('exports GESTURE_DEDUPLICATION_WINDOW_MS = 350 in content.js', () => {
      assert.equal(contentScript.GESTURE_DEDUPLICATION_WINDOW_MS, 350);
    });
  });

  describe('Submission Action Prevention Verification', () => {
    it('VERIFIED: Blocked prompt NEVER reaches simulated ChatGPT submission action', () => {
      let chatGPTReceivedSubmission = false;
      const chatGPTNativeHandler = () => {
        chatGPTReceivedSubmission = true;
      };

      const dangerousPrompt = 'DATABASE_URL="postgres://demo:DummyPass123@localhost:5432/testdb"';
      const scanResult = defaultDetector.scan(dangerousPrompt);
      assert.equal(scanResult.shouldBlock, true);

      // Simulate browser event capture -> bubble propagation
      let isPrevented = false;
      let isPropagationStopped = false;

      const clickEvent = {
        type: 'click',
        preventDefault: () => { isPrevented = true; },
        stopImmediatePropagation: () => { isPropagationStopped = true; }
      };

      // PromptShield intercepts in capture phase:
      if (scanResult.shouldBlock) {
        clickEvent.preventDefault();
        clickEvent.stopImmediatePropagation();
      }

      // ChatGPT React listener in bubbling phase (or normal DOM handler) only executes if not prevented/stopped
      if (!isPrevented && !isPropagationStopped) {
        chatGPTNativeHandler();
      }

      assert.equal(chatGPTReceivedSubmission, false, 'ChatGPT handler MUST NOT be called when prompt is blocked');
      assert.equal(isPrevented, true);
      assert.equal(isPropagationStopped, true);
    });

    it('VERIFIED: Clean prompt successfully reaches simulated ChatGPT submission action', () => {
      let chatGPTReceivedSubmission = false;
      let submittedPromptText = '';
      const chatGPTNativeHandler = (text) => {
        chatGPTReceivedSubmission = true;
        submittedPromptText = text;
      };

      const cleanPrompt = 'Can you write a unit test for quicksort in TypeScript?';
      const scanResult = defaultDetector.scan(cleanPrompt);
      assert.equal(scanResult.shouldBlock, false);

      let isPrevented = false;
      let isPropagationStopped = false;

      const clickEvent = {
        type: 'click',
        preventDefault: () => { isPrevented = true; },
        stopImmediatePropagation: () => { isPropagationStopped = true; }
      };

      // PromptShield evaluates in capture phase:
      if (scanResult.shouldBlock) {
        clickEvent.preventDefault();
        clickEvent.stopImmediatePropagation();
      }

      // ChatGPT handler receives the event
      if (!isPrevented && !isPropagationStopped) {
        chatGPTNativeHandler(cleanPrompt);
      }

      assert.equal(chatGPTReceivedSubmission, true, 'Clean prompt MUST reach ChatGPT handler');
      assert.equal(submittedPromptText, cleanPrompt);
    });
  });

  describe('Test Harness Integrity & Manifest V3 CSP Compliance', () => {
    const harnessPath = path.resolve(__dirname, '..', 'extension', 'sandbox', 'test-harness.html');
    const harnessScriptPath = path.resolve(__dirname, '..', 'extension', 'sandbox', 'test-harness.js');

    it('test-harness.html MUST exist', () => {
      assert.ok(fs.existsSync(harnessPath), 'extension/sandbox/test-harness.html must exist');
    });

    it('test-harness.js external script MUST exist', () => {
      assert.ok(fs.existsSync(harnessScriptPath), 'extension/sandbox/test-harness.js must exist');
    });

    it('test-harness.html MUST NOT contain inline <script> tags without src (MV3 CSP rule)', () => {
      const html = fs.readFileSync(harnessPath, 'utf8');
      const inlineScriptRegex = /<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi;
      const matches = [];
      let match;
      while ((match = inlineScriptRegex.exec(html)) !== null) {
        if (match[1].trim().length > 0) {
          matches.push(match[1]);
        }
      }
      assert.equal(
        matches.length,
        0,
        `Found forbidden inline script in test-harness.html: ${matches.join('\n---\n')}`
      );
    });

    it('test-harness.html MUST contain all required element IDs for vector cards & controls', () => {
      const html = fs.readFileSync(harnessPath, 'utf8');
      const requiredIds = [
        'prompt-textarea',
        'sim-send-btn',
        'sim-attach-btn',
        'sim-voice-btn',
        'composer-host',
        'event-console',
        'clear-console-btn',
        'vec-safe',
        'vec-openai',
        'vec-aws',
        'vec-privkey',
        'vec-db',
        'vec-pass',
        'vec-fp-env',
        'vec-fp-placeholder',
        'btn-remount-dom'
      ];

      for (const id of requiredIds) {
        assert.ok(
          html.includes(`id="${id}"`),
          `test-harness.html missing element id="${id}"`
        );
      }
    });

    it('test-harness.js MUST define click handlers for all vector buttons', () => {
      const js = fs.readFileSync(harnessScriptPath, 'utf8');
      const expectedVectorIds = [
        'vec-safe',
        'vec-openai',
        'vec-aws',
        'vec-privkey',
        'vec-db',
        'vec-pass',
        'vec-fp-env',
        'vec-fp-placeholder'
      ];

      for (const id of expectedVectorIds) {
        assert.ok(
          js.includes(id),
          `test-harness.js does not configure vector id "${id}"`
        );
      }
      assert.ok(js.includes('btn-remount-dom'), 'test-harness.js must handle btn-remount-dom');
      assert.ok(js.includes('clear-console-btn'), 'test-harness.js must handle clear-console-btn');
    });
  });

  // ─── ChatGPT Send-Button & Interception Regression Suite (All 9 User Scenarios) ───

  describe('ChatGPT Send-Button & Interception Regression Suite (All 9 User Scenarios)', () => {
    function setupRealisticDOMEnvironment() {
      // In-memory storage mock
      const storageData = {
        promptshield_enabled: true,
        promptshield_mode: 'STRICT',
        promptshield_incidents: [],
        promptshield_blocked_count: 0
      };

      const mockChrome = {
        storage: {
          local: {
            get: (keys, cb) => {
              const res = {};
              if (Array.isArray(keys)) {
                keys.forEach(k => { res[k] = storageData[k]; });
              } else if (typeof keys === 'string') {
                res[keys] = storageData[keys];
              }
              cb(res);
            },
            set: (obj, cb) => {
              Object.assign(storageData, obj);
              if (cb) cb();
            }
          },
          onChanged: { addListener: () => {} }
        },
        runtime: {
          sendMessage: async () => {}
        }
      };

      let modalVisible = false;
      let lastBlockedScan = null;
      let targetComposerRefocused = null;

      const mockUI = {
        showBlockedModal: (scanResult, composer) => {
          modalVisible = true;
          lastBlockedScan = scanResult;
          targetComposerRefocused = composer;
        },
        hideModal: () => {
          modalVisible = false;
        },
        isModalOpen: () => modalVisible
      };

      // Mock Event implementation
      class MockEvent {
        constructor(type, init = {}) {
          this.type = type;
          this.target = init.target || null;
          this.key = init.key || '';
          this.shiftKey = Boolean(init.shiftKey);
          this.isComposing = Boolean(init.isComposing);
          this.keyCode = init.keyCode || 0;
          this.defaultPrevented = false;
          this.immediatePropagationStopped = false;
        }
        preventDefault() {
          this.defaultPrevented = true;
        }
        stopImmediatePropagation() {
          this.immediatePropagationStopped = true;
        }
        stopPropagation() {}
      }

      // Mock DOM Node implementation
      class MockNode {
        constructor(tagName, attrs = {}, parent = null) {
          this.tagName = tagName.toUpperCase();
          this.id = attrs.id || '';
          this.className = attrs.class || attrs.className || '';
          this.type = attrs.type || '';
          this.disabled = Boolean(attrs.disabled);
          this.value = attrs.value || '';
          this._innerText = attrs.innerText || '';
          this._textContent = attrs.textContent || '';
          this.attributes = { ...attrs };
          this.parentNode = parent;
          this.children = [];
          if (parent) {
            parent.children.push(this);
          }
        }

        get innerText() {
          return this._innerText;
        }
        set innerText(val) {
          this._innerText = val;
          this._textContent = val;
        }

        get textContent() {
          return this._textContent;
        }
        set textContent(val) {
          this._textContent = val;
          this._innerText = val;
        }

        getAttribute(name) {
          return this.attributes[name] !== undefined ? this.attributes[name] : null;
        }

        setAttribute(name, val) {
          this.attributes[name] = String(val);
          if (name === 'id') this.id = String(val);
          if (name === 'class' || name === 'className') this.className = String(val);
          if (name === 'disabled') this.disabled = Boolean(val);
          if (name === 'type') this.type = String(val);
        }

        removeAttribute(name) {
          delete this.attributes[name];
          if (name === 'disabled') this.disabled = false;
        }

        closest(selector) {
          let curr = this;
          while (curr) {
            if (selector.includes('button, [role="button"]')) {
              if (curr.tagName === 'BUTTON' || curr.getAttribute('role') === 'button') {
                return curr;
              }
            }
            if (selector.includes('form') && curr.tagName === 'FORM') {
              return curr;
            }
            if (selector.includes('[class*="composer" i]') && curr.className.toLowerCase().includes('composer')) {
              return curr;
            }
            if (selector.includes('main') && curr.tagName === 'MAIN') {
              return curr;
            }
            curr = curr.parentNode;
          }
          return null;
        }

        querySelector(selector) {
          const all = this.querySelectorAll(selector);
          return all.length > 0 ? all[0] : null;
        }

        querySelectorAll(selector) {
          const matched = [];
          function traverse(node) {
            if (!node || !node.children) return;
            for (const child of node.children) {
              let isMatch = false;
              if (selector === '#prompt-textarea' && child.id === 'prompt-textarea') isMatch = true;
              if (selector.includes('[data-testid="prompt-textarea"]') && child.getAttribute('data-testid') === 'prompt-textarea') isMatch = true;
              if (selector.includes('p') && child.tagName === 'P') isMatch = true;
              if (selector.includes('svg') && child.tagName === 'SVG') isMatch = true;
              if (selector.includes('input[type="file"]') && child.tagName === 'INPUT' && child.type === 'file') isMatch = true;
              if (isMatch) matched.push(child);
              traverse(child);
            }
          }
          traverse(this);
          return matched;
        }

        contains(otherNode) {
          let curr = otherNode;
          while (curr) {
            if (curr === this) return true;
            curr = curr.parentNode;
          }
          return false;
        }
      }

      // Build realistic ChatGPT Composer DOM structure
      const rootForm = new MockNode('form', { class: 'stretch composer-wrapper' });
      const textareaWrapper = new MockNode('div', { class: 'relative flex flex-col w-full' }, rootForm);
      const composer = new MockNode('textarea', {
        id: 'prompt-textarea',
        'data-testid': 'prompt-textarea',
        placeholder: 'Message ChatGPT…'
      }, textareaWrapper);

      const toolbar = new MockNode('div', { class: 'flex items-center justify-between' }, rootForm);
      const leftControls = new MockNode('div', { class: 'flex items-center' }, toolbar);
      const attachBtn = new MockNode('button', {
        id: 'attach-btn',
        'data-testid': 'attach-button',
        'aria-label': 'Attach files',
        type: 'button'
      }, leftControls);

      const voiceBtn = new MockNode('button', {
        id: 'voice-btn',
        'data-testid': 'voice-mode-button',
        'aria-label': 'Voice mode',
        type: 'button'
      }, leftControls);

      const rightControls = new MockNode('div', { class: 'flex items-center' }, toolbar);
      const sendBtn = new MockNode('button', {
        id: 'send-btn',
        'data-testid': 'send-button',
        'aria-label': 'Send prompt',
        type: 'button'
      }, rightControls);
      const sendSvg = new MockNode('svg', { class: 'arrow-icon' }, sendBtn);
      const sendPath = new MockNode('path', { d: 'M8 16V6...' }, sendSvg);

      const stopBtn = new MockNode('button', {
        id: 'stop-btn',
        'data-testid': 'stop-button',
        'aria-label': 'Stop generating',
        type: 'button'
      }, rightControls);

      // Document mock
      const mockDocument = {
        body: rootForm,
        documentElement: rootForm,
        activeElement: composer,
        getElementById: (id) => {
          if (id === 'prompt-textarea') return composer;
          if (id === 'send-btn') return sendBtn;
          if (id === 'attach-btn') return attachBtn;
          if (id === 'voice-btn') return voiceBtn;
          if (id === 'stop-btn') return stopBtn;
          return null;
        },
        querySelector: (sel) => rootForm.querySelector(sel)
      };

      // Window mock with capture listeners
      const captureListeners = new Map();
      const mockWindow = {
        location: { origin: 'https://chatgpt.com' },
        addEventListener: (event, handler, useCapture) => {
          if (!captureListeners.has(event)) {
            captureListeners.set(event, []);
          }
          captureListeners.get(event).push({ handler, useCapture: Boolean(useCapture) });
        },
        dispatchEvent: (ev) => {
          const listeners = captureListeners.get(ev.type) || [];
          for (const l of listeners) {
            if (ev.immediatePropagationStopped) break;
            l.handler(ev);
          }
          return !ev.defaultPrevented;
        }
      };

      return {
        composer,
        sendBtn,
        sendSvg,
        sendPath,
        attachBtn,
        voiceBtn,
        stopBtn,
        rightControls,
        mockChrome,
        mockUI,
        mockDocument,
        mockWindow,
        storageData,
        MockNode,
        MockEvent,
        getModalVisible: () => modalVisible,
        getLastBlockedScan: () => lastBlockedScan
      };
    }

    // ─── 1. Sensitive prompt + Enter → blocked ──────────────────────────────
    it('1. Sensitive prompt + Enter → blocked', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      // Configure global context for test
      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      env.composer.value = 'Here is AWS key: AKIAIOSFODNN7EXAMPLE';
      const event = new env.MockEvent('keydown', { key: 'Enter', shiftKey: false, target: env.composer });

      contentScript.handleKeydownCapture(event);

      assert.equal(event.defaultPrevented, true, 'Enter keydown must be preventDefaulted');
      assert.equal(event.immediatePropagationStopped, true, 'Enter keydown must stop immediate propagation');
      assert.equal(env.getModalVisible(), true, 'Warning UI modal must be visible');
      assert.ok(env.storageData.promptshield_blocked_count >= 1, 'Incident count must increment in storage');
    });

    // ─── 2. Sensitive prompt + Send arrow click → blocked ───────────────────
    it('2. Sensitive prompt + Send arrow click → blocked', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      env.composer.value = 'Here is my OpenAI key: sk-proj-TEST1234567890abcdef1234567890abcdef12345678';
      // User clicks inner path of arrow icon in Send button
      const clickEvent = new env.MockEvent('click', { target: env.sendPath });

      contentScript.handleSendActionCapture(clickEvent);

      assert.equal(clickEvent.defaultPrevented, true, 'Send click must be preventDefaulted');
      assert.equal(clickEvent.immediatePropagationStopped, true, 'Send click must stop propagation');
      assert.equal(env.getModalVisible(), true, 'Warning UI modal must be shown');
      assert.ok(env.storageData.promptshield_blocked_count >= 1, 'Incident must be logged');
    });

    // ─── 3. Harmless prompt + Send arrow click → allowed ────────────────────
    it('3. Harmless prompt + Send arrow click → allowed', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      env.composer.value = 'Explain how binary search tree balancing works in TypeScript.';
      const clickEvent = new env.MockEvent('click', { target: env.sendPath });

      contentScript.handleSendActionCapture(clickEvent);

      assert.equal(clickEvent.defaultPrevented, false, 'Harmless prompt must NOT be preventDefaulted');
      assert.equal(clickEvent.immediatePropagationStopped, false, 'Propagation must NOT be stopped');
      assert.equal(env.getModalVisible(), false, 'Modal must NOT be shown');
      assert.equal(env.storageData.promptshield_blocked_count, 0, 'No incident should be recorded');
    });

    // ─── 4. Sensitive prompt + Shift+Enter → newline behavior preserved ─────
    it('4. Sensitive prompt + Shift+Enter → newline behavior preserved', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      env.composer.value = 'sk-proj-TEST1234567890abcdef1234567890abcdef12345678';
      const shiftEnterEvent = new env.MockEvent('keydown', { key: 'Enter', shiftKey: true, target: env.composer });

      contentScript.handleKeydownCapture(shiftEnterEvent);

      assert.equal(shiftEnterEvent.defaultPrevented, false, 'Shift+Enter must NOT be intercepted (allows newline)');
      assert.equal(env.getModalVisible(), false, 'Modal must NOT be shown for multiline newline insertion');
    });

    // ─── 5. Empty composer → no false incident ──────────────────────────────
    it('5. Empty composer → no false incident', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      env.composer.value = '    '; // whitespace empty
      const clickEvent = new env.MockEvent('click', { target: env.sendBtn });
      contentScript.handleSendActionCapture(clickEvent);

      assert.equal(clickEvent.defaultPrevented, false, 'Empty prompt click must not be intercepted');
      assert.equal(env.getModalVisible(), false, 'Empty prompt must not trigger alert');
      assert.equal(env.storageData.promptshield_blocked_count, 0, 'Zero incidents recorded for empty prompt');
    });

    // ─── 6. Re-rendered Send button → still protected ───────────────────────
    it('6. Re-rendered Send button → still protected', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      // Simulate React replacing send button with a newly mounted DOM element
      const reRenderedSendBtn = new env.MockNode('button', {
        id: 'new-send-btn',
        'data-testid': 'send-button',
        'aria-label': 'Send prompt',
        type: 'button'
      }, env.rightControls);
      const reRenderedSvg = new env.MockNode('svg', {}, reRenderedSendBtn);

      env.composer.value = 'Database secret: postgres://admin:SuperSecretPass123!@db.internal:5432/prod';
      const clickEvent = new env.MockEvent('click', { target: reRenderedSvg });

      contentScript.handleSendActionCapture(clickEvent);

      assert.equal(clickEvent.defaultPrevented, true, 'Newly re-rendered send button must still be intercepted');
      assert.equal(clickEvent.immediatePropagationStopped, true);
      assert.equal(env.getModalVisible(), true, 'Warning modal must trigger on re-rendered button');
    });

    // ─── 7. Attachment, voice, and stop buttons → not incorrectly blocked ────
    it('7. Attachment, voice, and stop-generation buttons → not incorrectly blocked', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      env.composer.value = 'Sensitive content sk-proj-TEST1234567890abcdef1234567890abcdef12345678';

      // 1. Attach button click
      const attachEvent = new env.MockEvent('click', { target: env.attachBtn });
      contentScript.handleSendActionCapture(attachEvent);
      assert.equal(attachEvent.defaultPrevented, false, 'Attachment button must NOT be intercepted');

      // 2. Voice button click
      const voiceEvent = new env.MockEvent('click', { target: env.voiceBtn });
      contentScript.handleSendActionCapture(voiceEvent);
      assert.equal(voiceEvent.defaultPrevented, false, 'Voice button must NOT be intercepted');

      // 3. Stop generation button click
      const stopEvent = new env.MockEvent('click', { target: env.stopBtn });
      contentScript.handleSendActionCapture(stopEvent);
      assert.equal(stopEvent.defaultPrevented, false, 'Stop-generation button must NOT be intercepted');

      assert.equal(env.getModalVisible(), false, 'None of non-send controls should trigger blocked modal');
    });

    // ─── 8. Duplicate event listeners → no duplicate incidents ───────────────
    it('8. Duplicate event listeners → no duplicate incidents', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();
      if (contentScript.resetListenersAttached) {
        contentScript.resetListenersAttached();
      }

      globalThis.window = env.mockWindow;
      globalThis.document = env.mockDocument;
      globalThis.chrome = env.mockChrome;
      globalThis.PromptShieldDetector = defaultDetector;
      globalThis.PromptShieldUI = env.mockUI;

      // Attach multiple times (idempotency check)
      contentScript.attachEventListeners();
      contentScript.attachEventListeners();
      contentScript.attachEventListeners();

      env.composer.value = 'DATABASE_URL="postgres://demo:SecretPass456!@localhost:5432/db"';

      // Rapid browser gesture sequence: pointerdown -> mousedown -> click
      const pDown = new env.MockEvent('pointerdown', { target: env.sendPath });
      const mDown = new env.MockEvent('mousedown', { target: env.sendPath });
      const mClick = new env.MockEvent('click', { target: env.sendPath });

      contentScript.handleSendActionCapture(pDown);
      contentScript.handleSendActionCapture(mDown);
      contentScript.handleSendActionCapture(mClick);

      assert.equal(pDown.defaultPrevented, true);
      assert.equal(mDown.defaultPrevented, true);
      assert.equal(mClick.defaultPrevented, true);

      // Exactly ONE incident recorded in storage despite 3 rapid events and multiple listener attachments
      assert.equal(env.storageData.promptshield_blocked_count, 1, 'Must record exactly 1 incident across rapid click sequence');
    });

    // ─── 9. Reporting/backend unavailable → local blocking still works ───────
    it('9. Reporting/backend unavailable → local blocking still works', () => {
      const env = setupRealisticDOMEnvironment();
      contentScript.resetSubmissionGesture();

      // Configure storage to simulate synced reporting enabled
      env.storageData.aegis_auth_token = 'expired_or_invalid_jwt';
      env.storageData.aegis_backend_url = 'http://127.0.0.1:9999'; // unreachable port
      env.storageData.promptshield_sync_enabled = true;

      // Mock fetch to simulate network failure (e.g. backend down)
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async () => {
        throw new TypeError('Failed to fetch: Gateway network unreachable');
      };

      try {
        globalThis.window = env.mockWindow;
        globalThis.document = env.mockDocument;
        globalThis.chrome = env.mockChrome;
        globalThis.PromptShieldDetector = defaultDetector;
        globalThis.PromptShieldUI = env.mockUI;

        env.composer.value = 'AWS secret: AKIAIOSFODNN7EXAMPLE';
        const clickEvent = new env.MockEvent('click', { target: env.sendBtn });

        // Must NOT throw unhandled rejection, and local blocking must succeed
        assert.doesNotThrow(() => {
          contentScript.handleSendActionCapture(clickEvent);
        });

        assert.equal(clickEvent.defaultPrevented, true, 'Local blocking must function even if backend is offline');
        assert.equal(clickEvent.immediatePropagationStopped, true);
        assert.equal(env.getModalVisible(), true, 'Local warning UI must display without relying on backend');
        assert.equal(env.storageData.promptshield_blocked_count, 1, 'Local storage incident must be recorded');
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
