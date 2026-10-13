/**
 * PromptShield AI - In-Page Warning UI Component
 * 
 * Manages the overlay modal and visual indicators when sensitive prompts are blocked.
 * Enforces singleton modal state to prevent duplicate stacked alerts.
 */

(function (root, factory) {
  if (typeof exports === 'object' && typeof module !== 'undefined') {
    module.exports = factory();
  } else {
    root.PromptShieldUI = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  let overlayElement = null;
  let isModalVisible = false;
  let currentTargetComposer = null;
  let keydownListenerAttached = false;

  /**
   * Initialize or retrieve the overlay DOM container
   */
  function getOrCreateOverlay() {
    const parentNode = document.body || document.documentElement;
    if (overlayElement && parentNode && parentNode.contains(overlayElement)) {
      return overlayElement;
    }

    const existing = document.getElementById('promptshield-overlay-container');
    if (existing) {
      overlayElement = existing;
      return overlayElement;
    }

    const container = document.createElement('div');
    container.id = 'promptshield-overlay-container';
    container.setAttribute('role', 'alertdialog');
    container.setAttribute('aria-modal', 'true');
    container.setAttribute('aria-labelledby', 'promptshield-modal-title');

    container.innerHTML = `
      <div class="promptshield-modal-card" id="promptshield-modal-card">
        <div class="promptshield-header">
          <div class="promptshield-brand">
            <div class="promptshield-logo-icon">
              <svg viewBox="0 0 24 24">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 6c1.4 0 2.5 1.1 2.5 2.5S13.4 12 12 12s-2.5-1.1-2.5-2.5S10.6 7 12 7zm0 13.9c-2.7-.9-5.1-4-5.5-7.9h11c-.4 3.9-2.8 7-5.5 7.9z"/>
              </svg>
            </div>
            <h2 class="promptshield-title" id="promptshield-modal-title">PromptShield Alert</h2>
          </div>
          <span class="promptshield-badge-blocked" id="promptshield-modal-badge">Submission Blocked</span>
        </div>

        <div class="promptshield-body">
          <p class="promptshield-message" id="promptshield-modal-summary">
            PromptShield detected sensitive information in your prompt and prevented it from being sent.
          </p>

          <div class="promptshield-violations-list" id="promptshield-violations-list">
            <!-- Dynamic violation cards inserted here -->
          </div>

          <div class="promptshield-guidance">
            <strong>Safe Practice:</strong> Replace actual credentials or secrets with environment variable references (e.g. <code>process.env.API_KEY</code>) or simulated mock values before continuing.
          </div>
        </div>

        <div class="promptshield-footer">
          <button type="button" class="promptshield-btn-primary" id="promptshield-btn-revise">
            Revise Prompt (Esc)
          </button>
        </div>
      </div>
    `;

    if (parentNode) {
      parentNode.appendChild(container);
    }
    overlayElement = container;

    // Attach click handler on revise button
    const reviseBtn = container.querySelector('#promptshield-btn-revise');
    if (reviseBtn) {
      reviseBtn.addEventListener('click', () => {
        hideModal();
      });
    }

    // Backdrop click dismisses
    container.addEventListener('click', (e) => {
      if (e.target === container) {
        hideModal();
      }
    });

    // Escape key dismisses modal
    if (!keydownListenerAttached) {
      window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && isModalVisible) {
          hideModal();
          e.stopPropagation();
        }
      }, true);
      keydownListenerAttached = true;
    }

    return overlayElement;
  }

  /**
   * Escape HTML to prevent XSS injection into the alert card
   */
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /**
   * Render alert modal with detected violations
   * 
   * @param {Object} scanResult - Result returned by detector.scan()
   * @param {HTMLElement} composerElement - Target composer DOM node to refocus on dismiss
   */
  function showBlockedModal(scanResult, composerElement) {
    currentTargetComposer = composerElement;
    const container = getOrCreateOverlay();

    const violationsList = container.querySelector('#promptshield-violations-list');
    const badge = container.querySelector('#promptshield-modal-badge');
    const summary = container.querySelector('#promptshield-modal-summary');

    if (!scanResult || !scanResult.violations || scanResult.violations.length === 0) {
      return;
    }

    // Set badge text according to max severity
    badge.textContent = `${scanResult.maxSeverity} - BLOCKED`;
    badge.className = `promptshield-badge-blocked ${scanResult.maxSeverity}`;

    summary.textContent = `PromptShield intercepted your submission because ${scanResult.violations.length} high-risk rule(s) were triggered.`;

    // Populate violation items
    violationsList.innerHTML = scanResult.violations
      .map((v) => {
        return `
          <div class="promptshield-violation-item">
            <div class="promptshield-violation-top">
              <span class="promptshield-rule-name">${escapeHtml(v.ruleName)} (${escapeHtml(v.ruleId)})</span>
              <span class="promptshield-rule-severity ${escapeHtml(v.severity)}">${escapeHtml(v.severity)}</span>
            </div>
            <div style="font-size: 12px; color: #9ca3af; margin-bottom: 6px;">
              ${escapeHtml(v.description)}
            </div>
            <div class="promptshield-redacted-box">
              Redacted Match: <code>${escapeHtml(v.redactedSnippet)}</code>
            </div>
          </div>
        `;
      })
      .join('');

    // Highlight composer visually
    if (composerElement) {
      composerElement.classList.add('promptshield-composer-warning');
    }

    // Show container
    container.classList.add('promptshield-visible');
    isModalVisible = true;

    // Focus primary action button for accessibility
    setTimeout(() => {
      const btn = container.querySelector('#promptshield-btn-revise');
      if (btn) btn.focus();
    }, 50);
  }

  /**
   * Hide the modal and restore focus to prompt composer
   */
  function hideModal() {
    if (!overlayElement) return;

    overlayElement.classList.remove('promptshield-visible');
    isModalVisible = false;

    if (currentTargetComposer) {
      currentTargetComposer.classList.remove('promptshield-composer-warning');
      try {
        currentTargetComposer.focus();
      } catch (err) {
        // Ignored if composer was unmounted
      }
    }
  }

  return {
    showBlockedModal,
    hideModal,
    isModalOpen: () => isModalVisible
  };
});
