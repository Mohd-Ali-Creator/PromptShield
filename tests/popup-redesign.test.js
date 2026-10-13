const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

describe('PromptShield AI - Extension Popup Redesign & MV3 Compliance Suite', () => {
  const rootDir = path.resolve(__dirname, '..');
  const aegisPopupHtmlPath = path.join(rootDir, 'Aegis-AI', 'extension', 'popup', 'popup.html');
  const aegisPopupJsPath = path.join(rootDir, 'Aegis-AI', 'extension', 'popup', 'popup.js');
  const aegisPopupCssPath = path.join(rootDir, 'Aegis-AI', 'extension', 'popup', 'popup.css');

  const rootPopupHtmlPath = path.join(rootDir, 'extension', 'popup', 'popup.html');
  const rootPopupJsPath = path.join(rootDir, 'extension', 'popup', 'popup.js');
  const rootPopupCssPath = path.join(rootDir, 'extension', 'popup', 'popup.css');

  test('popup files must exist in both Aegis-AI/extension and root extension directories', () => {
    assert.ok(fs.existsSync(aegisPopupHtmlPath), 'Aegis-AI popup.html must exist');
    assert.ok(fs.existsSync(aegisPopupJsPath), 'Aegis-AI popup.js must exist');
    assert.ok(fs.existsSync(aegisPopupCssPath), 'Aegis-AI popup.css must exist');
    assert.ok(fs.existsSync(rootPopupHtmlPath), 'Root extension popup.html must exist');
    assert.ok(fs.existsSync(rootPopupJsPath), 'Root extension popup.js must exist');
    assert.ok(fs.existsSync(rootPopupCssPath), 'Root extension popup.css must exist');
  });

  test('popup.html files must match and have NO inline <script> tags (Manifest V3 CSP Compliance)', () => {
    const aegisHtml = fs.readFileSync(aegisPopupHtmlPath, 'utf8');
    const rootHtml = fs.readFileSync(rootPopupHtmlPath, 'utf8');
    assert.strictEqual(aegisHtml, rootHtml, 'Aegis-AI and root popup.html must be identical');

    const inlineScriptMatch = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/i.test(aegisHtml);
    assert.strictEqual(inlineScriptMatch, false, 'popup.html MUST NOT contain inline <script> tags');

    const inlineEventHandlerMatch = /\son[a-z]+=/i.test(aegisHtml);
    assert.strictEqual(inlineEventHandlerMatch, false, 'popup.html MUST NOT contain inline event handlers');
  });

  test('popup.html must contain all required Neo-Brutalist dashboard panels and IDs', () => {
    const html = fs.readFileSync(aegisPopupHtmlPath, 'utf8');

    // Section A: Header
    assert.ok(html.includes('id="conn-status-badge"'), 'must include conn-status-badge');
    assert.ok(html.includes('id="conn-status-dot"'), 'must include conn-status-dot');
    assert.ok(html.includes('id="conn-status-text"'), 'must include conn-status-text');
    assert.ok(html.includes('id="refresh-btn"'), 'must include refresh-btn');

    // Section B: Guardrail Status Card
    assert.ok(html.includes('id="protection-toggle"'), 'must include protection-toggle');
    assert.ok(html.includes('id="guardrail-status-text"'), 'must include guardrail-status-text');
    assert.ok(html.includes('id="employee-display-val"'), 'must include employee-display-val');
    assert.ok(html.includes('id="org-display-val"'), 'must include org-display-val');
    assert.ok(html.includes('id="policy-sync-tag"'), 'must include policy-sync-tag');
    assert.ok(html.includes('id="policy-sync-time"'), 'must include policy-sync-time');
    assert.ok(html.includes('id="mode-select"'), 'must include mode-select');

    // Section C: Security Metrics
    assert.ok(html.includes('id="metric-scanned"'), 'must include metric-scanned');
    assert.ok(html.includes('id="metric-blocked"'), 'must include metric-blocked');
    assert.ok(html.includes('id="metric-warned"'), 'must include metric-warned');
    assert.ok(html.includes('id="metric-sanitized"'), 'must include metric-sanitized');
    assert.ok(html.includes('id="metrics-source-note"'), 'must include metrics-source-note');

    // Section D: Connection Panel
    assert.ok(html.includes('id="conn-disconnected-view"'), 'must include conn-disconnected-view');
    assert.ok(html.includes('id="conn-connected-view"'), 'must include conn-connected-view');
    assert.ok(html.includes('id="aegis-token-input"'), 'must include aegis-token-input');
    assert.ok(html.includes('id="aegis-connect-btn"'), 'must include aegis-connect-btn');
    assert.ok(html.includes('id="user-name-text"'), 'must include user-name-text');
    assert.ok(html.includes('id="user-org-text"'), 'must include user-org-text');
    assert.ok(html.includes('id="sync-policies-btn"'), 'must include sync-policies-btn');
    assert.ok(html.includes('id="aegis-disconnect-btn"'), 'must include aegis-disconnect-btn');

    // Section E: Incidents List
    assert.ok(html.includes('id="incidents-list"'), 'must include incidents-list');
    assert.ok(html.includes('id="clear-log-btn"'), 'must include clear-log-btn');

    // Section F: Quick Actions
    assert.ok(html.includes('id="open-reports-btn"'), 'must include open-reports-btn');
    assert.ok(html.includes('id="open-sandbox-btn"'), 'must include open-sandbox-btn');

    // Zero-Knowledge & Error UI
    assert.ok(html.includes('id="error-banner"'), 'must include error-banner');
    assert.ok(html.includes('Zero-Knowledge'), 'must prominently display Zero-Knowledge privacy assurance');
  });

  test('popup.js must be syntactically valid and reference existing DOM element IDs', () => {
    const js = fs.readFileSync(aegisPopupJsPath, 'utf8');
    const html = fs.readFileSync(aegisPopupHtmlPath, 'utf8');

    // Syntax validation
    assert.doesNotThrow(() => {
      new Function(js);
    }, 'popup.js must parse with zero syntax errors');

    // Check all getElementById calls
    const regex = /getElementById\(['"]([^'"]+)['"]\)/g;
    let match;
    const ids = [];
    while ((match = regex.exec(js)) !== null) {
      ids.push(match[1]);
    }

    ids.forEach((id) => {
      assert.ok(
        html.includes(`id="${id}"`) || html.includes(`id='${id}'`),
        `Element with id="${id}" referenced in popup.js must exist in popup.html`
      );
    });
  });

  test('popup.css must embody Aegis-AI Neo-Brutalist design tokens and fit Chrome dimensions', () => {
    const css = fs.readFileSync(aegisPopupCssPath, 'utf8');

    // Fonts
    assert.ok(css.includes('Outfit'), 'must import Outfit font');
    assert.ok(css.includes('Inter'), 'must import Inter font');
    assert.ok(css.includes('JetBrains Mono'), 'must import JetBrains Mono font');

    // Dimensions
    assert.ok(css.includes('width: 380px'), 'width must be 380px to fit Chrome popup');
    assert.ok(css.includes('max-height: 590px'), 'max-height must fit Chrome popup limits');

    // Neo-Brutalist design tokens
    assert.ok(css.includes('--shadow-base') || css.includes('3px 3px 0px'), 'must define neo-brutalist hard shadows');
    assert.ok(css.includes('--border-dark') || css.includes('#0f172a'), 'must use high-contrast dark border');
    assert.ok(css.includes('--purple-primary') || css.includes('#7c3aed'), 'must use purple branding');
  });
});
