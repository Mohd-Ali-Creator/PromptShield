/**
 * PromptShield AI - Background Service Worker (Manifest V3)
 * 
 * Responsibilities:
 * - Initializes default extension settings upon installation.
 * - Updates the extension toolbar badge when incidents are prevented.
 * - Maintains zero network telemetry.
 */

function ensureDefaults() {
  chrome.storage.local.get(['promptshield_enabled', 'promptshield_mode'], (result) => {
    if (result.promptshield_enabled === undefined) {
      chrome.storage.local.set({
        promptshield_enabled: true,
        promptshield_mode: 'STRICT',
        promptshield_blocked_count: 0,
        promptshield_incidents: []
      });
      chrome.action.setBadgeText({ text: 'ON' });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
    } else {
      const isEnabled = result.promptshield_enabled !== false;
      chrome.action.setBadgeText({ text: isEnabled ? 'ON' : 'OFF' });
      chrome.action.setBadgeBackgroundColor({ color: isEnabled ? '#10b981' : '#6b7280' });
    }
  });
}

chrome.runtime.onInstalled.addListener(() => {
  ensureDefaults();
});

// Run on service worker activation
ensureDefaults();

// Listen for incident messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PROMPTSHIELD_INCIDENT_RECORDED') {
    const count = message.count || 1;
    chrome.action.setBadgeText({ text: String(count) });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' }); // Red badge for blocks
    sendResponse({ status: 'ok' });
  } else if (message.type === 'PROMPTSHIELD_TOGGLE_STATE') {
    const isEnabled = message.enabled;
    if (isEnabled) {
      chrome.action.setBadgeText({ text: 'ON' });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
    } else {
      chrome.action.setBadgeText({ text: 'OFF' });
      chrome.action.setBadgeBackgroundColor({ color: '#6b7280' });
    }
    sendResponse({ status: 'ok' });
  }
});
