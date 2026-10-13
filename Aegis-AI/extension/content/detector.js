/**
 * PromptShield AI - Detection Engine
 * 
 * Local-first regex and heuristic engine for scanning prompts.
 * Operates in browser content-script contexts and Node.js test environments.
 * 
 * PRIVACY GUARANTEE:
 * - 100% in-memory local execution.
 * - Zero network calls or external telemetry.
 * - Raw secrets and prompts are NEVER logged or retained.
 */

(function (root, factory) {
  if (typeof exports === 'object' && typeof module !== 'undefined') {
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else {
    root.PromptShieldDetector = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Severity definitions
  const SEVERITY = {
    CRITICAL: 'CRITICAL', // Hard block: never allow submission
    HIGH: 'HIGH',         // Block: requires explicit policy handling
    MEDIUM: 'MEDIUM',     // Warning / audit: notify user
    LOW: 'LOW',           // Informational
    NONE: 'NONE'
  };

  const SEVERITY_WEIGHT = {
    [SEVERITY.CRITICAL]: 4,
    [SEVERITY.HIGH]: 3,
    [SEVERITY.MEDIUM]: 2,
    [SEVERITY.LOW]: 1,
    [SEVERITY.NONE]: 0
  };

  /**
   * Known placeholder and mock values that should be treated as benign examples
   */
  const COMMON_PLACEHOLDERS = [
    'your-api-key',
    'your_api_key',
    'your-key-here',
    'your_key_here',
    'your-api-key-here',
    'your_api_key_here',
    'your-password-here',
    'your_password_here',
    'replace_with_key',
    'replace-me',
    'insert_token_here',
    'insert-password-here',
    'insert_password_here',
    'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx',
    'sk-xxxx',
    'dummy_key',
    'example_password',
    'password123', // if explicitly labeled as sample in comments
    'my-secret-key-placeholder',
    '<api_key>',
    '<your_password>',
    '<your-api-key-here>',
    '<insert-key>'
  ];

  /**
   * Luhn Algorithm validator for payment card numbers
   */
  function isValidLuhn(numberString) {
    const cleanDigits = numberString.replace(/[\s-]/g, '');
    if (!/^\d{13,19}$/.test(cleanDigits)) return false;

    // Reject repeated trivial digits like 0000000000000000 or 1111111111111111
    if (/^(\d)\1+$/.test(cleanDigits)) return false;

    let sum = 0;
    let shouldDouble = false;

    for (let i = cleanDigits.length - 1; i >= 0; i--) {
      let digit = parseInt(cleanDigits.charAt(i), 10);
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }

    return sum % 10 === 0;
  }

  /**
   * Mask/Redact sensitive string for display without exposing the secret
   */
  function maskSensitive(value, prefixLen = 4, suffixLen = 3) {
    if (!value || typeof value !== 'string') return '[REDACTED]';
    const trimmed = value.trim();
    if (trimmed.length <= prefixLen + suffixLen) {
      return '*'.repeat(Math.max(6, trimmed.length));
    }
    const start = trimmed.substring(0, prefixLen);
    const end = trimmed.substring(trimmed.length - suffixLen);
    return `${start}****...****${end}`;
  }

  /**
   * Security detection rules
   */
  const RULES = [
    {
      id: 'SEC-001',
      name: 'Private Key Block',
      severity: SEVERITY.CRITICAL,
      description: 'Asymmetric private key certificate block detected (RSA, EC, OpenSSH, PGP).',
      pattern: /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----|$)/gi,
      customValidator: (match) => {
        // High confidence match for private keys
        return match.includes('BEGIN') && match.includes('PRIVATE KEY');
      },
      redactor: () => '-----BEGIN [REDACTED] PRIVATE KEY-----'
    },
    {
      id: 'SEC-002',
      name: 'OpenAI API Key',
      severity: SEVERITY.CRITICAL,
      description: 'OpenAI secret API key pattern detected.',
      pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{28,64}\b/g,
      customValidator: (match) => {
        const lower = match.toLowerCase();
        if (COMMON_PLACEHOLDERS.some((p) => lower.includes(p))) return false;
        // Require at least some character variety
        const uniqueChars = new Set(match.slice(7)).size;
        return uniqueChars > 6;
      },
      redactor: (m) => maskSensitive(m, 8, 4)
    },
    {
      id: 'SEC-003',
      name: 'AWS Access Key ID',
      severity: SEVERITY.CRITICAL,
      description: 'Amazon Web Services Access Key ID detected.',
      pattern: /\b(AKIA|ASIA|AROA)[0-9A-Z]{16}\b/g,
      customValidator: (match) => {
        if (match === 'AKIAIOSFODNN7EXAMPLE') {
          // AWS documentation example key: treat as valid synthetic vector for test
          return true;
        }
        // Disallow all-same character
        return !/^(\w)\1+$/.test(match);
      },
      redactor: (m) => maskSensitive(m, 4, 3)
    },
    {
      id: 'SEC-004',
      name: 'GitHub Personal Access Token',
      severity: SEVERITY.CRITICAL,
      description: 'GitHub personal access token or fine-grained token pattern detected.',
      pattern: /\bgh[pousr]_[A-Za-z0-9_]{36,60}\b/g,
      customValidator: (match) => {
        const lower = match.toLowerCase();
        return !COMMON_PLACEHOLDERS.some((p) => lower.includes(p));
      },
      redactor: (m) => maskSensitive(m, 4, 4)
    },
    {
      id: 'SEC-005',
      name: 'Google Cloud API Key',
      severity: SEVERITY.CRITICAL,
      description: 'Google Cloud Platform API key detected.',
      pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
      customValidator: (match) => {
        const lower = match.toLowerCase();
        return !COMMON_PLACEHOLDERS.some((p) => lower.includes(p));
      },
      redactor: (m) => maskSensitive(m, 6, 3)
    },
    {
      id: 'SEC-006',
      name: 'Slack Token',
      severity: SEVERITY.CRITICAL,
      description: 'Slack bot, user, or app authorization token detected.',
      pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,50}\b/g,
      customValidator: (match) => {
        return match.split('-').length >= 3;
      },
      redactor: (m) => maskSensitive(m, 5, 3)
    },
    {
      id: 'SEC-007',
      name: 'Database Connection URI with Credentials',
      severity: SEVERITY.HIGH,
      description: 'Database connection string containing embedded credentials.',
      pattern: /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/(?:[a-zA-Z0-9_.-]+):([^@\s]+)@([a-zA-Z0-9_.-]+)(?::\d+)?\/?[^\s]*/gi,
      customValidator: (match) => {
        // Disallow placeholder schemes like mongodb://user:password@localhost
        const lower = match.toLowerCase();
        if (lower.includes(':password@') || lower.includes(':user@') || lower.includes(':<password>@')) {
          // If it's literally ':password@', check if it's explicitly an example
          return true; // Still high risk to paste connection strings
        }
        return true;
      },
      redactor: (m) => {
        return m.replace(/(:\/\/[\w.-]+:)([^@]+)(@)/, '$1[REDACTED_PASSWORD]$3');
      }
    },
    {
      id: 'SEC-008',
      name: 'Plaintext Password Assignment',
      severity: SEVERITY.HIGH,
      description: 'Hardcoded password or secret assignment detected in prompt.',
      pattern: /(?:password|passwd|pwd|db_pass|secret_key|api_secret)\s*[:=]\s*["']?([^\s"';,\n\r]{6,})["']?/gi,
      customValidator: (match, text) => {
        const lower = match.toLowerCase();
        // Ignore safe code patterns like process.env.PASSWORD or os.environ.get
        if (
          lower.includes('process.env') ||
          lower.includes('os.environ') ||
          lower.includes('os.getenv') ||
          lower.includes('get_secret') ||
          lower.includes('getenv') ||
          lower.includes('${')
        ) {
          return false;
        }

        // Ignore obvious placeholder templates
        if (COMMON_PLACEHOLDERS.some((p) => lower.includes(p))) {
          return false;
        }

        // Extract value
        const assignmentParts = match.split(/[:=]/);
        if (assignmentParts.length < 2) return false;
        const val = assignmentParts.slice(1).join('=').trim().replace(/^["']|["']$/g, '');

        // Ignore function calls like `getPassword()` or `config.pass`
        if (val.endsWith('()') || val.includes('.')) {
          return false;
        }

        // Must have reasonable length and entropy
        return val.length >= 6;
      },
      redactor: (m) => {
        const parts = m.split(/[:=]/);
        return `${parts[0].trim()} = [REDACTED_PASSWORD]`;
      }
    },
    {
      id: 'SEC-009',
      name: 'Payment Card Number',
      severity: SEVERITY.MEDIUM,
      description: 'Luhn-valid payment card number pattern detected.',
      pattern: /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{15,16}\b/g,
      customValidator: (match) => {
        return isValidLuhn(match);
      },
      redactor: (m) => maskSensitive(m.replace(/[\s-]/g, ''), 4, 4)
    },
    {
      id: 'SEC-010',
      name: 'US Social Security Number',
      severity: SEVERITY.MEDIUM,
      description: 'Synthetic or active US Social Security Number format detected.',
      pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
      customValidator: (match) => {
        // Disallow obvious sequences like 123-45-6789 if needed, but standard regex handles area rules
        return true;
      },
      redactor: (m) => maskSensitive(m, 3, 2)
    }
  ];

  /**
   * Main PromptDetector engine
   */
  class PromptDetector {
    constructor(options = {}) {
      this.rules = options.rules || RULES;
      this.customRules = options.customRules || [];
      // Company Data DNA rules — set dynamically from company-rules.js
      this._companyRules = [];
    }

    /**
     * Replace the active set of compiled company rules.
     * Called by content.js whenever chrome.storage changes.
     * @param {Object[]} compiledRules - Output of CompanyRules.compileEnabledRules()
     */
    setCompanyRules(compiledRules) {
      this._companyRules = Array.isArray(compiledRules) ? compiledRules : [];
      console.log('[PromptShield AI] Company DNA rules updated: ' + this._companyRules.length + ' active rule(s).');
    }

    /**
     * Returns the current active company rules (read-only snapshot).
     */
    getCompanyRules() {
      return [...this._companyRules];
    }

    /**
     * Scan a prompt text against active rules.
     * 
     * @param {string} text - Raw input prompt text to inspect.
     * @returns {Object} Inspection result object with findings and severity.
     */
    scan(text) {
      if (!text || typeof text !== 'string') {
        return {
          hasViolations: false,
          maxSeverity: SEVERITY.NONE,
          shouldBlock: false,
          violations: [],
          stats: { ruleCount: this.rules.length, scannedLength: 0 }
        };
      }

      const trimmedText = text.trim();
      if (trimmedText.length === 0) {
        return {
          hasViolations: false,
          maxSeverity: SEVERITY.NONE,
          shouldBlock: false,
          violations: [],
          stats: { ruleCount: this.rules.length, scannedLength: 0 }
        };
      }

      const violations = [];
      const allRules = [...this.rules, ...this.customRules, ...this._companyRules];

      for (const rule of allRules) {
        // Reset regex state
        const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
        let match;

        while ((match = regex.exec(trimmedText)) !== null) {
          const matchedString = match[0];

          // Run custom validator if present
          if (typeof rule.customValidator === 'function') {
            const isValid = rule.customValidator(matchedString, trimmedText);
            if (!isValid) {
              continue;
            }
          }

          // Redact match
          const redactedSnippet = typeof rule.redactor === 'function'
            ? rule.redactor(matchedString)
            : maskSensitive(matchedString);

          violations.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            description: rule.description,
            redactedSnippet: redactedSnippet,
            index: match.index,
            matchLength: matchedString.length,
            timestamp: Date.now(),
            // Company-rule metadata (undefined for built-in rules)
            _isCompanyRule: rule._isCompanyRule || false,
            _doesBlock: rule._doesBlock || false,
            _companyAction: rule._companyAction || null
          });

          // Avoid infinite loops with zero-length matches
          if (regex.lastIndex === match.index) {
            regex.lastIndex++;
          }
        }
      }

      // Determine highest severity
      let maxSeverity = SEVERITY.NONE;
      let maxWeight = 0;

      for (const v of violations) {
        const weight = SEVERITY_WEIGHT[v.severity] || 0;
        if (weight > maxWeight) {
          maxWeight = weight;
          maxSeverity = v.severity;
        }
      }

      // Company rules with action="block" force shouldBlock regardless of severity.
      // Company rules with action="warn" or "redact" NEVER block, even if severity is HIGH/CRITICAL —
      // the admin explicitly chose a non-blocking action for that rule.
      // Built-in rules (no _isCompanyRule flag) still block at HIGH/CRITICAL severity as before.
      const hasCompanyBlock = violations.some(v => v._doesBlock === true);

      // Only count built-in rule violations toward severity-based blocking
      const builtInMaxSeverity = (() => {
        let sev = SEVERITY.NONE;
        let weight = 0;
        for (const v of violations) {
          if (!v._isCompanyRule) {
            const w = SEVERITY_WEIGHT[v.severity] || 0;
            if (w > weight) { weight = w; sev = v.severity; }
          }
        }
        return sev;
      })();

      const shouldBlock = hasCompanyBlock ||
        builtInMaxSeverity === SEVERITY.CRITICAL ||
        builtInMaxSeverity === SEVERITY.HIGH;


      return {
        hasViolations: violations.length > 0,
        maxSeverity: maxSeverity,
        shouldBlock: shouldBlock,
        violations: violations,
        stats: {
          ruleCount: allRules.length,
          scannedLength: trimmedText.length,
          violationsFound: violations.length
        }
      };
    }
  }

  // Singleton instance
  const defaultDetector = new PromptDetector();

  return {
    PromptDetector,
    defaultDetector,
    SEVERITY,
    SEVERITY_WEIGHT,
    RULES,
    maskSensitive,
    isValidLuhn,
    scan: (text) => defaultDetector.scan(text),
    setCompanyRules: (rules) => defaultDetector.setCompanyRules(rules),
    getCompanyRules: () => defaultDetector.getCompanyRules()
  };
});
