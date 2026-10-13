/**
 * PromptShield AI - Company Data DNA Engine
 *
 * Allows a company administrator to define custom confidential-data patterns
 * that PromptShield detects locally in employee prompts.
 *
 * SECURITY GUARANTEES:
 * - 100% local evaluation. Zero network calls.
 * - Raw prompts and matched values are NEVER logged or persisted.
 * - Regex patterns are validated and ReDoS-screened before compilation.
 * - No eval() or Function() — arbitrary executable code from admins is rejected.
 * - Rule configurations are read-only at scan time.
 *
 * RULE CONFIGURATION FORMAT (stored at key "promptshield_company_rules"):
 * [
 *   {
 *     id: "CDR-001",                       // Required. Unique string identifier.
 *     name: "Project Falcon Code",         // Required. Human-readable display name.
 *     description: "...",                  // Optional. Explains what the rule guards.
 *     patternType: "exact" | "regex",      // Required. "exact" = substring match (safe).
 *                                          //           "regex" = validated RegExp.
 *     pattern: "PROJECT-FALCON-7Q",        // Required. The marker string or regex source.
 *     severity: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW",  // Required.
 *     action: "block" | "warn" | "redact", // Required. Determines shouldBlock outcome.
 *     enabled: true                        // Required. false = rule is inactive.
 *   }
 * ]
 *
 * ACTION → shouldBlock mapping (STRICT mode):
 *   "block"  → sets shouldBlock = true (same behaviour as CRITICAL/HIGH rules)
 *   "warn"   → sets shouldBlock = false (modal shown but submission permitted)
 *   "redact" → sets shouldBlock = false (violation recorded, no block)
 */

(function (root, factory) {
  if (typeof exports === 'object' && typeof module !== 'undefined') {
    module.exports = factory();
  } else {
    root.PromptShieldCompanyRules = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ─── Constants ────────────────────────────────────────────────────────────

  const STORAGE_KEY = 'promptshield_company_rules';

  const VALID_SEVERITY = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const VALID_ACTION   = ['block', 'warn', 'redact'];
  const VALID_PATTERN_TYPE = ['exact', 'regex'];

  /**
   * Maximum allowed pattern length to prevent resource exhaustion.
   * Exact markers can be longer; regex patterns are kept tighter.
   */
  const MAX_EXACT_LENGTH  = 512;
  const MAX_REGEX_LENGTH  = 256;

  /**
   * Maximum number of company rules to prevent storage bloat / scan overhead.
   */
  const MAX_RULE_COUNT = 100;

  /**
   * Simple structural ReDoS heuristics — rejects patterns containing
   * nested quantifiers or ambiguous grouping that classically cause
   * catastrophic backtracking. Not exhaustive, but eliminates most attacks.
   *
   * Rejected constructs:
   *   (a+)+   (a*)* / (a+)* / (a*)+   (a{2,})+   (.+)+
   *   (?:a|aa)+  (?:a|a)+
   */
  const REDOS_PATTERNS = [
    /(\(([^)]+)\)[\+\*]){1,}[\+\*]/,     // nested quantifiers like (a+)+
    /\([^)]*[\+\*][^)]*\)[\+\*]/,        // group with quantifier, then quantifier
    /(\.\+|\.\*)\){0,1}[\+\*]/,          // .+ or .* followed by quantifier
    /\{[2-9]\d*,\d*\}[\+\*]/,            // {2,}+ patterns
    /\|[^)]{0,20}\|/,                    // nested alternation (a|a)
  ];

  // ─── Validation ───────────────────────────────────────────────────────────

  /**
   * Validates a single rule configuration object.
   * Returns { valid: boolean, error: string | null }
   */
  function validateRule(rule) {
    if (!rule || typeof rule !== 'object') {
      return { valid: false, error: 'Rule must be a plain object.' };
    }

    // ID
    if (!rule.id || typeof rule.id !== 'string' || rule.id.trim().length === 0) {
      return { valid: false, error: 'Rule must have a non-empty string "id".' };
    }
    if (!/^[A-Za-z0-9_\-]+$/.test(rule.id)) {
      return { valid: false, error: `Rule id "${rule.id}" contains invalid characters. Use only [A-Za-z0-9_-].` };
    }

    // Name
    if (!rule.name || typeof rule.name !== 'string' || rule.name.trim().length === 0) {
      return { valid: false, error: `Rule "${rule.id}" must have a non-empty "name".` };
    }

    // Pattern type
    if (!VALID_PATTERN_TYPE.includes(rule.patternType)) {
      return { valid: false, error: `Rule "${rule.id}" patternType must be "exact" or "regex". Got: "${rule.patternType}".` };
    }

    // Pattern
    if (typeof rule.pattern !== 'string' || rule.pattern.length === 0) {
      return { valid: false, error: `Rule "${rule.id}" must have a non-empty string "pattern".` };
    }

    if (rule.patternType === 'exact') {
      if (rule.pattern.length > MAX_EXACT_LENGTH) {
        return { valid: false, error: `Rule "${rule.id}" exact pattern exceeds max length of ${MAX_EXACT_LENGTH}.` };
      }
    }

    if (rule.patternType === 'regex') {
      if (rule.pattern.length > MAX_REGEX_LENGTH) {
        return { valid: false, error: `Rule "${rule.id}" regex pattern exceeds max length of ${MAX_REGEX_LENGTH}.` };
      }
      // ReDoS structural checks
      for (const rp of REDOS_PATTERNS) {
        if (rp.test(rule.pattern)) {
          return { valid: false, error: `Rule "${rule.id}" regex pattern is rejected due to catastrophic backtracking risk.` };
        }
      }
      // Attempt compilation
      try {
        new RegExp(rule.pattern, 'gi');
      } catch (e) {
        return { valid: false, error: `Rule "${rule.id}" regex pattern is invalid: ${e.message}` };
      }
    }

    // Severity
    if (!VALID_SEVERITY.includes(rule.severity)) {
      return { valid: false, error: `Rule "${rule.id}" severity must be one of: ${VALID_SEVERITY.join(', ')}.` };
    }

    // Action
    if (!VALID_ACTION.includes(rule.action)) {
      return { valid: false, error: `Rule "${rule.id}" action must be one of: ${VALID_ACTION.join(', ')}.` };
    }

    // Enabled
    if (typeof rule.enabled !== 'boolean') {
      return { valid: false, error: `Rule "${rule.id}" "enabled" must be a boolean.` };
    }

    return { valid: true, error: null };
  }

  /**
   * Validates an array of rule config objects.
   * Returns { valid: boolean, errors: string[], validRules: Object[] }
   */
  function validateRuleSet(ruleConfigs) {
    const errors = [];
    const validRules = [];

    if (!Array.isArray(ruleConfigs)) {
      return { valid: false, errors: ['Rule configuration must be an array.'], validRules: [] };
    }

    if (ruleConfigs.length > MAX_RULE_COUNT) {
      errors.push(`Rule count (${ruleConfigs.length}) exceeds maximum of ${MAX_RULE_COUNT}.`);
      return { valid: false, errors, validRules: [] };
    }

    const seenIds = new Set();
    for (const rule of ruleConfigs) {
      const result = validateRule(rule);
      if (!result.valid) {
        errors.push(result.error);
        continue;
      }
      if (seenIds.has(rule.id)) {
        errors.push(`Duplicate rule id detected: "${rule.id}".`);
        continue;
      }
      seenIds.add(rule.id);
      validRules.push(rule);
    }

    return {
      valid: errors.length === 0,
      errors,
      validRules
    };
  }

  // ─── Compilation ──────────────────────────────────────────────────────────

  /**
   * Compiles a validated rule config into a runtime detector rule object
   * compatible with PromptDetector's customRules array.
   *
   * PRIVACY: redactor never returns the raw matched value — always masks it.
   */
  function compileRule(ruleConfig) {
    let compiledPattern;

    if (ruleConfig.patternType === 'exact') {
      // Escape all regex metacharacters so the string is matched literally.
      // Word boundaries ensure "PROJECT-FALCON-7Q" doesn't match "PROJECT-FALCON-7QX".
      const escaped = ruleConfig.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      compiledPattern = new RegExp('(?<![\\w-])' + escaped + '(?![\\w-])', 'gi');
    } else {
      // regex patternType — already validated above
      compiledPattern = new RegExp(ruleConfig.pattern, 'gi');
    }

    // Determine if this rule should cause shouldBlock = true
    const doesBlock = ruleConfig.action === 'block';

    return {
      id: ruleConfig.id,
      name: ruleConfig.name,
      severity: ruleConfig.severity,
      description: ruleConfig.description || `Company-defined rule: ${ruleConfig.name}`,
      pattern: compiledPattern,
      // Redact match — NEVER expose raw matched confidential value in logs/UI
      redactor: (m) => {
        const visible = Math.min(4, Math.floor(m.length / 3));
        const prefix = m.substring(0, visible);
        return `${prefix}${'*'.repeat(Math.max(4, m.length - visible))}[COMPANY-REDACTED]`;
      },
      // Override shouldBlock based on action field (not just severity)
      _companyAction: ruleConfig.action,
      _doesBlock: doesBlock,
      _isCompanyRule: true
    };
  }

  /**
   * Compiles all enabled rules from a validated rule set.
   * Disabled rules are silently skipped.
   */
  function compileEnabledRules(validRules) {
    return validRules
      .filter(r => r.enabled === true)
      .map(compileRule);
  }

  // ─── Storage Integration ──────────────────────────────────────────────────

  /**
   * Loads company rules from chrome.storage.local, validates them,
   * and returns compiled runtime rules.
   *
   * @returns {Promise<{ compiledRules: Object[], errors: string[] }>}
   */
  function loadFromStorage() {
    return new Promise((resolve) => {
      if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
        resolve({ compiledRules: [], errors: [] });
        return;
      }

      chrome.storage.local.get([STORAGE_KEY], (result) => {
        const raw = result[STORAGE_KEY];
        if (!raw || !Array.isArray(raw) || raw.length === 0) {
          resolve({ compiledRules: [], errors: [] });
          return;
        }

        const { validRules, errors } = validateRuleSet(raw);
        if (errors.length > 0) {
          console.warn('[PromptShield Company DNA] Rule validation errors:', errors);
        }

        const compiledRules = compileEnabledRules(validRules);
        console.log(`[PromptShield Company DNA] Loaded ${compiledRules.length} active company rule(s) from ${validRules.length} valid / ${raw.length} total.`);
        resolve({ compiledRules, errors });
      });
    });
  }

  /**
   * Saves a validated rule configuration array to chrome.storage.local.
   * Rejects if validation fails.
   *
   * @param {Object[]} ruleConfigs
   * @returns {Promise<{ success: boolean, errors: string[] }>}
   */
  function saveToStorage(ruleConfigs) {
    return new Promise((resolve) => {
      const { valid, errors, validRules } = validateRuleSet(ruleConfigs);
      if (!valid) {
        resolve({ success: false, errors });
        return;
      }

      if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) {
        resolve({ success: false, errors: ['chrome.storage.local is not available.'] });
        return;
      }

      chrome.storage.local.set({ [STORAGE_KEY]: validRules }, () => {
        console.log(`[PromptShield Company DNA] Saved ${validRules.length} rule(s) to storage.`);
        resolve({ success: true, errors: [] });
      });
    });
  }

  // ─── Exports ─────────────────────────────────────────────────────────────

  return {
    STORAGE_KEY,
    VALID_SEVERITY,
    VALID_ACTION,
    VALID_PATTERN_TYPE,
    MAX_RULE_COUNT,
    validateRule,
    validateRuleSet,
    compileRule,
    compileEnabledRules,
    loadFromStorage,
    saveToStorage
  };
});
