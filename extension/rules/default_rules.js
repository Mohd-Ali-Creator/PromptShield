/**
 * PromptShield AI - Default Security Rules Catalog
 * 
 * Provides metadata and descriptions for UI configuration and rule catalogs.
 */

(function (root, factory) {
  if (typeof exports === 'object' && typeof module !== 'undefined') {
    module.exports = factory();
  } else {
    root.PromptShieldRules = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  return [
    {
      id: 'SEC-001',
      name: 'Private Key Block',
      category: 'Cryptographic Secrets',
      severity: 'CRITICAL',
      defaultAction: 'BLOCK',
      description: 'Detects RSA, EC, OpenSSH, and PGP private key headers.'
    },
    {
      id: 'SEC-002',
      name: 'OpenAI API Key',
      category: 'AI Service Credentials',
      severity: 'CRITICAL',
      defaultAction: 'BLOCK',
      description: 'Detects OpenAI platform secret keys (sk-... / sk-proj-...).'
    },
    {
      id: 'SEC-003',
      name: 'AWS Access Key ID',
      category: 'Cloud Credentials',
      severity: 'CRITICAL',
      defaultAction: 'BLOCK',
      description: 'Detects AWS IAM user and STS credentials (AKIA / ASIA).'
    },
    {
      id: 'SEC-004',
      name: 'GitHub Personal Access Token',
      category: 'Developer Credentials',
      severity: 'CRITICAL',
      defaultAction: 'BLOCK',
      description: 'Detects GitHub classic and fine-grained personal access tokens.'
    },
    {
      id: 'SEC-005',
      name: 'Google Cloud API Key',
      category: 'Cloud Credentials',
      severity: 'CRITICAL',
      defaultAction: 'BLOCK',
      description: 'Detects Google Cloud Platform API service keys (AIza...).'
    },
    {
      id: 'SEC-006',
      name: 'Slack Token',
      category: 'SaaS Credentials',
      severity: 'CRITICAL',
      defaultAction: 'BLOCK',
      description: 'Detects Slack bot, user, or OAuth tokens (xoxb/xoxp/xoxa).'
    },
    {
      id: 'SEC-007',
      name: 'Database Connection URI with Credentials',
      category: 'Infrastructure Credentials',
      severity: 'HIGH',
      defaultAction: 'BLOCK',
      description: 'Detects Postgres, MySQL, Mongo, Redis connection URIs with embedded passwords.'
    },
    {
      id: 'SEC-008',
      name: 'Plaintext Password Assignment',
      category: 'Credentials',
      severity: 'HIGH',
      defaultAction: 'BLOCK',
      description: 'Detects code-like assignments containing plaintext passwords or secrets.'
    },
    {
      id: 'SEC-009',
      name: 'Payment Card Number (Luhn Validated)',
      category: 'Financial PII',
      severity: 'MEDIUM',
      defaultAction: 'WARN',
      description: 'Detects 13-19 digit payment cards passing Luhn checksum verification.'
    },
    {
      id: 'SEC-010',
      name: 'US Social Security Number',
      category: 'Personal Identity (PII)',
      severity: 'MEDIUM',
      defaultAction: 'WARN',
      description: 'Detects US Social Security Number patterns.'
    }
  ];
});
