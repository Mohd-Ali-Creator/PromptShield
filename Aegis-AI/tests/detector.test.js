/**
 * PromptShield AI - Detector Automated Test Suite
 * 
 * Comprehensive regression tests verifying detector rule accuracy,
 * severity classifications, STRICT mode blocking decisions, and false positive resistance.
 * 
 * Covers all 11 required test matrix categories:
 * 1. OpenAI-style API-key patterns
 * 2. AWS access-key patterns
 * 3. GitHub token patterns
 * 4. Private-key blocks (RSA, EC, OpenSSH, PKCS#8)
 * 5. Plain-text passwords
 * 6. Database connection strings containing credentials (PostgreSQL, MySQL, MongoDB, Redis)
 * 7. Payment-card numbers that pass Luhn validation
 * 8. SSN-format identifiers according to existing rules
 * 9. Safe placeholders (sk-xxxx, your-api-key-here, etc.)
 * 10. Safe environment references (process.env, os.getenv)
 * 11. Normal coding questions and ordinary text
 * 
 * Runs natively via `node --test tests/detector.test.js`.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// Direct import of the exact extension detector module
const { PromptDetector, defaultDetector, SEVERITY } = require('../extension/content/detector.js');

describe('PromptShield AI - Detection Engine Comprehensive Test Suite', () => {
  const detector = defaultDetector;

  describe('1. OpenAI-Style API Key Patterns (CRITICAL - Must Block in STRICT Mode)', () => {
    it('detects synthetic OpenAI project API key (sk-proj-...)', () => {
      const prompt = 'Please debug this OpenAI code: sk-proj-TEST1234567890abcdef1234567890abcdef12345678';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-002'));

      // Verify redaction: full secret must NOT be visible in snippet
      const v = result.violations.find((v) => v.ruleId === 'SEC-002');
      assert.ok(!v.redactedSnippet.includes('TEST1234567890abcdef1234567890abcdef12345678'));
      assert.ok(v.redactedSnippet.includes('****'));
    });

    it('detects standard synthetic OpenAI API key (sk-...)', () => {
      const prompt = 'My key is sk-TEST1234567890abcdef1234567890abcdef12345678';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-002'));
    });
  });

  describe('2. AWS Access Key Patterns (CRITICAL - Must Block in STRICT Mode)', () => {
    it('detects AWS Access Key ID (AKIA prefix)', () => {
      const prompt = 'AWS credentials: AKIAIOSFODNN7EXAMPLE and bucket name s3://backup';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-003'));
      const v = result.violations.find((v) => v.ruleId === 'SEC-003');
      assert.ok(!v.redactedSnippet.includes('IOSFODNN7EXAMPLE'));
    });

    it('detects temporary AWS Access Key ID (ASIA prefix)', () => {
      const prompt = 'export AWS_ACCESS_KEY_ID=ASIA1234567890ABCDEF';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-003'));
    });

    it('detects AWS IAM Role Key ID (AROA prefix)', () => {
      const prompt = 'Role key: AROA1234567890ABCDEF in assume-role response';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-003'));
    });
  });

  describe('3. GitHub Token Patterns (CRITICAL - Must Block in STRICT Mode)', () => {
    it('detects GitHub Personal Access Token (ghp_ prefix)', () => {
      const prompt = 'curl -H "Authorization: token ghp_TEST1234567890abcdef1234567890abcdef12" https://api.github.com';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-004'));
      const v = result.violations.find((v) => v.ruleId === 'SEC-004');
      assert.ok(!v.redactedSnippet.includes('TEST1234567890abcdef1234567890abcdef12'));
    });

    it('detects GitHub OAuth Token (gho_ prefix)', () => {
      const prompt = 'token: "gho_TEST1234567890abcdef1234567890abcdef12"';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-004'));
    });
  });

  describe('4. Private-Key Certificate Blocks (CRITICAL - Must Block in STRICT Mode)', () => {
    it('detects multiline RSA private key blocks', () => {
      const prompt = `Can you convert this key to PEM?
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y8KxN...[SYNTHETIC TEST KEY CONTENT]...
-----END RSA PRIVATE KEY-----`;
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-001'));
      assert.ok(result.violations[0].redactedSnippet.includes('[REDACTED]'));
      assert.ok(!result.violations[0].redactedSnippet.includes('SYNTHETIC TEST KEY CONTENT'));
    });

    it('detects EC private key blocks', () => {
      const prompt = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEI...[SYNTHETIC EC KEY]...
-----END EC PRIVATE KEY-----`;
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-001'));
    });

    it('detects OpenSSH private key blocks', () => {
      const prompt = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC...[SYNTHETIC OPENSSH KEY]...
-----END OPENSSH PRIVATE KEY-----`;
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-001'));
    });

    it('detects generic PKCS#8 private key blocks', () => {
      const prompt = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7...
-----END PRIVATE KEY-----`;
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-001'));
    });
  });

  describe('5. Plain-Text Passwords (HIGH - Must Block in STRICT Mode)', () => {
    it('detects db_password assignment in code snippets', () => {
      const prompt = 'const config = {\n  db_password: "MySuperSecretProductionPassword99!"\n};';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.HIGH);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-008'));
      const v = result.violations.find((v) => v.ruleId === 'SEC-008');
      assert.ok(!v.redactedSnippet.includes('MySuperSecretProductionPassword99!'));
      assert.ok(v.redactedSnippet.includes('[REDACTED_PASSWORD]'));
    });

    it('detects passwd / password assignment', () => {
      const prompt = 'passwd = "AdminSecret_2026!"';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.HIGH);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-008'));
    });

    it('detects secret_key assignment', () => {
      const prompt = 'secret_key = "SuperAppSecretKey_987654"';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.HIGH);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-008'));
    });
  });

  describe('6. Database Connection Strings Containing Credentials (HIGH - Must Block in STRICT Mode)', () => {
    it('detects PostgreSQL URI containing user credentials', () => {
      const prompt = 'Connection error on: postgres://app_user:SuperPassWord123@prod-db.internal:5432/main_db';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.HIGH);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-007'));
      const v = result.violations.find((v) => v.ruleId === 'SEC-007');
      assert.ok(!v.redactedSnippet.includes('SuperPassWord123'));
      assert.ok(v.redactedSnippet.includes('[REDACTED_PASSWORD]'));
    });

    it('detects MySQL URI containing user credentials', () => {
      const prompt = 'DATABASE_URL="mysql://admin:SecretPass456@db.corp.local:3306/app"';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.HIGH);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-007'));
      const v = result.violations.find((v) => v.ruleId === 'SEC-007');
      assert.ok(!v.redactedSnippet.includes('SecretPass456'));
    });

    it('detects MongoDB URI containing user credentials', () => {
      const prompt = 'mongodb://dbuser:MongoPass789@cluster0.example.net:27017/analytics';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.HIGH);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-007'));
      const v = result.violations.find((v) => v.ruleId === 'SEC-007');
      assert.ok(!v.redactedSnippet.includes('MongoPass789'));
    });

    it('detects Redis URI containing embedded auth credentials', () => {
      const prompt = 'Cache connection: redis://default:AuthToken456@cache.internal:6379/0';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.HIGH);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-007'));
    });

    it('allows database URI without credentials', () => {
      const prompt = 'Connect locally via postgres://localhost:5432/testdb or mongodb://localhost:27017/dev';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });
  });

  describe('7. Payment-Card Numbers (MEDIUM - Audits but DOES NOT Block in STRICT Mode)', () => {
    it('detects Luhn-valid synthetic payment card (spaced format)', () => {
      // 4242 4242 4242 4242 passes the standard Luhn algorithm
      const prompt = 'Test payment using card number: 4242 4242 4242 4242 with expiry 12/28';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.MEDIUM);
      // Policy: STRICT mode only blocks CRITICAL and HIGH severity
      assert.equal(result.shouldBlock, false);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-009'));

      // Check redaction masks the middle digits
      const v = result.violations.find((v) => v.ruleId === 'SEC-009');
      assert.ok(v.redactedSnippet.includes('****'));
    });

    it('detects Luhn-valid synthetic payment card (hyphen format)', () => {
      // 4532-0150-1234-5671 is Luhn-valid
      const prompt = 'Card: 4532-0150-1234-5671';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.MEDIUM);
      assert.equal(result.shouldBlock, false);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-009'));
    });

    it('ignores 16-digit number that fails Luhn checksum', () => {
      // 4242 4242 4242 4243 has check digit 3 instead of 2 (fails Luhn)
      const prompt = 'Order reference ID: 4242 4242 4242 4243';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('ignores repeated trivial digits (0000 0000 0000 0000 and 1111 1111 1111 1111)', () => {
      assert.equal(detector.scan('Card: 0000 0000 0000 0000').hasViolations, false);
      assert.equal(detector.scan('Card: 1111 1111 1111 1111').hasViolations, false);
    });
  });

  describe('8. US Social Security Numbers (MEDIUM - Audits but DOES NOT Block in STRICT Mode)', () => {
    it('detects valid format US SSN (123-45-6789)', () => {
      const prompt = 'Patient SSN is 123-45-6789 in the admission record.';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.MEDIUM);
      // Policy: STRICT mode only blocks CRITICAL and HIGH severity
      assert.equal(result.shouldBlock, false);
      assert.ok(result.violations.some((v) => v.ruleId === 'SEC-010'));

      const v = result.violations.find((v) => v.ruleId === 'SEC-010');
      assert.ok(!v.redactedSnippet.includes('123-45-6789'));
      assert.ok(v.redactedSnippet.includes('****'));
    });

    it('rejects invalid area number 000 (000-12-3456)', () => {
      const prompt = 'SSN: 000-12-3456';
      const result = detector.scan(prompt);
      assert.equal(result.hasViolations, false);
    });

    it('rejects invalid area number 666 (666-12-3456)', () => {
      const prompt = 'SSN: 666-12-3456';
      const result = detector.scan(prompt);
      assert.equal(result.hasViolations, false);
    });

    it('rejects invalid area numbers 900-999 (912-34-5678)', () => {
      const prompt = 'SSN: 912-34-5678';
      const result = detector.scan(prompt);
      assert.equal(result.hasViolations, false);
    });

    it('rejects invalid group number 00 (123-00-4567)', () => {
      const prompt = 'SSN: 123-00-4567';
      const result = detector.scan(prompt);
      assert.equal(result.hasViolations, false);
    });

    it('rejects invalid serial number 0000 (123-45-0000)', () => {
      const prompt = 'SSN: 123-45-0000';
      const result = detector.scan(prompt);
      assert.equal(result.hasViolations, false);
    });

    it('ignores plain 9-digit integers without SSN hyphens', () => {
      const prompt = 'Item SKU number: 123456789';
      const result = detector.scan(prompt);
      assert.equal(result.hasViolations, false);
    });
  });

  describe('9. Safe Placeholders (Must NOT Block & No Violations)', () => {
    it('allows short placeholder sk-xxxx', () => {
      const prompt = 'OpenAI keys begin with sk-xxxx in standard documentation.';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows documentation placeholder your-api-key-here', () => {
      const prompt = 'Set api_key = "your-api-key-here" in config.json';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows underscore placeholder your_api_key_here', () => {
      const prompt = 'auth_token = "your_api_key_here"';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows angle bracket placeholder <your-api-key-here>', () => {
      const prompt = 'openai_api_key = "<your-api-key-here>"';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows repeated x placeholder sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', () => {
      const prompt = 'Example: sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx placeholder', () => {
      const prompt = 'Project key format: sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows placeholder password assignments (your-password-here, replace-me)', () => {
      assert.equal(detector.scan('password = "your-password-here"').shouldBlock, false);
      assert.equal(detector.scan('db_pass = "replace_with_key"').shouldBlock, false);
    });
  });

  describe('10. Safe Environment Variable References (Must NOT Block & No Violations)', () => {
    it('allows JavaScript process.env lookups in password assignments', () => {
      const prompt = 'const password = process.env.DB_PASSWORD;\nconst apiKey = process.env.API_KEY;';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows Python os.environ.get and os.getenv lookups', () => {
      const prompt = `import os
db_password = os.environ.get("DB_PASSWORD")
api_key = os.getenv("API_KEY")
print("Connected")`;
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows template string interpolation like ${process.env.SECRET}', () => {
      const prompt = 'const secret_key = `${process.env.APP_SECRET}`;';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows function call assignments like getPassword()', () => {
      const prompt = 'password = getPassword()';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });
  });

  describe('11. Normal Coding Questions and Ordinary Text (Must NOT Block & No Violations)', () => {
    it('allows standard computer science technical questions', () => {
      const prompt = 'Explain how TCP 3-way handshake operates and how SYN cookies protect against SYN flooding.';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.maxSeverity, SEVERITY.NONE);
      assert.equal(result.shouldBlock, false);
      assert.equal(result.violations.length, 0);
    });

    it('allows TypeScript algorithms and data structures', () => {
      const prompt = `function reverseBinaryTree(root: TreeNode | null): TreeNode | null {
  if (!root) return null;
  const left = reverseBinaryTree(root.left);
  const right = reverseBinaryTree(root.right);
  root.left = right;
  root.right = left;
  return root;
}`;
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows SQL queries and database schemas without passwords', () => {
      const prompt = 'SELECT u.id, u.username, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id;';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows discussions of password hashing algorithms', () => {
      const prompt = 'What is the recommended salt round length when hashing user passwords using bcrypt in Node.js?';
      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, false);
      assert.equal(result.shouldBlock, false);
    });

    it('allows empty strings, whitespace, null, and undefined gracefully', () => {
      assert.equal(detector.scan('').shouldBlock, false);
      assert.equal(detector.scan('   \n\t  ').shouldBlock, false);
      assert.equal(detector.scan(null).shouldBlock, false);
      assert.equal(detector.scan(undefined).shouldBlock, false);
    });
  });

  describe('Combined Multi-Violation Inputs', () => {
    it('handles multiline prompt containing mixed CRITICAL, HIGH, and MEDIUM violations', () => {
      const prompt = `Configuration dump:
AWS_KEY=AKIAIOSFODNN7EXAMPLE
OPENAI=sk-proj-TEST1234567890abcdef1234567890abcdef12345678
db_password = "ProductionPassword99!"
Card: 4242 4242 4242 4242
SSN: 123-45-6789`;

      const result = detector.scan(prompt);

      assert.equal(result.hasViolations, true);
      assert.equal(result.maxSeverity, SEVERITY.CRITICAL);
      assert.equal(result.shouldBlock, true);
      assert.ok(result.violations.length >= 5);

      // Verify all findings have redacted snippets
      for (const v of result.violations) {
        assert.ok(v.redactedSnippet, `Violation ${v.ruleId} must have a redactedSnippet`);
        assert.ok(!v.redactedSnippet.includes('ProductionPassword99!'), 'Password must be redacted');
      }
    });
  });
});
