# Aegis Security Decision Model Blueprint

## Core Philosophy
The Aegis Guardrail engine operates on an **evidence-based** architecture. No payload is punished with a high-risk score or a blocking action unless explicitly backed by a concrete security indicator (heuristic, regex, ML classification, or URL scanning).

## Axis 1: Risk Score (0.0 to 1.0)
The risk score represents the *cumulative likelihood of harm*. It is calculated by summing the severity values of triggered indicators.

- **0.0**: Baseline. No indicators triggered.
- **+0.2 - 0.3**: PII Redaction triggered (Low severity exfiltration risk, auto-sanitized).
- **+0.4 - 0.9**: Injection Heuristic Keyword matched.
- **+ML_SCORE (if > 0.60)**: AI Intent Classifier flagged semantic threat.
- **+0.9**: URL Sandbox flagged malicious domain.
- **+FILE_ML_SCORE (if > 0.60)**: File scanner detected indirect prompt injection.

*Constraint Check:* If `len(indicators) == 0`, `risk_score` MUST equal `0.0`.

## Axis 2: Confidence (0.0 to 1.0)
Confidence represents the *certainty of the classification engine*, not the severity of the threat.
- **SAFE (0.95)**: High confidence in the absence of indicators.
- **LOW (0.85)**: Moderate confidence, usually PII auto-redaction.
- **MEDIUM (0.85)**: Moderate confidence, usually ML semantic flags or edge-case heuristics.
- **HIGH (0.90)**: Strong confidence, explicit injection heuristics triggered.
- **CRITICAL (0.95)**: Extreme confidence, malicious URLs or deep indirect injection detected.

## Axis 3: Classification & Action Matrix

| Risk Score Range | Classification | Default Action | Action Override Condition |
|------------------|----------------|----------------|---------------------------|
| `0.0` | **SAFE** | `ALLOWED` | N/A |
| `< 0.4` | **LOW** | `ALLOWED` | `SANITIZED` (if PII redacted) |
| `< 0.7` | **MEDIUM** | `WARNED` | `SANITIZED` (if regex neutralized threat) |
| `< 0.9` | **HIGH** | `BLOCKED` | `SANITIZED` (if all threats successfully stripped) |
| `>= 0.9` | **CRITICAL** | `BLOCKED` | `SANITIZED` (rarely applicable to severe payloads) |

## Implementation Rules
1. **Never Fail Closed without Evidence**: A payload cannot default to a `WARNED` or `BLOCKED` state simply due to model uncertainty.
2. **Deterministic Fallbacks**: If ML crashes, the system falls back to Regex and Heuristics.
3. **Traceability**: Every fraction of the `risk_score` must have a corresponding string pushed to the `threat_reasons` array. This is strictly enforced at the end of the pipeline.
