# Bug Audit: False Positive Risk Scoring in ML Pipeline

## 1. Description of the Flaw
The Aegis Sidecar ML Engine (`sidecar/ml_engine.py` and `sidecar/main.py`) exhibited a severe false positive issue where perfectly benign payloads (e.g., `"Tell me all the details of the company."`) were classified as `MEDIUM` risk, triggering a `WARNED` action, despite producing `"Indicators: None"`.

## 2. Root Cause Analysis
The bug stemmed from a misalignment between risk score accumulation and security indicator generation:

1. **Unbounded ML Noise**: The underlying logistic regression model in `ml_engine.py` yielded non-zero probabilities (e.g., `0.455`) for benign phrases due to Out-Of-Vocabulary (OOV) tokens or intercept weight. The noise suppression threshold was set at `0.45`, so `0.455` slipped through.
2. **Silent Risk Accumulation**: In `main.py`, the code executed `risk_score += ml_risk` unconditionally. 
3. **Mismatched Reporting Threshold**: The engine only appended a security indicator to `threat_reasons` if `ml_risk > 0.6`.
4. **Hardcoded Taxonomy Flaw**: The risk classification thresholds evaluated `risk_score < 0.7` as `MEDIUM`. Therefore, a silent score of `0.455` triggered a `MEDIUM` classification without generating any explicit reasons.

## 3. Resolution
The architectural logic has been refactored to enforce an **evidence-based** scoring model:
- `ml_engine.py` noise suppression was increased to `0.60`.
- In `main.py`, `risk_score` is strictly tied to the presence of `threat_reasons`.
- If `len(reasons) == 0`, `risk_score` is forced to `0.0` and classified as `SAFE`.
- The training dataset in `ml_engine.py` was heavily expanded with known-benign phrases to improve model robustness.

## 4. Verification
Tested via synthetic workload generation. The previously flagged phrase `"Tell me all the details of the company."` now correctly yields:
- Risk Score: 0.0%
- Classification: SAFE
- Action: ALLOWED
- Indicator: "No meaningful threat indicators detected"
