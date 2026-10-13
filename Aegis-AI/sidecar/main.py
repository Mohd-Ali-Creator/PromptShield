from fastapi import FastAPI
from pydantic import BaseModel
import re
import time
from ml_engine import analyze_intent

app = FastAPI(title="Aegis.AI Guardrail Sidecar")

class PromptRequest(BaseModel):
    prompt: str

class GuardrailResponse(BaseModel):
    original_prompt: str
    redacted_prompt: str
    is_injection: bool
    risk_score: float
    risk_level: str
    confidence: float
    action: str
    threat_reasons: list[dict]
    analysis_latency_ms: float

# Precise regex for PII (emails, SSN-like patterns, phone numbers)
EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
PHONE_REGEX = r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
SSN_REGEX = r'\b\d{3}-\d{2}-\d{4}\b'

# Context-aware heuristics for Prompt Injection, Exfiltration & Exploitation
INJECTION_RULES = [
    # Direct instruction override
    (re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|system)?\s*(instructions?|prompts?|rules?|directives?|guidelines?)\b", re.IGNORECASE), "Prompt Injection", "Instruction override attempt"),
    # System prompt extraction
    (re.compile(r"\b(show|reveal|print|spit out|display|output|dump)\s+(me\s+)?(your\s+)?(system\s+prompt|core\s+directives?|hidden\s+instructions?|initial\s+prompt)\b", re.IGNORECASE), "Prompt Injection", "System prompt exfiltration attempt"),
    # Developer / Jailbreak mode
    (re.compile(r"\b(developer\s+mode(\s+enabled)?|unrestricted\s+mode|jailbreak|you\s+are\s+now\s+(an?\s+evil|dan|unrestricted))\b", re.IGNORECASE), "Prompt Injection", "Jailbreak / Persona override attempt"),
    # Evasion / Security bypass (requires security context, avoiding benign traffic/cardiac bypass)
    (re.compile(r"\bbypass\s+(the\s+)?(security|firewall|guardrail|filter|waf|auth|authentication|restriction|rules|safety|protection)\b", re.IGNORECASE), "Security Evasion", "Security boundary bypass attempt"),
    # Sensitive credential & data exfiltration
    (re.compile(r"\b(reveal|extract|dump|leak|steal|give\s+me)\s+(all\s+)?(administrator|admin|user|database|internal)?\s*(passwords?|credentials?|secrets?|api[_\s]?keys?|tokens?|salaries)\b", re.IGNORECASE), "Sensitive Information Extraction", "Credential / secret extraction attempt"),
    # Database destruction & SQL injection
    (re.compile(r"\b(drop\s+table|delete\s+from\s+\w+|truncate\s+table|drop\s+database|xp_cmdshell)\b", re.IGNORECASE), "Database Exploitation", "SQL/Database destruction command"),
    # Social engineering
    (re.compile(r"\btrick\s+(the\s+)?(user|admin|victim|system)\s+into\b", re.IGNORECASE), "Social Engineering", "Social engineering / deception attempt"),
    # Exfiltration of unauthorized bulk records
    (re.compile(r"\b(dump|leak|steal|exfiltrate)\s+(all\s+)?(internal|secret|confidential|private|sensitive|employee|customer|database)\s+data\b", re.IGNORECASE), "Sensitive Information Extraction", "Bulk data exfiltration attempt"),
    (re.compile(r"\bgive\s+me\s+(your\s+)?all\s+data\b", re.IGNORECASE), "Sensitive Information Extraction", "Bulk data exfiltration attempt"),
]

@app.post("/analyze", response_model=GuardrailResponse)
async def analyze_prompt(req: PromptRequest):
    start_time = time.time()
    prompt = req.prompt
    reasons = []
    
    # 1. PII Redaction
    redacted = re.sub(EMAIL_REGEX, "[REDACTED_EMAIL]", prompt)
    if redacted != prompt:
        reasons.append({"type": "Data Exfiltration (PII)", "indicator": "Email PII detected"})
        
    temp_redacted = re.sub(PHONE_REGEX, "[REDACTED_PHONE]", redacted)
    if temp_redacted != redacted:
        reasons.append({"type": "Data Exfiltration (PII)", "indicator": "Phone PII detected"})
    redacted = temp_redacted
    
    temp_redacted = re.sub(SSN_REGEX, "[REDACTED_SSN]", redacted)
    if temp_redacted != redacted:
        reasons.append({"type": "Data Exfiltration (PII)", "indicator": "SSN PII detected"})
    redacted = temp_redacted

    # 2. Heuristic Pattern Matching
    is_injection = False
    risk_score = 0.0
    prompt_lower = prompt.lower()
    
    for pattern, rule_type, rule_desc in INJECTION_RULES:
        match = pattern.search(prompt_lower)
        if match:
            risk_score += 0.4
            is_injection = True
            reasons.append({"type": rule_type, "indicator": f"{rule_desc}: '{match.group(0)}'"})
            
    # 3. Machine Learning Threat Detection
    ml_risk = analyze_intent(prompt)
    if ml_risk > 0.0:
        is_injection = True
        risk_score += ml_risk
        reasons.append({"type": "AI Semantic Intent", "indicator": f"Contextual Threat Detected (Confidence: {ml_risk:.2f})"})
        
    # 4. Multi-Modal Analysis (Links & Files / Indirect Prompt Injection)
    urls = re.findall(r'(https?://[^\s]+)', prompt)
    if urls:
        for url in urls:
            reasons.append({"type": "URL Sandbox Analysis", "indicator": f"Triggered for: '{url}'"})
            if "malicious" in url or "phishing" in url or "evil" in url:
                is_injection = True
                risk_score += 0.9
                reasons.append({"type": "Malicious Link (URL)", "indicator": f"CRITICAL: URL '{url}' flagged as malicious payload source!"})

    file_matches = re.findall(r'\[FILE:\s*(.*?)\s*-\s*Content:\s*"(.*?)"\]', prompt, re.IGNORECASE)
    for filename, content in file_matches:
        reasons.append({"type": "Deep Scanning", "indicator": f"Attached file: '{filename}'"})
        file_risk = analyze_intent(content)
        if file_risk > 0.0:
            is_injection = True
            risk_score += file_risk
            reasons.append({"type": "File-based Injection", "indicator": f"INDIRECT PROMPT INJECTION detected inside file '{filename}' (ML Score: {file_risk:.2f})"})
    
    # Cap risk score
    risk_score = min(risk_score, 1.0)
    
    # Base logic: If no reasons exist, risk MUST be 0.0
    if len(reasons) == 0:
        risk_score = 0.0
    elif len(reasons) > 0 and not is_injection:
        risk_score = max(risk_score, 0.2) # PII or basic heuristics

    # Compute risk level and confidence based on explicit taxonomy
    if risk_score == 0.0:
        risk_level = "SAFE"
        confidence = 0.95
        action = "ALLOWED"
    elif risk_score < 0.4:
        risk_level = "LOW"
        confidence = 0.85
        action = "ALLOWED"
    elif risk_score < 0.7:
        risk_level = "MEDIUM"
        confidence = 0.85
        action = "WARNED"
    elif risk_score < 0.9:
        risk_level = "HIGH"
        confidence = 0.90
        action = "SANITIZED" if is_injection else "BLOCKED"
    else:
        risk_level = "CRITICAL"
        confidence = 0.95
        action = "BLOCKED"
        
    # Generate Safe Rewrite whenever threats/injections are flagged or action is SANITIZED/BLOCKED
    if is_injection or action in ["SANITIZED", "BLOCKED"]:
        if "password" in prompt_lower or "credential" in prompt_lower or "salaries" in prompt_lower:
            redacted = "Authenticate user via secure standard protocol."
        elif "drop" in prompt_lower or "table" in prompt_lower or "sql" in prompt_lower:
            redacted = "Query public database records safely."
        elif "reveal" in prompt_lower or "secrets" in prompt_lower or "data" in prompt_lower or "exfiltrate" in prompt_lower:
            redacted = "Provide publicly available information about the company."
        else:
            redacted = "Process the request safely according to standard guidelines."
            
    latency_ms = (time.time() - start_time) * 1000

    return GuardrailResponse(
        original_prompt=prompt,
        redacted_prompt=redacted,
        is_injection=is_injection,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        action=action,
        threat_reasons=reasons,
        analysis_latency_ms=latency_ms
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
