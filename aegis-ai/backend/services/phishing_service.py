"""
AEGIS.AI — Hybrid Phishing Analysis Service
Combines: 
  1. Local Logistic Regression (Fast/Offline)
  2. HuggingFace BERT Phishing Classifier (Deep/SOTA)
  3. NLP Pattern Analysis (Contextual)
  4. Scam Signature Detection (Rule-based)
"""

import re
import os
import pickle
import math
import requests
from typing import List, Dict, Tuple
from dotenv import load_dotenv

load_dotenv()

HF_API_TOKEN = os.getenv("HF_API_TOKEN")

# ─── SCAM SIGNATURES ──────────────────────────────────────────────────────────
URGENCY_PATTERNS = [
    (r'\b(urgent|urgently)\b', 'Urgency trigger — creates panic to prevent clear thinking', 'red'),
    (r'\b24 hours?\b|\b48 hours?\b|\b72 hours?\b', 'Artificial deadline — classic phishing pressure tactic', 'red'),
    (r'\b(expire[sd]?|expiring)\b', 'Expiry claim — forces immediate action without verification', 'amber'),
    (r'\bimmediately\b|\bright now\b|\bat once\b', 'Immediacy language — suppresses rational decision-making', 'red'),
    (r'\bfinal notice\b|\blast warning\b|\bfinal warning\b', 'Final notice framing — implies severe consequences to force action', 'red'),
]

ACTION_TRAP_PATTERNS = [
    (r'click here|click the link|click below', 'Deceptive CTA — masks actual destination URL', 'red'),
    (r'\bverify your (account|password|identity|information|details)\b', 'Credential harvesting request — legitimate services never ask via email', 'red'),
    (r'\bconfirm your (account|payment|details|information)\b', 'Confirmation trap — used to harvest personal data', 'amber'),
    (r'\bupdate your (payment|billing|credit card|account)\b', 'Payment info phishing — collecting financial data under false pretenses', 'red'),
    (r'\bprovide your\b|\bsubmit your\b|\benter your\b', 'Data harvesting — requesting sensitive info through email is a major red flag', 'amber'),
]

CREDENTIAL_PATTERNS = [
    (r'\bpassword\b', 'Password mention — legitimate services never request passwords via email', 'red'),
    (r'\b(ssn|social security number?|national id)\b', 'SSN/National ID request — never shared over email legitimately', 'red'),
    (r'\b(otp|one[- ]time password|pin|cvv)\b', 'Security code request — banks never ask for OTPs or CVVs via email', 'red'),
    (r'\b(account number|routing number|bank details)\b', 'Banking details request — hallmark of financial phishing', 'red'),
    (r'\bcredit card\b', 'Credit card mention — payment info requests via email are suspicious', 'amber'),
]

IMPERSONATION_PATTERNS = [
    (r'\b(paypal|pay-pal)\b', 'PayPal impersonation — top phishing brand target', 'amber'),
    (r'\b(amazon|amaz0n)\b', 'Amazon impersonation — frequently spoofed in phishing campaigns', 'amber'),
    (r'\b(apple|icloud|itunes)\b', 'Apple impersonation — common credential theft vector', 'amber'),
    (r'\b(microsoft|windows|outlook|office 365)\b', 'Microsoft impersonation — enterprise phishing target', 'amber'),
    (r'\b(irs|income tax|tax refund|hmrc)\b', 'Tax authority impersonation — creates legal fear to force compliance', 'red'),
    (r'\b(netflix|spotify|hulu)\b', 'Streaming service impersonation — payment info harvesting tactic', 'amber'),
    (r'\b(bank|hsbc|chase|wells fargo|citibank|hdfc|sbi|icici)\b', 'Bank impersonation — financial credential theft', 'red'),
    (r'\b(google|gmail|facebook|instagram)\b', 'Social platform impersonation — account takeover attempt', 'amber'),
]

REWARD_SCAM_PATTERNS = [
    (r'\byou (have won|are selected|are chosen|won)\b', 'Lottery/prize scam — nobody randomly wins prizes via email', 'red'),
    (r'\b(free gift|gift card|cash prize|reward)\b', 'Reward lure — used to attract victims into sharing personal data', 'amber'),
    (r'\bclaim your\b', 'Claim framing — creates false entitlement to get user to act', 'amber'),
    (r'\b(million|billion)\b.*\b(dollar|usd|transfer|fund)\b', 'Advance fee fraud (419 scam) pattern detected', 'red'),
    (r'\bprocessing fee\b|\bsmall fee\b|\badmin fee\b', 'Advance fee request — classic Nigerian prince scam tactic', 'red'),
]

SUSPICIOUS_URL_PATTERNS = [
    (r'http[s]?://[^\s]*\.(tk|ml|ga|cf|gq|ru|cc|xyz|work|click|loan)', 'Suspicious TLD detected — commonly used for free phishing domains', 'red'),
    (r'(secure|verify|login|update|account|confirm)-[^\s]+\.(com|net|org)', 'Lookalike domain pattern — mimics legitimate sites with hyphenated prefixes', 'red'),
    (r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'Raw IP address link — legitimate companies never use IP-based URLs', 'red'),
    (r'bit\.ly|tinyurl|t\.co|ow\.ly|short\.|rb\.gy', 'URL shortener — hides actual destination, common in phishing', 'amber'),
]

ALL_PATTERNS = URGENCY_PATTERNS + ACTION_TRAP_PATTERNS + CREDENTIAL_PATTERNS + IMPERSONATION_PATTERNS + REWARD_SCAM_PATTERNS + SUSPICIOUS_URL_PATTERNS

# ─── RECOMMENDATION ENGINE ────────────────────────────────────────────────────
RECOMMENDATIONS = {
    'credential_harvest': {
        'title': 'Credential Harvesting Attempt',
        'action': "DO NOT enter your credentials. Legitimate services never request passwords, OTPs, PINs, or banking details via email. Report this email to your IT/security team and delete it immediately. If you already clicked a link, change your passwords immediately and enable 2FA on all accounts."
    },
    'financial_scam': {
        'title': 'Financial Fraud Attempt',
        'action': "Do not transfer money, pay any fees, or share banking details. Contact your bank directly using the number on your card to verify any suspicious activity. Report to the FTC (reportfraud.ftc.gov) or your local cybercrime authority."
    },
    'impersonation': {
        'title': 'Brand Impersonation Phishing',
        'action': "Do NOT click any links. Instead, open a new browser tab and navigate directly to the official company website to check your account status. Report this email using the 'Report Phishing' option in your email client."
    },
    'advance_fee': {
        'title': 'Advance Fee Fraud (419/Nigerian Scam)',
        'action': "This is a classic advance fee fraud. No such money transfer exists. Do not respond, do not share personal details, and do not send any money. Block the sender and report to your national cybercrime platform."
    },
    'urgency_trap': {
        'title': 'Urgency-Based Social Engineering',
        'action': "Slow down — urgency is the primary weapon in this email. Do not take any action within the email. Verify the claim independently by contacting the organization through their official website or customer support number."
    },
    'prize_scam': {
        'title': 'Lottery/Prize Scam',
        'action': "You did not win a prize. Prize scam emails exist solely to collect personal data or small payments. Do not respond, do not click any links, and do not provide personal information."
    },
    'generic_phishing': {
        'title': 'Phishing Attempt Detected',
        'action': "Do not click any links or download attachments in this email. Do not provide any personal information. Forward this email to your email provider's phishing report service."
    },
    'safe': {
        'title': 'No Significant Threats Detected',
        'action': "This message appears legitimate. However, always apply good email hygiene: verify unexpected requests directly with the sender and avoid clicking embedded links."
    }
}

# ─── MODEL LOADER (LOCAL) ─────────────────────────────────────────────────────
_local_model = None

def get_local_model():
    global _local_model
    if _local_model is not None: return _local_model
    model_path = os.path.join(os.path.dirname(__file__), "..", "ml", "phishing_model.pkl")
    if os.path.exists(model_path):
        try:
            with open(model_path, 'rb') as f:
                _local_model = pickle.load(f)
                return _local_model
        except: pass
    return None

# ─── HUGGINGFACE CLASS (SOTA) ─────────────────────────────────────────────────
def get_hf_prediction(text: str) -> Tuple[float, float]:
    """Hits specialized BERT phishing model on HuggingFace with retry for loading."""
    import time
    if not HF_API_TOKEN: 
        print("DEBUG: No HF_API_TOKEN found in environment")
        return 0.0, 0.0
    
    API_URL = "https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing"
    headers = {
        "Authorization": f"Bearer {HF_API_TOKEN}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AEGIS-AI/1.1"
    }
    
    # Extended retry loop for model cold starts (status 503 or 504)
    # Total wait time could be around 40-60s in worst case.
    max_retries = 5
    for i in range(max_retries):
        try:
            print(f"DEBUG: Hitting HF API at {API_URL} (Attempt {i+1})...")
            # Increase timeout to 30s to allow for cold starts
            response = requests.post(API_URL, headers=headers, json={"inputs": text}, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                print(f"DEBUG: HF API Success: {result}")
                
                # Handle various response formats: [[{}]] or [{}] or {}
                if isinstance(result, list):
                    res = result[0] if isinstance(result[0], list) else result
                else:
                    res = [result]
                
                # Look for phishing label
                phish_items = [d for d in res if d.get('label', '').lower() in ['phishing', 'label_1', '1']]
                if phish_items:
                    # Sort to get highest score if multiple (unlikely)
                    phish_item = max(phish_items, key=lambda x: x.get('score', 0))
                    max_score = max(d.get('score', 0) for d in res) if res else 0.0
                    return float(phish_item['score']), float(max_score)
                return 0.0, 0.0 # Bening or no labels
                
            elif response.status_code in [503, 504]:
                wait_time = 5 + (i * 2) # Incremental backoff
                print(f"DEBUG: Model is loading/busy ({response.status_code}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                print(f"DEBUG: HF API Error {response.status_code}: {response.text}")
                break
        except requests.exceptions.Timeout:
            print(f"DEBUG: HF API Timeout. Model might be loading. Retrying...")
            continue
        except Exception as e:
            print(f"DEBUG: HF API Exception: {str(e)}")
            break
            
    return 0.0, 0.0

# ─── PATTERN & NLP ANALYSIS ───────────────────────────────────────────────────
def analyze_patterns(text: str) -> Tuple[List[Dict], int, str]:
    text_lower = text.lower()
    flagged = []
    pattern_score = 0
    rec_type = 'generic_phishing'
    
    for pattern, reason, level in ALL_PATTERNS:
        matches = re.finditer(pattern, text_lower)
        for match in matches:
            flagged.append({"text": match.group(), "reason": reason, "level": level})
            pattern_score += (18 if level == 'red' else 8)
            
    # Category detection
    cred_match = any(re.search(p[0], text_lower) for p in CREDENTIAL_PATTERNS)
    adv_match = bool(re.search(r'\b(million|billion)\b.*\b(dollar|usd|transfer|fund)\b', text_lower))
    prize_match = any(re.search(p[0], text_lower) for p in REWARD_SCAM_PATTERNS)
    imp_match = any(re.search(p[0], text_lower) for p in IMPERSONATION_PATTERNS)
    urg_match = any(re.search(p[0], text_lower) for p in URGENCY_PATTERNS)

    if cred_match: rec_type = 'credential_harvest'
    elif adv_match: rec_type = 'advance_fee'
    elif prize_match: rec_type = 'prize_scam'
    elif imp_match: rec_type = 'impersonation'
    elif urg_match: rec_type = 'urgency_trap'

    return flagged[:10], min(pattern_score, 100), rec_type

def get_nlp_score(text: str) -> int:
    score = 0
    t = text.lower()
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.25: score += 15
    if text.count('!') >= 3: score += 10
    if re.search(r'\$(\d+)|₹(\d+)|rs\.?(\s*\d+)', t): score += 10
    if re.search(r'\b(dear (customer|user|friend|account holder|sir|madam))\b', t): score += 10
    return min(score, 45)

# ─── MAIN ADVANCED ANALYSIS ───────────────────────────────────────────────────
def analyze_phishing_advanced(text: str) -> dict:
    # 1. HuggingFace Prediction (Weights: 50% if available)
    hf_prob, hf_conf = get_hf_prediction(text)
    
    # 2. Local ML Prediction (Weights: 50% if HF fails, or 30% if HF works)
    local_model = get_local_model()
    local_prob = 0.0
    if local_model:
        try:
            local_prob = local_model.predict_proba([text])[0][1]
        except: pass

    # 3. Patterns & NLP
    flagged_phrases, pattern_score, rec_type = analyze_patterns(text)
    nlp_score = get_nlp_score(text)

    # ── Composite Risk Calculation ──
    if hf_conf > 0.6:
        # Hybrid with SOTA Model
        threat_score = int((hf_prob * 50) + (local_prob * 20) + (pattern_score * 0.2) + (nlp_score * 0.1))
        confidence = hf_conf
        ai_summary_prefix = "HuggingFace BERT model combined with local ML confirms: "
    else:
        # Local-only Fallback
        threat_score = int((local_prob * 60) + (pattern_score * 0.3) + (nlp_score * 0.1))
        confidence = 0.82
        ai_summary_prefix = "Local AI model and scam pattern analysis identifies: "

    threat_score = min(100, threat_score)
    verdict = 'PHISHING' if threat_score > 48 else 'LEGIT'
    severity = 'LOW' if threat_score < 30 else 'MED' if threat_score < 60 else 'HIGH' if threat_score < 85 else 'CRIT'
    
    if verdict == 'LEGIT':
        rec = RECOMMENDATIONS['safe']
        explanation = "No significant phishing indicators were found. The email structure is consistent with legitimate communication."
    else:
        rec = RECOMMENDATIONS.get(rec_type, RECOMMENDATIONS['generic_phishing'])
        explanation = f"{ai_summary_prefix} This email exhibits characteristic signs of social engineering, including {rec_type.replace('_',' ')} tactitcs. We detected {len(flagged_phrases)} high-risk markers."

    return {
        "threat_score": threat_score,
        "severity": severity,
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "flagged_phrases": flagged_phrases,
        "recommended_action": f"[{rec['title']}] {rec['action']}",
        "explanation_summary": explanation,
        "engine_source": "HuggingFace Hybrid Engine" if hf_conf > 0.6 else "Local ML + Rule Engine",
        "analysis_breakdown": {
            "ml_probability": round(max(hf_prob, local_prob), 3),
            "pattern_score": pattern_score,
            "nlp_score": nlp_score
        }
    }
