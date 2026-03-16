"""
url_service.py — Malicious URL detection engine for AEGIS.AI
No external scorer imports — fully self-contained.
"""

import os
import re
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv
from models.schemas import AnalyzeTextResponse, FlaggedPhrase

load_dotenv()

HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")
HF_URL = "https://router.huggingface.co/hf-inference/models/r3ddkahili/final-complete-malicious-url-model"
HF_TIMEOUT = 8

def get_severity(score):
    if score <= 25: return "LOW"
    if score <= 50: return "MED"
    if score <= 75: return "HIGH"
    return "CRIT"

def fuse_scores(hf_score, structural_score, domain_score, w_hf=0.40, w_kw=0.35, w_pt=0.25):
    raw = w_hf * hf_score + w_kw * structural_score + w_pt * domain_score
    return int(min(max(raw, 0), 100))

SUSPICIOUS_TLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".link",".info",".biz",".work",".online",".site",".website",".space"}
TRUSTED_DOMAINS = {"google.com","microsoft.com","apple.com","amazon.com","facebook.com","twitter.com","instagram.com","linkedin.com","github.com","stackoverflow.com","wikipedia.org","youtube.com","netflix.com","paypal.com"}
LOOKALIKE_PATTERNS = [
    (r"paypa[l1]", "PayPal lookalike — character substitution (l to 1)"),
    (r"amaz[o0]n", "Amazon lookalike — character substitution (o to 0)"),
    (r"g[o0]{2}gle", "Google lookalike — character substitution"),
    (r"micros[o0]ft", "Microsoft lookalike — character substitution"),
    (r"app[l1]e", "Apple lookalike — character substitution"),
    (r"faceb[o0]{2}k", "Facebook lookalike — character substitution"),
    (r"netfl[i1]x", "Netflix lookalike — character substitution"),
    (r"linkedln", "LinkedIn lookalike — ln instead of in"),
]
SUSPICIOUS_PATH_KEYWORDS = [
    ("login",    "Login page in URL — credential harvesting indicator",    "red"),
    ("verify",   "Verification request in URL — phishing pattern",         "red"),
    ("confirm",  "Confirmation request in URL — phishing pattern",         "red"),
    ("account",  "Account reference in URL — phishing pattern",            "amber"),
    ("secure",   "False security claim in URL — trust manipulation",       "amber"),
    ("update",   "Update request in URL — social engineering",             "amber"),
    ("validate", "Validation request in URL — phishing pattern",           "amber"),
    ("banking",  "Banking reference in URL — financial phishing",          "red"),
    ("password", "Password reference in URL — credential theft",           "red"),
    ("signin",   "Sign-in reference in URL — credential harvesting",       "red"),
    ("suspend",  "Suspension threat in URL — fear-based phishing",         "red"),
]
SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.link","tiny.cc","is.gd","buff.ly","rebrand.ly"}

def extract_features(url):
    flagged = []
    score = 0.0
    url_lower = url.lower().strip()
    try:
        parsed = urlparse(url_lower if url_lower.startswith("http") else "http://" + url_lower)
        domain = parsed.netloc or parsed.path.split("/")[0]
        path = parsed.path.lower()
        scheme = parsed.scheme
    except Exception:
        domain = url_lower
        path = ""
        scheme = "http"
    domain_clean = domain.replace("www.", "")

    if scheme == "http":
        score += 10
        flagged.append(FlaggedPhrase(text=scheme+"://", reason="No HTTPS — unencrypted connection", level="amber"))

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain_clean):
        score += 30
        flagged.append(FlaggedPhrase(text=domain_clean, reason="IP address as domain — common malware tactic", level="red"))

    if any(s in domain_clean for s in SHORTENERS):
        score += 15
        flagged.append(FlaggedPhrase(text=domain_clean, reason="URL shortener — hides true destination", level="amber"))

    for tld in SUSPICIOUS_TLDS:
        if domain_clean.endswith(tld):
            score += 15
            flagged.append(FlaggedPhrase(text=tld, reason=f"Suspicious TLD '{tld}' — commonly abused", level="amber"))
            break

    for pattern, reason in LOOKALIKE_PATTERNS:
        m = re.search(pattern, domain_clean)
        if m:
            score += 25
            flagged.append(FlaggedPhrase(text=m.group(), reason=reason, level="red"))

    subdomain_count = len(domain_clean.split(".")) - 2
    if subdomain_count >= 3:
        score += 15
        flagged.append(FlaggedPhrase(text=domain_clean, reason=f"Excessive subdomains ({subdomain_count}) — phishing pattern", level="amber"))

    digits = sum(c.isdigit() for c in domain_clean.split(".")[0])
    if digits >= 3:
        score += 10
        flagged.append(FlaggedPhrase(text=domain_clean, reason="High digit count in domain — unusual for legitimate sites", level="amber"))

    for keyword, reason, level in SUSPICIOUS_PATH_KEYWORDS:
        if keyword in path:
            score += 12
            flagged.append(FlaggedPhrase(text=keyword, reason=reason, level=level))

    if len(url) > 100:
        score += 10
        flagged.append(FlaggedPhrase(text=f"Length: {len(url)} chars", reason="Excessively long URL — hides malicious destination", level="amber"))

    if domain_clean.count("-") >= 3:
        score += 10
        flagged.append(FlaggedPhrase(text=domain_clean, reason=f"{domain_clean.count('-')} hyphens in domain — suspicious", level="amber"))

    return flagged, min(score, 100.0)

def domain_reputation_score(url):
    for trusted in TRUSTED_DOMAINS:
        if trusted in url.lower():
            return 0.0
    return 30.0

def _call_hf(url):
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    resp = requests.post(HF_URL, headers=headers, json={"inputs": url}, timeout=HF_TIMEOUT)
    resp.raise_for_status()
    result = resp.json()
    if isinstance(result, list) and isinstance(result[0], list):
        items = result[0]
    elif isinstance(result, list) and isinstance(result[0], dict):
        items = result
    else:
        raise ValueError("Unexpected HF response format")
    malicious_labels = {"malicious","phishing","malware","defacement","label_1","1"}
    prob = next((item["score"] for item in items if item["label"].lower() in malicious_labels), 0.0)
    confidence = max(item["score"] for item in items)
    return prob, confidence

def analyze_url(url: str) -> AnalyzeTextResponse:
    url = url.strip()
    flagged, structural_score = extract_features(url)
    domain_score = domain_reputation_score(url)
    hf_prob = 0.0
    confidence = 0.0
    fallback = False

    if HF_API_TOKEN:
        try:
            hf_prob, confidence = _call_hf(url)
        except Exception as e:
            print(f"[AEGIS] HF URL model failed ({e}), fallback active")
            fallback = True
    else:
        print("[AEGIS] No HF token — fallback scorer for URL")
        fallback = True

    hf_score = hf_prob * 100

    if fallback:
        final_score = fuse_scores(0, structural_score, domain_score, w_hf=0.0, w_kw=0.65, w_pt=0.35)
        confidence = round(min(0.5 + (final_score / 200), 0.85), 2)
    else:
        final_score = fuse_scores(hf_score, structural_score, domain_score)

    severity = get_severity(final_score)
    verdict = "MALICIOUS" if final_score > 50 else "SAFE"

    if final_score > 50 and not flagged:
        flagged.append(FlaggedPhrase(text=url[:60], reason="URL structure matches malicious patterns (model-detected).", level="red"))

    action = (
        "Do not visit this URL. Block at firewall level. If already visited, run malware scan and check for credential exposure."
        if verdict == "MALICIOUS"
        else "URL appears safe. Always verify destination before entering credentials."
    )

    return AnalyzeTextResponse(
        threat_score=final_score,
        severity=severity,
        verdict=verdict,
        confidence=confidence,
        flagged_phrases=flagged,
        recommended_action=action,
    )