from services.phishing_service import analyze_phishing_advanced
import json

text = "URGENT: Your PayPal account has been limited. Click here to verify your identity now!"
print(f"Analyzing: {text}\n")

result = analyze_phishing_advanced(text)

print(json.dumps(result, indent=4))
