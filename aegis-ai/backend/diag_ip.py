import requests
import os
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("HF_API_TOKEN")

# IP of router.huggingface.co (from nslookup)
# Addresses:  108.159.80.125, 108.159.80.102, 108.159.80.16, 108.159.80.107
ip = "108.159.80.125"
url = f"https://{ip}/hf-inference/models/ealvaradob/bert-finetuned-phishing"

print(f"Testing direct IP request to {url} with Host header...")
try:
    # We must set the Host header so the server knows which virtual host we want.
    # We also need to verify=False because the cert will be for router.huggingface.co, not the IP.
    headers = {
        "Authorization": f"Bearer {token}",
        "Host": "router.huggingface.co"
    }
    response = requests.post(url, headers=headers, json={"inputs": "Test"}, timeout=15, verify=False)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Request failed: {e}")

# Try with api-inference but with router path
url2 = "https://api-inference.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing"
print(f"\nTesting URL with resolved domain: {url2}")
try:
    response = requests.post(url2, headers={"Authorization": f"Bearer {token}"}, json={"inputs": "Test"}, timeout=15)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Request failed: {e}")
