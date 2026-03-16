import socket
import requests
import os
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("HF_API_TOKEN")

host = "router.huggingface.co"
print(f"Resolving {host}...")
try:
    ip = socket.gethostbyname(host)
    print(f"Resolved to: {ip}")
except Exception as e:
    print(f"DNS Resolution failed: {e}")

url = "https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing"
print(f"\nTesting request to {url}...")
try:
    # Disable verify for a moment just to see if it's a cert/proxy issue
    response = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json={"inputs": "Test"}, timeout=10)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Request failed: {e}")

# Try with api-inference but maybe the router is just a CNAME?
alt_host = "api-inference.huggingface.co"
print(f"\nResolving {alt_host}...")
try:
    ip_alt = socket.gethostbyname(alt_host)
    print(f"Resolved to: {ip_alt}")
except Exception as e:
    print(f"DNS Resolution failed for alt: {e}")
