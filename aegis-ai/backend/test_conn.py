import requests
import os
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("HF_API_TOKEN")

urls = [
    "https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing",
    "https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing"
]

print(f"Token found: {'Yes' if token else 'No'}")

for url in urls:
    print(f"\nTesting URL: {url}")
    try:
        response = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json={"inputs": "Test"}, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}")
    except Exception as e:
        print(f"Exception: {str(e)}")
