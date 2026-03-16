import requests
import os
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("HF_API_TOKEN")

url = "https://router.huggingface.co/hf-inference/models/ealvaradob/bert-finetuned-phishing"
print(f"Testing URL: {url}")
try:
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AEGIS-AI/1.0"
    }
    response = requests.post(url, headers=headers, json={"inputs": "Is this a phishing email?"}, timeout=15)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
except Exception as e:
    print(f"Exception: {str(e)}")
