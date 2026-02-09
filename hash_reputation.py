import os
from pathlib import Path
import requests
from dotenv import load_dotenv

# load .env file
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

def lookup_sha256_vt(sha256: str) -> dict:
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        return {
            "provider": "VirusTotal",
            "found": False,
            "verdict": "error",
            "error": "VIRUSTOTAL_API_KEY not set"
        }

    try:
        r = requests.get(
            VT_URL.format(sha256=sha256),
            headers={"x-apikey": vt_api_key},
            timeout=10,
        )

        if r.status_code == 404:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "unknown"
            }

        if r.status_code == 401:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "error",
                "error": "VT 401 Unauthorized (API key missing/invalid)"
            }

        if r.status_code == 429:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "error",
                "error": "VT 429 Too Many Requests (rate limit exceeded)"
            }

        if not r.ok:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "error",
                "error": f"VT HTTP {r.status_code}: {r.text[:200]}"
            }

        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif harmless > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        return {          
            "found": True,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        }

    except Exception as e:
        return {
            "provider": "VirusTotal",
            "found": False,
            "verdict": "error",
            "error": str(e)
        }