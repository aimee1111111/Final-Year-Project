"""
This module performs SHA-256 file hash lookups using the VirusTotal API.

It loads the API key from the .env file, sends the file hash to VirusTotal,
and returns a structured result showing whether the hash was found and what
the overall reputation verdict is. It also handles common API errors such
as missing keys, invalid authentication, rate limits, and unexpected request
failures.
"""
import os
from pathlib import Path
import requests
from dotenv import load_dotenv

# Loads environment variables from the .env file
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# URL template used to query VirusTotal by SHA-256 hash
VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

def lookup_sha256_vt(sha256: str) -> dict:
    """
    Looks up a SHA-256 file hash using the VirusTotal API.

    Parameters:
    - sha256: the SHA-256 hash of the file to check

    Returns:
    - a dictionary containing the lookup result, including whether the file
      was found, the verdict, and detection statistics where available
    """

    # Gets the VirusTotal API key from environment variables
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    # Returns an error if the API key is missing
    if not vt_api_key:
        return {
            "provider": "VirusTotal",
            "found": False,
            "verdict": "error",
            "error": "VIRUSTOTAL_API_KEY not set"
        }

    try:
        # Sends the SHA-256 lookup request to VirusTotal
        r = requests.get(
            VT_URL.format(sha256=sha256),
            headers={"x-apikey": vt_api_key},
            timeout=10,
        )

        # If VirusTotal has no record of the file hash
        if r.status_code == 404:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "unknown"
            }

        # If the API key is missing or invalid
        if r.status_code == 401:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "error",
                "error": "VT 401 Unauthorized (API key missing/invalid)"
            }

        # If the request is blocked due to rate limiting
        if r.status_code == 429:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "error",
                "error": "VT 429 Too Many Requests (rate limit exceeded)"
            }

        # Handles any other non-success HTTP response
        if not r.ok:
            return {
                "provider": "VirusTotal",
                "found": False,
                "verdict": "error",
                "error": f"VT HTTP {r.status_code}: {r.text[:200]}"
            }

        # Extracts the analysis statistics from the JSON response
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        # Determines the final verdict based on the returned statistics
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif harmless > 0:
            verdict = "clean"
        else:
            verdict = "unknown"

        # Returns the final structured result
        return {
            "provider": "VirusTotal",
            "found": True,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        }

    except Exception as e:
        # Handles network errors or unexpected failures
        return {
            "provider": "VirusTotal",
            "found": False,
            "verdict": "error",
            "error": str(e)
        }