import os
import requests
from dotenv import load_dotenv

# Load variables from .env into environment
load_dotenv()

MB_URL = "https://mb-api.abuse.ch/api/v1/"

def lookup_sha256_malwarebazaar(sha256: str) -> dict:
    mb_key = os.getenv("MALWAREBAZAAR_AUTH_KEY")
    if not mb_key:
        return {
            "provider": "MalwareBazaar",
            "found": False,
            "verdict": "error",
            "error": "MALWAREBAZAAR_AUTH_KEY not set"
        }

    try:
        r = requests.post(
            MB_URL,
            data={"query": "get_info", "hash": sha256},
            headers={"Auth-Key": mb_key},
            timeout=10,
        )

        if r.status_code == 401:
            return {
                "provider": "MalwareBazaar",
                "found": False,
                "verdict": "error",
                "error": "MB 401 Unauthorized (Auth-Key missing/invalid)"
            }

        if not r.ok:
            return {
                "provider": "MalwareBazaar",
                "found": False,
                "verdict": "error",
                "error": f"MB HTTP {r.status_code}: {r.text[:200]}"
            }

        js = r.json()
        status = js.get("query_status")

        if status == "hash_not_found":
            return {"provider": "MalwareBazaar", "found": False, "verdict": "unknown"}

        if status != "ok":
            return {
                "provider": "MalwareBazaar",
                "found": False,
                "verdict": "error",
                "error": f"MB query_status={status}"
            }

        data = js.get("data") or []
        if not data:
            return {"provider": "MalwareBazaar", "found": False, "verdict": "unknown"}

        entry = data[0]
        return {
            "provider": "MalwareBazaar",
            "found": True,
            "verdict": "malicious",
            "file_type": entry.get("file_type"),
            "tags": entry.get("tags"),
        }

    except Exception as e:
        return {
            "provider": "MalwareBazaar",
            "found": False,
            "verdict": "error",
            "error": str(e)
        }