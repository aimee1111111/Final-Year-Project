import os
import io
import time
import hashlib
import traceback

import clamd
import requests

from hash_reputation import lookup_sha256_vt
from hash_reputation_mb import lookup_sha256_malwarebazaar

"""
This module handles the file scanning logic for a single uploaded file.

It connects to ClamAV for signature-based malware detection, sends the file
to a YARA scanning service for rule-based detection, and checks the file’s
SHA-256 hash against external reputation sources such as VirusTotal and
MalwareBazaar. It then combines all of these results into one final scan
response containing the verdict, message, threat list, and per-engine details.
"""

# Gets the ClamAV host from environment variables, or uses "clamav" by default
CLAMD_HOST = os.environ.get("CLAMD_HOST", "clamav")

# Gets the ClamAV port from environment variables, or uses 3310 by default
CLAMD_PORT = int(os.environ.get("CLAMD_PORT", "3310"))

# Gets the YARA service URL and removes any trailing slash
YARA_SERVICE_URL = os.environ.get("YARA_SERVICE_URL", "").rstrip("/")


def _get_clamd_client(retries: int = 15, delay: float = 1.0):
    """
    Tries to connect to the ClamAV daemon.

    It retries multiple times in case the service is still starting up.
    If all attempts fail, the last error is raised.
    """
    last_err = None

    for _ in range(retries):
        try:
            client = clamd.ClamdNetworkSocket(host=CLAMD_HOST, port=CLAMD_PORT)
            client.ping()
            return client
        except Exception as e:
            last_err = e
            time.sleep(delay)

    raise last_err


def scan_with_clamav(data_bytes: bytes) -> dict:
    """
    Scans file bytes using ClamAV.

    Returns:
    - clean result if no malware is found
    - threat result if ClamAV detects a signature
    - error result if the scan fails or returns an unexpected response
    """
    try:
        cd = _get_clamd_client()

        # Sends the file bytes to ClamAV using an in-memory stream
        res = cd.instream(io.BytesIO(data_bytes))

        # Handles unexpected response formats
        if not res or not isinstance(res, dict):
            return {"safe": None, "engine": "ClamAV", "error": f"unexpected clamd response: {res}"}

        # Extracts the first result from the ClamAV response
        status, sig = next(iter(res.values()))

        if status == "FOUND":
            return {"safe": False, "engine": "ClamAV", "threat": sig}

        if status == "OK":
            return {"safe": True, "engine": "ClamAV"}

        return {"safe": None, "engine": "ClamAV", "error": f"clamd status: {status}, sig: {sig}"}
    except Exception as e:
        return {"safe": None, "engine": "ClamAV", "error": str(e)}


def scan_with_yara(data_bytes: bytes) -> dict:
    """
    Sends file bytes to the external YARA scanning service.

    Returns:
    - a structured YARA result if successful
    - an error object if the service is unavailable or times out
    """
    if not YARA_SERVICE_URL:
        return {"safe": None, "engine": "YARA", "error": "YARA_SERVICE_URL not set"}

    try:
        # Sends the file as multipart form data to the YARA service
        files = {"file": ("upload.bin", data_bytes, "application/octet-stream")}
        r = requests.post(f"{YARA_SERVICE_URL}/scan", files=files, timeout=15)

        payload = r.json()

        # Handles non-success HTTP responses
        if r.status_code >= 400:
            return {"safe": None, "engine": "YARA", "error": payload.get("error") or f"HTTP {r.status_code}"}

        return payload
    except requests.Timeout:
        return {"safe": None, "engine": "YARA", "error": "timeout"}
    except Exception as e:
        return {"safe": None, "engine": "YARA", "error": str(e)}


def _worst_verdict(*verdicts: str) -> str:
    """
    Chooses the highest-risk verdict from a list of verdict strings.

    Risk order:
    malicious > suspicious > clean > unknown > error
    """
    rank = {"malicious": 4, "suspicious": 3, "clean": 2, "unknown": 1, "error": 0}
    best = "unknown"
    best_score = -1

    for v in verdicts:
        if not v:
            continue

        score = rank.get(v, 1)
        if score > best_score:
            best, best_score = v, score

    return best


def scan_single_file(file_obj) -> dict:
    """
    Scans one uploaded file using multiple detection methods.

    Process:
    1. Reads the file content
    2. Calculates the SHA-256 hash
    3. Scans with ClamAV
    4. Scans with YARA
    5. Checks the hash reputation with VirusTotal and MalwareBazaar
    6. Combines all results into one final response

    Returns:
    - a structured result containing filename, size, type, verdict,
      threats, message, and detailed per-engine scan results
    """
    try:
        # Makes sure reading starts from the beginning of the file
        file_obj.stream.seek(0)

        # Reads the file bytes into memory
        file_data = file_obj.stream.read()
        file_size = len(file_data)

        # Gets MIME type, or uses a default binary type if missing
        mime_type = file_obj.content_type or "application/octet-stream"

        # Generates the SHA-256 hash of the file
        sha256 = hashlib.sha256(file_data).hexdigest()

        # Runs local and rule-based scans
        clamav_result = scan_with_clamav(file_data)
        yara_result = scan_with_yara(file_data)

        # Stores detected threat descriptions
        threats = []

        # Stores detailed scan results from each engine
        scan_results = []

        # ClamAV result handling
        if clamav_result.get("safe") is False:
            threats.append(f"ClamAV: {clamav_result.get('threat')}")
            scan_results.append({
                "engine": "ClamAV",
                "status": "threat_detected",
                "details": clamav_result.get("threat")
            })
        elif clamav_result.get("safe") is True:
            scan_results.append({"engine": "ClamAV", "status": "clean"})
        else:
            scan_results.append({
                "engine": "ClamAV",
                "status": "error",
                "error": clamav_result.get("error")
            })

        # YARA result handling
        if yara_result.get("safe") is False:
            for t in yara_result.get("threats", []):
                rule_name = t.get("rule")
                desc = (t.get("meta") or {}).get("description", "No description")
                threats.append(f"YARA: {rule_name} - {desc}")

            scan_results.append({
                "engine": "YARA",
                "status": "threat_detected",
                "details": yara_result.get("threats")
            })
        elif yara_result.get("safe") is True:
            scan_results.append({"engine": "YARA", "status": "clean"})
        else:
            scan_results.append({
                "engine": "YARA",
                "status": "error",
                "error": yara_result.get("error")
            })

        # Looks up the file hash using external reputation sources
        vt_rep = lookup_sha256_vt(sha256) or {
            "provider": "VirusTotal",
            "found": False,
            "verdict": "unknown"
        }

        mb_rep = lookup_sha256_malwarebazaar(sha256) or {
            "provider": "MalwareBazaar",
            "found": False,
            "verdict": "unknown"
        }

        # Chooses the worst verdict between the two reputation providers
        combined_verdict = _worst_verdict(vt_rep.get("verdict"), mb_rep.get("verdict"))

        # Builds a combined reputation summary
        hash_rep = {
            "sha256": sha256,
            "verdict": combined_verdict,
            "providers": {
                "VirusTotal": vt_rep,
                "MalwareBazaar": mb_rep
            },
        }

        # VirusTotal result handling
        if vt_rep.get("verdict") in ("malicious", "suspicious"):
            threats.append(
                f"VirusTotal: {vt_rep.get('verdict')} "
                f"(mal={vt_rep.get('malicious', 0)}, sus={vt_rep.get('suspicious', 0)})"
            )
            scan_results.append({
                "engine": "VirusTotal",
                "status": "threat_detected" if vt_rep.get("verdict") == "malicious" else "suspicious",
                "details": vt_rep
            })
        elif vt_rep.get("verdict") == "clean":
            scan_results.append({"engine": "VirusTotal", "status": "clean", "details": vt_rep})
        elif vt_rep.get("verdict") == "unknown":
            scan_results.append({"engine": "VirusTotal", "status": "unknown", "details": vt_rep})
        else:
            scan_results.append({
                "engine": "VirusTotal",
                "status": "error",
                "error": vt_rep.get("error")
            })

        # MalwareBazaar result handling
        if mb_rep.get("verdict") in ("malicious", "suspicious"):
            threats.append(f"MalwareBazaar: {mb_rep.get('verdict')} (sig={mb_rep.get('signature')})")
            scan_results.append({
                "engine": "MalwareBazaar",
                "status": "threat_detected" if mb_rep.get("verdict") == "malicious" else "suspicious",
                "details": mb_rep
            })
        elif mb_rep.get("verdict") == "clean":
            scan_results.append({"engine": "MalwareBazaar", "status": "clean", "details": mb_rep})
        elif mb_rep.get("verdict") == "unknown":
            scan_results.append({"engine": "MalwareBazaar", "status": "unknown", "details": mb_rep})
        else:
            scan_results.append({
                "engine": "MalwareBazaar",
                "status": "error",
                "error": mb_rep.get("error")
            })

        # File is only considered safe if no threats were found
        safe = len(threats) == 0

        # Collects engine errors separately
        errors = [r for r in scan_results if r.get("status") == "error"]

        # Decides the final message shown to the user
        if threats:
            message = "Threats detected!"
        elif errors:
            message = "Scan completed with errors"
            safe = False
        else:
            message = "File is clean"

        # Returns the full combined scan result
        return {
            "filename": file_obj.filename,
            "sha256": sha256,
            "hash_reputation": hash_rep,
            "size": file_size,
            "type": mime_type,
            "safe": safe,
            "message": message,
            "threats": threats,
            "scan_results": scan_results,
        }

    except Exception as e:
        # Prints the stack trace for debugging
        traceback.print_exc()

        # Returns a failure result if the scan process crashes
        return {
            "filename": getattr(file_obj, "filename", None),
            "safe": False,
            "error": str(e),
            "message": f"Scan failed: {e}"
        }