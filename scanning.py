import os
import io
import time
import hashlib
import traceback

import clamd
import requests

from hash_reputation import lookup_sha256_vt
from hash_reputation_mb import lookup_sha256_malwarebazaar

CLAMD_HOST = os.environ.get("CLAMD_HOST", "clamav")
CLAMD_PORT = int(os.environ.get("CLAMD_PORT", "3310"))
YARA_SERVICE_URL = os.environ.get("YARA_SERVICE_URL", "").rstrip("/")


def _get_clamd_client(retries: int = 15, delay: float = 1.0):
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
    try:
        cd = _get_clamd_client()
        res = cd.instream(io.BytesIO(data_bytes))

        if not res or not isinstance(res, dict):
            return {"safe": None, "engine": "ClamAV", "error": f"unexpected clamd response: {res}"}

        status, sig = next(iter(res.values()))
        if status == "FOUND":
            return {"safe": False, "engine": "ClamAV", "threat": sig}
        if status == "OK":
            return {"safe": True, "engine": "ClamAV"}
        return {"safe": None, "engine": "ClamAV", "error": f"clamd status: {status}, sig: {sig}"}
    except Exception as e:
        return {"safe": None, "engine": "ClamAV", "error": str(e)}


def scan_with_yara(data_bytes: bytes) -> dict:
    if not YARA_SERVICE_URL:
        return {"safe": None, "engine": "YARA", "error": "YARA_SERVICE_URL not set"}

    try:
        files = {"file": ("upload.bin", data_bytes, "application/octet-stream")}
        r = requests.post(f"{YARA_SERVICE_URL}/scan", files=files, timeout=15)
        payload = r.json()

        if r.status_code >= 400:
            return {"safe": None, "engine": "YARA", "error": payload.get("error") or f"HTTP {r.status_code}"}

        return payload
    except requests.Timeout:
        return {"safe": None, "engine": "YARA", "error": "timeout"}
    except Exception as e:
        return {"safe": None, "engine": "YARA", "error": str(e)}


def _worst_verdict(*verdicts: str) -> str:
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
    try:
        file_obj.stream.seek(0)
        file_data = file_obj.stream.read()
        file_size = len(file_data)

        mime_type = file_obj.content_type or "application/octet-stream"
        sha256 = hashlib.sha256(file_data).hexdigest()

        clamav_result = scan_with_clamav(file_data)
        yara_result = scan_with_yara(file_data)

        threats = []
        scan_results = []

        # ClamAV
        if clamav_result.get("safe") is False:
            threats.append(f"ClamAV: {clamav_result.get('threat')}")
            scan_results.append({"engine": "ClamAV", "status": "threat_detected", "details": clamav_result.get("threat")})
        elif clamav_result.get("safe") is True:
            scan_results.append({"engine": "ClamAV", "status": "clean"})
        else:
            scan_results.append({"engine": "ClamAV", "status": "error", "error": clamav_result.get("error")})

        # YARA
        if yara_result.get("safe") is False:
            for t in yara_result.get("threats", []):
                rule_name = t.get("rule")
                desc = (t.get("meta") or {}).get("description", "No description")
                threats.append(f"YARA: {rule_name} - {desc}")
            scan_results.append({"engine": "YARA", "status": "threat_detected", "details": yara_result.get("threats")})
        elif yara_result.get("safe") is True:
            scan_results.append({"engine": "YARA", "status": "clean"})
        else:
            scan_results.append({"engine": "YARA", "status": "error", "error": yara_result.get("error")})

        # Hash reputation
        vt_rep = lookup_sha256_vt(sha256) or {"provider": "VirusTotal", "found": False, "verdict": "unknown"}
        mb_rep = lookup_sha256_malwarebazaar(sha256) or {"provider": "MalwareBazaar", "found": False, "verdict": "unknown"}

        combined_verdict = _worst_verdict(vt_rep.get("verdict"), mb_rep.get("verdict"))
        hash_rep = {
            "sha256": sha256,
            "verdict": combined_verdict,
            "providers": {"VirusTotal": vt_rep, "MalwareBazaar": mb_rep},
        }

        if vt_rep.get("verdict") in ("malicious", "suspicious"):
            threats.append(f"VirusTotal: {vt_rep.get('verdict')} (mal={vt_rep.get('malicious', 0)}, sus={vt_rep.get('suspicious', 0)})")
            scan_results.append({"engine": "VirusTotal", "status": "threat_detected" if vt_rep.get("verdict") == "malicious" else "suspicious", "details": vt_rep})
        elif vt_rep.get("verdict") == "clean":
            scan_results.append({"engine": "VirusTotal", "status": "clean", "details": vt_rep})
        elif vt_rep.get("verdict") == "unknown":
            scan_results.append({"engine": "VirusTotal", "status": "unknown", "details": vt_rep})
        else:
            scan_results.append({"engine": "VirusTotal", "status": "error", "error": vt_rep.get("error")})

        if mb_rep.get("verdict") in ("malicious", "suspicious"):
            threats.append(f"MalwareBazaar: {mb_rep.get('verdict')} (sig={mb_rep.get('signature')})")
            scan_results.append({"engine": "MalwareBazaar", "status": "threat_detected" if mb_rep.get("verdict") == "malicious" else "suspicious", "details": mb_rep})
        elif mb_rep.get("verdict") == "clean":
            scan_results.append({"engine": "MalwareBazaar", "status": "clean", "details": mb_rep})
        elif mb_rep.get("verdict") == "unknown":
            scan_results.append({"engine": "MalwareBazaar", "status": "unknown", "details": mb_rep})
        else:
            scan_results.append({"engine": "MalwareBazaar", "status": "error", "error": mb_rep.get("error")})

        safe = len(threats) == 0
        errors = [r for r in scan_results if r.get("status") == "error"]

        if threats:
            message = "Threats detected!"
        elif errors:
            message = "Scan completed with errors"
            safe = False
        else:
            message = "File is clean"

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
        traceback.print_exc()
        return {"filename": getattr(file_obj, "filename", None), "safe": False, "error": str(e), "message": f"Scan failed: {e}"}