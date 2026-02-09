import os
import io
import yara
import clamd
import hashlib
import traceback

from hash_reputation import lookup_sha256_vt
from hash_reputation_mb import lookup_sha256_malwarebazaar


# ClamAV (expects a local clamd listening on 3310)
cd = clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310)

# YARA: load ONLY from external rules file
YARA_RULES_PATH = os.environ.get("YARA_RULES_PATH", "rules.yar")

yara_rules = None
try:
    if os.path.exists(YARA_RULES_PATH):
        yara_rules = yara.compile(filepath=YARA_RULES_PATH)
        print(f"[YARA] Rules loaded from: {YARA_RULES_PATH}")
    else:
        print(f"[YARA] Rules file not found at: {YARA_RULES_PATH}. YARA scanning will be disabled.")
except Exception as e:
    print(f"[YARA] Failed to load rules: {e}. YARA scanning will be disabled.")
    yara_rules = None


def scan_with_clamav(data_bytes: bytes) -> dict:
    try:
        stream = io.BytesIO(data_bytes)
        res = cd.instream(stream)
        status, sig = list(res.values())[0]
        if status == "FOUND":
            return {"safe": False, "engine": "ClamAV", "threat": sig}
        return {"safe": True, "engine": "ClamAV"}
    except Exception as e:
        return {"safe": None, "engine": "ClamAV", "error": str(e)}


def scan_with_yara(data_bytes: bytes) -> dict:
    if not yara_rules:
        return {"safe": None, "engine": "YARA", "error": "YARA rules not loaded"}

    try:
        matches = yara_rules.match(data=data_bytes)
        if matches:
            threats = [{"rule": m.rule, "tags": m.tags, "meta": m.meta} for m in matches]
            return {"safe": False, "engine": "YARA", "threats": threats}
        return {"safe": True, "engine": "YARA"}
    except Exception as e:
        return {"safe": None, "engine": "YARA", "error": str(e)}


def _worst_verdict(*verdicts: str) -> str:
    """
    Pick the worst verdict from a list.
    Order: malicious > suspicious > clean > unknown > error
    (You can swap error position if you want errors to "poison" the result.)
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
    try:
        file_obj.stream.seek(0)
        file_data = file_obj.stream.read()
        file_size = len(file_data)

        mime_type = file_obj.content_type or "application/octet-stream"
        sha256 = hashlib.sha256(file_data).hexdigest()

        # local engines
        clamav_result = scan_with_clamav(file_data)
        yara_result = scan_with_yara(file_data)

        threats = []
        scan_results = []

        # ClamAV
        if clamav_result["safe"] is False:
            threats.append(f"ClamAV: {clamav_result['threat']}")
            scan_results.append({"engine": "ClamAV", "status": "threat_detected", "details": clamav_result["threat"]})
        elif clamav_result["safe"] is True:
            scan_results.append({"engine": "ClamAV", "status": "clean"})
        else:
            scan_results.append({"engine": "ClamAV", "status": "error", "error": clamav_result.get("error")})

        # YARA
        if yara_result["safe"] is False:
            for t in yara_result["threats"]:
                rule_name = t["rule"]
                desc = (t.get("meta") or {}).get("description", "No description")
                threats.append(f"YARA: {rule_name} - {desc}")
            scan_results.append({"engine": "YARA", "status": "threat_detected", "details": yara_result["threats"]})
        elif yara_result["safe"] is True:
            scan_results.append({"engine": "YARA", "status": "clean"})
        else:
            scan_results.append({"engine": "YARA", "status": "error", "error": yara_result.get("error")})

        # Hash reputation lookups
        do_hash_lookup = True
        if threats:
            do_hash_lookup = True

        vt_rep = lookup_sha256_vt(sha256) if do_hash_lookup else {"provider": "VirusTotal", "found": False, "verdict": "unknown"}
        mb_rep = lookup_sha256_malwarebazaar(sha256) if do_hash_lookup else {"provider": "MalwareBazaar", "found": False, "verdict": "unknown"}

        # Combine results
        combined_verdict = _worst_verdict(vt_rep.get("verdict"), mb_rep.get("verdict"))

        hash_rep = {
            "sha256": sha256,
            "verdict": combined_verdict,
            "providers": {
                "VirusTotal": vt_rep,
                "MalwareBazaar": mb_rep,
            }
        }

        # Add reputation results to scan_results + threats
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
            # MalwareBazaar “found” is basically malicious
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
            "size_bytes": file_size,
            "mime_type": mime_type,
            "sha256": sha256,
            "hash_reputation": hash_rep,  # now includes both providers
            "size": file_size,
            "type": mime_type,
            "safe": safe,
            "message": message,
            "threats": threats,
            "scan_results": scan_results,
        }

    except Exception as e:
        traceback.print_exc()
        return {
            "filename": getattr(file_obj, "filename", None),
            "safe": False,
            "error": str(e),
            "message": f"Scan failed: {e}",
        }