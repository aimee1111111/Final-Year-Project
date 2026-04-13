import io
import hashlib
from types import SimpleNamespace

from scanning import scan_single_file


def make_fake_upload(filename="test.txt", content=b"hello world", content_type="text/plain"):
    return SimpleNamespace(
        filename=filename,
        content_type=content_type,
        stream=io.BytesIO(content),
    )


def test_scan_single_file_clean(monkeypatch):
    file_bytes = b"hello world"
    expected_sha256 = hashlib.sha256(file_bytes).hexdigest()

    monkeypatch.setattr(
        "scanning.scan_with_clamav",
        lambda data: {"safe": True, "engine": "ClamAV"}
    )
    monkeypatch.setattr(
        "scanning.scan_with_yara",
        lambda data: {"safe": True, "engine": "YARA"}
    )
    monkeypatch.setattr(
        "scanning.lookup_sha256_vt",
        lambda sha256: {
            "provider": "VirusTotal",
            "found": False,
            "verdict": "unknown"
        }
    )
    monkeypatch.setattr(
        "scanning.lookup_sha256_malwarebazaar",
        lambda sha256: {
            "provider": "MalwareBazaar",
            "found": False,
            "verdict": "unknown"
        }
    )

    fake_file = make_fake_upload(content=file_bytes)
    result = scan_single_file(fake_file)

    assert result["filename"] == "test.txt"
    assert result["sha256"] == expected_sha256
    assert result["size"] == len(file_bytes)
    assert result["type"] == "text/plain"
    assert result["safe"] is True
    assert result["message"] == "File is clean"
    assert result["threats"] == []

    engines = [r["engine"] for r in result["scan_results"]]
    assert "ClamAV" in engines
    assert "YARA" in engines
    assert "VirusTotal" in engines
    assert "MalwareBazaar" in engines


def test_scan_single_file_detects_threats(monkeypatch):
    monkeypatch.setattr(
        "scanning.scan_with_clamav",
        lambda data: {
            "safe": False,
            "engine": "ClamAV",
            "threat": "Eicar-Test-Signature"
        }
    )
    monkeypatch.setattr(
        "scanning.scan_with_yara",
        lambda data: {
            "safe": False,
            "engine": "YARA",
            "threats": [
                {
                    "rule": "SuspiciousMacro",
                    "meta": {"description": "Macro behaviour detected"}
                }
            ]
        }
    )
    monkeypatch.setattr(
        "scanning.lookup_sha256_vt",
        lambda sha256: {
            "provider": "VirusTotal",
            "found": True,
            "verdict": "malicious",
            "malicious": 12,
            "suspicious": 2
        }
    )
    monkeypatch.setattr(
        "scanning.lookup_sha256_malwarebazaar",
        lambda sha256: {
            "provider": "MalwareBazaar",
            "found": True,
            "verdict": "malicious",
            "signature": "Trojan.Agent"
        }
    )

    fake_file = make_fake_upload(filename="bad.exe", content=b"malicious file")
    result = scan_single_file(fake_file)

    assert result["filename"] == "bad.exe"
    assert result["safe"] is False
    assert result["message"] == "Threats detected!"
    assert len(result["threats"]) >= 4

    assert any("ClamAV" in threat for threat in result["threats"])
    assert any("YARA" in threat for threat in result["threats"])
    assert any("VirusTotal" in threat for threat in result["threats"])
    assert any("MalwareBazaar" in threat for threat in result["threats"])