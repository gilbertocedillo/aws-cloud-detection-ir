#!/usr/bin/env python3
"""Tests for analyzer + scanner. Runs under pytest OR standalone:
   python3 tests/test_analyzer_scanner.py  (built-in runner, exit 1 on failure)"""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "analyzer"))
sys.path.insert(0, str(ROOT / "scanner"))
import analyze_cloudtrail as an
import scan_terraform as sc

RECORDS = an.load_records(ROOT / "sample-logs" / "sample-cloudtrail.json")
ALERTS = an.analyze(RECORDS)
IDS = {a["detection_id"] for a in ALERTS}
BENIGN = RECORDS[:5]  # first 5 records are the benign noise block by construction

def test_detects_root_usage():
    assert "DET-02" in IDS

def test_detects_console_login_without_mfa():
    assert "DET-01" in IDS

def test_detects_iam_policy_change():
    assert "DET-03" in IDS

def test_detects_open_security_group():
    assert "DET-04" in IDS

def test_detects_public_s3():
    assert "DET-05" in IDS

def test_detects_cloudtrail_tampering():
    assert "DET-07" in IDS

def test_detects_runinstances_burst():
    assert "DET-06" in IDS
    burst = [a for a in ALERTS if a["detection_id"] == "DET-06"][0]
    assert burst["count"] >= 5 and burst["region"] == "ap-southeast-2"

def test_benign_records_produce_no_alerts():
    assert an.analyze(BENIGN) == [], f"false positives: {an.analyze(BENIGN)}"

def test_alerts_have_attack_and_severity():
    for a in ALERTS:
        assert a["severity"] in ("critical", "high", "medium", "low")
        assert a["attack"]["technique"].startswith("T1")

def test_scanner_flags_vulnerable_stack():
    findings = sc.scan(ROOT / "terraform-vulnerable")
    ids = {f["id"] for f in findings}
    assert {"SEC-01", "SEC-02", "SEC-03", "SEC-04a", "SEC-05a"} <= ids, ids
    for f in findings:
        assert f["remediation"] and f["severity"] and "file" in f

def test_scanner_passes_secure_stack():
    findings = sc.scan(ROOT / "terraform-secure")
    assert findings == [], f"false positives on secure stack: {findings}"

def test_sample_log_is_valid_cloudtrail_shape():
    assert len(RECORDS) >= 10
    for r in RECORDS:
        assert "eventName" in r and "userIdentity" in r

if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"PASS {name}")
        except AssertionError as e:
            failed += 1; print(f"FAIL {name}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
