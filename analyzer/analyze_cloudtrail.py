#!/usr/bin/env python3
"""
analyze_cloudtrail.py - offline CloudTrail detection analyzer.

Reads a CloudTrail log file (either a bare JSON array of records, or the native
{"Records": [...]} export format), applies the DET-01..DET-07 rule catalog
(same rules as detections/athena-queries.sql), and emits structured alerts:

  {detection_id, title, severity, attack: {tactic, technique},
   event_time, actor, source_ip, region, event_name, evidence}

Usage:
  python3 analyze_cloudtrail.py <log.json> [--out alerts.json]
  ALERT_WEBHOOK_URL=https://... python3 analyze_cloudtrail.py <log.json>

Exit code always 0 on success (alerting tool, not a gate); parse errors exit 2.
"""
import json, os, sys
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

def _get(rec, *path, default=None):
    cur = rec
    for k in path:
        if not isinstance(cur, dict): return default
        cur = cur.get(k, default)
        if cur is default: return default
    return cur

def load_records(path: Path):
    data = json.loads(path.read_text())
    if isinstance(data, list): return data
    if isinstance(data, dict) and isinstance(data.get("Records"), list): return data["Records"]
    raise ValueError("Unsupported format: expected a JSON array or {'Records': [...]}")

def base_alert(rec, det_id, title, severity, tactic, technique, evidence):
    return {
        "detection_id": det_id, "title": title, "severity": severity,
        "attack": {"tactic": tactic, "technique": technique},
        "event_time": rec.get("eventTime"),
        "actor": _get(rec, "userIdentity", "arn") or _get(rec, "userIdentity", "userName") or "unknown",
        "source_ip": rec.get("sourceIPAddress"),
        "region": rec.get("awsRegion"),
        "event_name": rec.get("eventName"),
        "event_source": rec.get("eventSource"),
        "evidence": evidence,
    }

def detect(rec):
    """Return a list of alerts for one CloudTrail record (0, 1, or rarely more)."""
    alerts = []
    name = rec.get("eventName", "")
    source = rec.get("eventSource", "")
    params = rec.get("requestParameters") or {}
    params_str = json.dumps(params)

    # DET-02 Root usage (check first - it contextualizes everything else)
    if _get(rec, "userIdentity", "type") == "Root":
        alerts.append(base_alert(rec, "DET-02", "Root account used", "critical",
                                 "Defense Evasion / Persistence", "T1078.004 Cloud Accounts",
                                 f"Root performed {name} from {rec.get('sourceIPAddress')}"))

    # DET-01 Console login without MFA
    if name == "ConsoleLogin":
        mfa = _get(rec, "additionalEventData", "MFAUsed")
        outcome = _get(rec, "responseElements", "ConsoleLogin") or _get(rec, "additionalEventData", "ConsoleLogin") or "Success"
        if str(mfa).lower() in ("no", "false") and str(outcome).lower() == "success":
            alerts.append(base_alert(rec, "DET-01", "Console sign-in without MFA", "high",
                                     "Initial Access / Persistence", "T1078 Valid Accounts",
                                     "ConsoleLogin succeeded with MFAUsed != Yes"))

    # DET-03 IAM changes
    if source == "iam.amazonaws.com" and name in (
        "AttachUserPolicy", "PutUserPolicy", "CreateUser", "CreatePolicy",
        "PutRolePolicy", "AttachRolePolicy", "CreateAccessKey", "UpdateLoginProfile"):
        alerts.append(base_alert(rec, "DET-03", f"IAM change: {name}", "high",
                                 "Persistence / Privilege Escalation", "T1098 Account Manipulation / T1136.003",
                                 f"{name} params: {params_str[:200]}"))

    # DET-04 SG open ingress
    if name == "AuthorizeSecurityGroupIngress" and "0.0.0.0/0" in params_str:
        alerts.append(base_alert(rec, "DET-04", "Security Group opened to 0.0.0.0/0", "high",
                                 "Defense Evasion / Lateral Movement enabler", "T1021 Remote Services",
                                 f"Ingress params: {params_str[:200]}"))

    # DET-05 S3 public policy/ACL
    if name in ("PutBucketPolicy", "PutBucketAcl") and (
        '"Principal":"*"' in params_str.replace(" ", "") or '"Principal": "*"' in params_str
        or "AllUsers" in params_str or name == "PutBucketAcl" and "public" in params_str.lower()):
        alerts.append(base_alert(rec, "DET-05", "S3 bucket made public", "critical",
                                 "Exfiltration", "T1537 Transfer Data to Cloud Account",
                                 f"{name} params: {params_str[:200]}"))

    # DET-07 CloudTrail tampering
    if name in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"):
        alerts.append(base_alert(rec, "DET-07", f"CloudTrail tampering: {name}", "critical",
                                 "Defense Evasion", "T1562.008 Impair Defenses: Disable Cloud Logs",
                                 f"{name} from {rec.get('sourceIPAddress')}"))
    return alerts

def detect_bursts(records):
    """DET-06: >=5 RunInstances by same actor+region in the file window."""
    from collections import Counter
    counts = Counter()
    first = {}
    for r in records:
        if r.get("eventName") == "RunInstances":
            key = ((_get(r, "userIdentity", "arn") or "unknown"), r.get("awsRegion"))
            counts[key] += 1
            first.setdefault(key, r)
    alerts = []
    for (actor, region), n in counts.items():
        if n >= 5:
            rec = first[(actor, region)]
            a = base_alert(rec, "DET-06", "EC2 launch burst (possible crypto-mining)", "medium",
                           "Impact", "T1496 Resource Hijacking / T1578 Modify Cloud Compute",
                           f"{n} RunInstances by {actor} in {region} within log window")
            a["count"] = n
            alerts.append(a)
    return alerts

def analyze(records):
    alerts = []
    for r in records:
        alerts.extend(detect(r))
    alerts.extend(detect_bursts(records))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(alerts, key=lambda a: (order.get(a["severity"], 9), a.get("event_time") or ""))

def post_webhook(alerts, url):
    if not url or not requests: return
    for a in alerts:
        try:
            requests.post(url, json={"content": f"🚨 [{a['severity'].upper()}] {a['detection_id']} {a['title']} — actor={a['actor']} ip={a['source_ip']}", "alert": a}, timeout=5)
        except Exception as e:
            print(f"webhook failed: {e}", file=sys.stderr)

def main(argv):
    if len(argv) < 2:
        print(__doc__); return 2
    records = load_records(Path(argv[1]))
    alerts = analyze(records)
    payload = json.dumps(alerts, indent=2)
    print(payload)
    out = "alerts.json"
    if "--out" in argv: out = argv[argv.index("--out") + 1]
    Path(out).write_text(payload + "\n")
    post_webhook(alerts, os.getenv("ALERT_WEBHOOK_URL", ""))
    print(f"\n{len(alerts)} alert(s) from {len(records)} record(s) -> {out}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
