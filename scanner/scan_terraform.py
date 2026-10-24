#!/usr/bin/env python3
"""
scan_terraform.py - a mini-Checkov for THIS stack (learning tool, see README.md in this folder).

Scans .tf files as text (regex/heuristics, no HCL parser) for the misconfiguration
patterns numbered SEC-01..SEC-05 and emits JSON findings:
  {id, severity, resource, file, line, remediation}

Usage:
  python3 scan_terraform.py <file-or-dir> [--out findings.json]
Exit code: 1 if any high/critical finding, else 0 (CI-friendly).

Known limits (honest): text scanning can miss values built by variables, modules,
or jsonencode nesting edge cases. Real Checkov parses HCL/graph - use it in
production pipelines (config: ../.checkov.yml). This scanner exists to teach the
patterns and to work with zero dependencies.
"""
import json, re, sys
from pathlib import Path

PATTERNS = [
    {
        "id": "SEC-01", "severity": "critical",
        "regex": re.compile(r'acl\s*=\s*"public-read|public-read-write"', re.I),
        "resource": "aws_s3_bucket_acl",
        "remediation": "Remove public ACL; add aws_s3_bucket_public_access_block with all four flags true and use IAM/bucket policies only.",
    },
    {
        "id": "SEC-02", "severity": "high",
        "regex": re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\][^\}]*?from_port\s*=\s*22|from_port\s*=\s*22[^\}]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"', re.S),
        "resource": "aws_security_group ingress",
        "remediation": "Scope SSH (22) to the operator /32 or disable it and use SSM Session Manager.",
    },
    {
        "id": "SEC-03", "severity": "medium",
        "regex": re.compile(r'encrypted\s*=\s*false'),
        "resource": "aws_instance root_block_device / storage",
        "remediation": "Set encrypted = true on all EBS volumes and enable storage encryption.",
    },
    {
        "id": "SEC-04a", "severity": "critical",
        "regex": re.compile(r'Action\s*=\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]|"Action"\s*:\s*"\*"'),
        "resource": "aws_iam_policy",
        "remediation": "Replace wildcard actions with the specific actions the workload needs.",
    },
    {
        "id": "SEC-04b", "severity": "high",
        "regex": re.compile(r'Resource\s*=\s*"\*"|"Resource"\s*:\s*"\*"'),
        "resource": "aws_iam_policy",
        "remediation": "Scope Resource to the specific ARNs (bucket, log group) instead of '*'.",
    },
]

def nearest_resource(text_before: str) -> str:
    m = list(re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', text_before))
    if m:
        last = m[-1]
        return f'{last.group(1)}.{last.group(2)}'
    return "unknown"

def scan_file(path: Path):
    text = path.read_text(errors="ignore")
    findings = []
    for pat in PATTERNS:
        for m in pat["regex"].finditer(text):
            line = text[:m.start()].count("\n") + 1
            findings.append({
                "id": pat["id"], "severity": pat["severity"],
                "resource": nearest_resource(text[:m.start()]),
                "check": pat["resource"], "file": str(path), "line": line,
                "evidence": m.group(0)[:80].replace("\n", " "),
                "remediation": pat["remediation"],
            })
    # SEC-02 block-aware pass: check EACH ingress block on its own - a file may
    # legitimately contain 0.0.0.0/0 on port 443 AND a scoped port 22 block.
    for m in re.finditer(r'ingress\s*\{(.*?)\n\s*\}', text, re.S):
        block = m.group(1)
        if re.search(r'from_port\s*=\s*22', block) and '"0.0.0.0/0"' in block:
            line = text[:m.start()].count("\n") + 1
            findings.append({
                "id": "SEC-02", "severity": "high",
                "resource": nearest_resource(text[:m.start()]),
                "check": "aws_security_group ingress", "file": str(path), "line": line,
                "evidence": "ingress block: port 22 open to 0.0.0.0/0",
                "remediation": "Scope SSH (22) to the operator /32 or disable it and use SSM Session Manager.",
            })
    return findings

def scan(target: Path):
    files = []
    if target.is_file():
        files = [target]
    else:
        files = sorted(target.rglob("*.tf"))
    all_findings, combined = [], ""
    for f in files:
        all_findings.extend(scan_file(f))
        combined += f.read_text(errors="ignore") + "\n"
    # SEC-05: stack-level absence checks (only meaningful for a directory/stack).
    # Match resource DECLARATIONS, not bare words - comments may name the resources.
    def declared(res_type):
        return re.search(r'resource\s+"' + res_type + r'"', combined) is not None
    if files:
        if not declared("aws_cloudtrail"):
            all_findings.append({
                "id": "SEC-05a", "severity": "high", "resource": "aws_cloudtrail (absent)",
                "check": "logging", "file": str(target), "line": 0,
                "evidence": "no aws_cloudtrail resource in stack",
                "remediation": "Enable a multi-region CloudTrail with log-file validation to a dedicated S3 bucket.",
            })
        if not declared("aws_guardduty_detector"):
            all_findings.append({
                "id": "SEC-05b", "severity": "medium", "resource": "aws_guardduty_detector (absent)",
                "check": "threat detection", "file": str(target), "line": 0,
                "evidence": "no aws_guardduty_detector resource in stack",
                "remediation": "Enable GuardDuty (aws_guardduty_detector enable = true).",
            })
        if not declared("aws_s3_bucket_public_access_block") and declared("aws_s3_bucket"):
            all_findings.append({
                "id": "SEC-01b", "severity": "high", "resource": "aws_s3_bucket_public_access_block (absent)",
                "check": "aws_s3_bucket", "file": str(target), "line": 0,
                "evidence": "S3 bucket(s) present but no public access block",
                "remediation": "Add aws_s3_bucket_public_access_block with block_public_acls/policy, ignore_public_acls, restrict_public_buckets = true.",
            })
    # dedupe
    seen, out = set(), []
    for f in all_findings:
        k = (f["id"], f["file"], f["line"])
        if k not in seen:
            seen.add(k); out.append(f)
    return sorted(out, key=lambda x: (x["file"], x["line"], x["id"]))

def main(argv):
    if len(argv) < 2:
        print(__doc__); return 2
    target = Path(argv[1])
    findings = scan(target)
    payload = json.dumps(findings, indent=2)
    if "--out" in argv:
        Path(argv[argv.index("--out") + 1]).write_text(payload + "\n")
    print(payload)
    return 1 if any(f["severity"] in ("high", "critical") for f in findings) else 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
