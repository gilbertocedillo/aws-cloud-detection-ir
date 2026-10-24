# Runbook: EC2 Crypto-Mining (GuardDuty CryptoCurrency Finding)

**Triggers:** GuardDuty `CryptoCurrency:EC2/BitcoinTool.B!DNS` (or `.B`), DET-06 RunInstances burst, billing spike.
**Severity:** Critical (active resource hijack + likely compromised credentials). **ATT&CK:** T1496 Resource Hijacking, T1578.

## 1. Triage (15 min)
- GuardDuty finding details: instance id, DNS domain queried (mining pool), first/last seen.
- DET-06 Athena query: who launched the instance(s), from which IP, in which regions?
  Mining is rarely one instance — search ALL regions for the same actor in the window.
- How did they get in? Correlate: DET-04 (SG opened), DET-03 (key abused), exposed service
  on the instance itself (check the host project aws-n8n-soc-automation alerts).

## 2. Containment
- Quarantine every suspect instance: `lambda/remediate.py` action `quarantine_ec2`
  (swap to quarantine SG). **Do not terminate yet** — disk is evidence.
- Snapshot volumes (EBS snapshot) before any stop/terminate decision.
- Disable the credentials that launched the instances (see ir-compromised-iam-key.md)
  and set an AWS Budgets alert if not present — mining burns money hourly.

## 3. Eradication
- After snapshots + log capture: terminate mining instances, delete attacker SGs/keys,
  remove persistence (cron/systemd on the image is irrelevant once terminated, but
  check sibling instances launched from the same AMI/account in the window).

## 4. Recovery
- Rebuild from a known-clean AMI; patch the entry vector (close SG, rotate keys, enforce MFA).
- Watch billing + GuardDuty for 7 days; mining actors commonly retry with the same keys
  if any credential survived.

## 5. Evidence preservation
- EBS snapshots, GuardDuty finding export, CloudTrail DET-06 results, instance metadata
  (launch time, IAM role, user data), and the DNS/mining-pool indicators for the intel file.
