# Runbook: Compromised IAM Access Key

**Triggers:** DET-03 (IAM changes from an unusual IP), DET-01/02, GuardDuty `UnauthorizedAccess:IAMUser/*`, or a leaked-key report (GitHub secret scanning, TruffleHog).
**Severity:** Critical until scoped. **ATT&CK:** T1078 Valid Accounts, T1098, T1136.003.

## 1. Triage (15 min)
- Identify the key: `aws iam list-access-keys --user-name <user>` and CloudTrail by `accessKeyId`.
- Run DET-03/DET-07 Athena queries for the window from first suspicious event −24h to now:
  what did the key create, attach, open, or stop?
- Check source IPs against the user's known IPs/VPN; check for `CreateUser`, `CreateAccessKey`
  (persistence), `RunInstances` bursts (DET-06), and S3 policy changes (DET-05).

## 2. Containment
- **Disable, do not delete** the key (evidence + reversibility):
  `lambda/remediate.py` action `disable_access_key` (DRY_RUN=false after approval),
  or `aws iam update-access-key --user-name <u> --access-key-id <id> --status Inactive`.
- Disable any NEW keys/users the attacker created; quarantine instances they launched
  (`quarantine_ec2`), do not terminate them yet.
- Force console password reset + revoke active sessions if the human user is also affected.

## 3. Eradication
- Remove attacker-created IAM users, policies, roles, and SG rules (use the CloudTrail
  inventory from triage as the checklist — every `Create*/Attach*/Authorize*` gets a revert).
- Rotate the legitimate user's credentials; require MFA.

## 4. Recovery
- Issue a new key to the owner out-of-band; monitor DET-01..07 for 7 days with the
  attacker IPs on a watchlist; confirm no residual persistence (login profiles, Lambda
  functions, EventBridge rules created in the window).

## 5. Evidence preservation
- Export the CloudTrail query results (Athena → S3 CSV), GuardDuty findings, and the
  remediation Lambda logs. Record: key id, first/last malicious event, IPs, every
  resource touched, every action taken with timestamps. Never delete the disabled key
  or attacker-created resources until the review closes.
