# Runbook: Public S3 Bucket

**Triggers:** DET-05 (PutBucketPolicy/PutBucketAcl public), scanner SEC-01, GuardDuty/Macie or external report.
**Severity:** Critical if data is sensitive; High otherwise. **ATT&CK:** T1537, T1567 exfiltration paths.

## 1. Triage (10 min)
- Which bucket, what changed, who changed it (DET-05 Athena query), and when?
- Classify the data: object listing + tags; was any object actually READ by outsiders?
  Check S3 server-access logs / CloudTrail data events for `GetObject` from unknown IPs.
- Was the change legitimate (static website launch)? Confirm with the bucket owner before assuming malice.

## 2. Containment
- Block public access immediately: `lambda/remediate.py` action `block_s3_public`
  (enables all four BlockPublicAccess flags), or
  `aws s3api put-public-access-block --bucket <b> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- Remove/replace the public bucket policy statement; snapshot the malicious policy JSON first (evidence).

## 3. Eradication
- Fix the source: if Terraform, apply the terraform-secure/ pattern (SEC-01 fix) so the
  next deploy doesn't reopen it; if a user did it manually, coach + add an SCP/Config rule
  (`s3-bucket-public-read-prohibited`) to prevent recurrence.

## 4. Recovery
- Verify with the scanner + `aws s3api get-bucket-policy-status` (IsPublic=false) and an
  unauthenticated GET attempt from outside (must return 403).
- If sensitive data was exposed: follow breach-notification policy, rotate any secrets
  that were in the bucket, and expand log review to the full exposure window.

## 5. Evidence preservation
- Save: the public policy/ACL JSON, CloudTrail DET-05 record, S3 access logs for the
  exposure window, and the list of external IPs that performed GetObject.
