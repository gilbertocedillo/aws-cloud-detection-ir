-- ============================================================================
-- CloudTrail Athena detection queries
-- Database/table: cloudtrail_db.cloudtrail_logs (adjust names + date partitions)
-- Partition filter pattern: replace '2026-10-21' window with your range.
-- Each query mirrors a rule in analyzer/analyze_cloudtrail.py (same DET-IDs).
-- ============================================================================

-- DET-01 | Console sign-in WITHOUT MFA
-- ATT&CK: T1078 Valid Accounts
SELECT eventtime, useridentity.arn AS who, sourceipaddress, awsregion,
       json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used
FROM cloudtrail_db.cloudtrail_logs
WHERE eventsource = 'signin.amazonaws.com'
  AND eventname = 'ConsoleLogin'
  AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
  AND date(eventtime) >= DATE '2026-10-14'
ORDER BY eventtime DESC;

-- DET-02 | Root account usage (any API call as root)
-- ATT&CK: T1078.004 Cloud Accounts
SELECT eventtime, eventname, eventsource, sourceipaddress, awsregion
FROM cloudtrail_db.cloudtrail_logs
WHERE useridentity.type = 'Root'
  AND date(eventtime) >= DATE '2026-10-14'
ORDER BY eventtime DESC;

-- DET-03 | IAM policy change / user creation
-- ATT&CK: T1098 Account Manipulation, T1136.003 Create Cloud Account
SELECT eventtime, useridentity.arn AS actor, eventname, sourceipaddress,
       json_extract(requestparameters, '$.policyArn') AS policy_arn,
       json_extract(requestparameters, '$.userName')  AS target_user
FROM cloudtrail_db.cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN ('AttachUserPolicy','PutUserPolicy','CreateUser',
                    'CreatePolicy','PutRolePolicy','AttachRolePolicy',
                    'CreateAccessKey','UpdateLoginProfile')
  AND date(eventtime) >= DATE '2026-10-14'
ORDER BY eventtime DESC;

-- DET-04 | Security Group ingress opened (esp. 0.0.0.0/0)
-- ATT&CK: T1021 Remote Services / exposure enabling T1190
SELECT eventtime, useridentity.arn AS actor, sourceipaddress,
       json_extract(requestparameters, '$.groupId') AS group_id,
       requestparameters
FROM cloudtrail_db.cloudtrail_logs
WHERE eventname = 'AuthorizeSecurityGroupIngress'
  AND requestparameters LIKE '%0.0.0.0/0%'
  AND date(eventtime) >= DATE '2026-10-14'
ORDER BY eventtime DESC;

-- DET-05 | S3 bucket policy / ACL made public
-- ATT&CK: T1537 Transfer Data to Cloud Account / public data exposure
SELECT eventtime, useridentity.arn AS actor, eventname, sourceipaddress,
       json_extract(requestparameters, '$.bucketName') AS bucket,
       requestparameters
FROM cloudtrail_db.cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutBucketPolicy','PutBucketAcl','PutBucketPublicAccessBlock')
  AND (requestparameters LIKE '%"Principal":"*"%' OR requestparameters LIKE '%AllUsers%'
       OR eventname = 'PutBucketAcl')
  AND date(eventtime) >= DATE '2026-10-14'
ORDER BY eventtime DESC;

-- DET-06 | RunInstances burst / unusual region (crypto-mining precursor)
-- ATT&CK: T1578 Modify Cloud Compute Infrastructure, T1496 Resource Hijacking
SELECT awsregion, useridentity.arn AS actor,
       COUNT(*) AS instances_launched, MIN(eventtime) AS first_seen
FROM cloudtrail_db.cloudtrail_logs
WHERE eventname = 'RunInstances'
  AND date(eventtime) >= DATE '2026-10-14'
GROUP BY awsregion, useridentity.arn
HAVING COUNT(*) >= 5
ORDER BY instances_launched DESC;
-- Analyst note: also eyeball any RunInstances where awsregion is outside your
-- approved region list, even at low counts.

-- DET-07 | CloudTrail tampering - DEFENSE EVASION, page immediately
-- ATT&CK: T1562.008 Impair Defenses: Disable Cloud Logs
SELECT eventtime, useridentity.arn AS actor, eventname, sourceipaddress,
       errorcode, requestparameters
FROM cloudtrail_db.cloudtrail_logs
WHERE eventname IN ('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors','DeleteEventDataStore')
  AND date(eventtime) >= DATE '2026-10-14'
ORDER BY eventtime DESC;
