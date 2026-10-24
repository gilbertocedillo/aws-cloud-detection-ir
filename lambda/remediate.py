"""
remediate.py - AWS IR auto-remediation Lambda (single handler, dispatch by action).

Actions (event.action):
  quarantine_ec2     {instance_id}                  -> swap instance SGs to QUARANTINE_SG_ID
  block_s3_public    {bucket}                       -> PutBucketPublicAccessBlock (all 4 flags)
  disable_access_key {user_name, access_key_id}     -> UpdateAccessKey Status=Inactive (NOT delete:
                                                       preserves evidence + reversible during IR)

Safety:
  - DRY_RUN env (default "true"): logs the API call it WOULD make, changes nothing.
  - Idempotent: re-running an action that is already applied returns already_applied=true.
  - Structured JSON logging on every path (CloudWatch forensics).

Least-privilege IAM for THIS Lambda (attach only this; nothing else):
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid":"QuarantineEC2","Effect":"Allow",
     "Action":["ec2:DescribeInstances","ec2:ModifyInstanceAttribute"],
     "Resource":"arn:aws:ec2:*:*:instance/*"},
    {"Sid":"BlockS3Public","Effect":"Allow",
     "Action":["s3:GetBucketPublicAccessBlock","s3:PutBucketPublicAccessBlock"],
     "Resource":"arn:aws:s3:::*"},
    {"Sid":"DisableKey","Effect":"Allow",
     "Action":["iam:ListAccessKeys","iam:UpdateAccessKey"],
     "Resource":"arn:aws:iam::*:user/*"},
    {"Sid":"OwnLogs","Effect":"Allow",
     "Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],
     "Resource":"arn:aws:logs:*:*:log-group:/aws/lambda/cloud-ir-remediate:*"}
  ]
}
In production, scope the ARNs to the lab account / tagged resources.
"""
import json, os
import boto3
from botocore.exceptions import ClientError

DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"
QUARANTINE_SG = os.getenv("QUARANTINE_SG_ID", "")

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
iam = boto3.client("iam")

def log(event, **fields):
    print(json.dumps({"event": event, **fields}))

def result(action, ok, changed, detail):
    out = {"ok": ok, "action": action, "changed": changed, "dry_run": DRY_RUN, "detail": detail}
    log("remediation_result", **out)
    return out

def quarantine_ec2(instance_id):
    if not QUARANTINE_SG:
        return result("quarantine_ec2", False, False, "QUARANTINE_SG_ID env var not set")
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    inst = desc["Reservations"][0]["Instances"][0]
    current = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    if current == [QUARANTINE_SG]:
        return result("quarantine_ec2", True, False, f"already_applied: {instance_id} already in quarantine SG")
    log("would_modify_instance", instance_id=instance_id, from_groups=current, to_groups=[QUARANTINE_SG])
    if DRY_RUN:
        return result("quarantine_ec2", True, False, f"DRY_RUN: would swap {current} -> [{QUARANTINE_SG}] on {instance_id} (original SGs logged for rollback)")
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[QUARANTINE_SG])
    return result("quarantine_ec2", True, True, f"{instance_id} quarantined; original SGs were {current} (log them for rollback)")

def block_s3_public(bucket):
    try:
        cur = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        if all(cur.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            return result("block_s3_public", True, False, f"already_applied: {bucket} already fully blocked")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
    log("would_block_s3_public", bucket=bucket)
    if DRY_RUN:
        return result("block_s3_public", True, False, f"DRY_RUN: would enable all BlockPublicAccess flags on {bucket}")
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    return result("block_s3_public", True, True, f"{bucket} public access blocked")

def disable_access_key(user_name, access_key_id):
    keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    match = [k for k in keys if k["AccessKeyId"] == access_key_id]
    if not match:
        return result("disable_access_key", False, False, f"key {access_key_id} not found for user {user_name}")
    if match[0].get("Status") == "Inactive":
        return result("disable_access_key", True, False, "already_applied: key already Inactive")
    log("would_disable_key", user_name=user_name, access_key_id=access_key_id)
    if DRY_RUN:
        return result("disable_access_key", True, False, f"DRY_RUN: would set {access_key_id} Inactive for {user_name}")
    iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Inactive")
    return result("disable_access_key", True, True, f"{access_key_id} disabled (Inactive, not deleted - evidence preserved)")

def handler(event, context):
    if isinstance(event, dict) and isinstance(event.get("body"), str):
        try: event = json.loads(event["body"])
        except Exception: pass
    action = (event or {}).get("action", "")
    log("remediation_invoked", action=action, dry_run=DRY_RUN)
    try:
        if action == "quarantine_ec2":
            out = quarantine_ec2(event["instance_id"])
        elif action == "block_s3_public":
            out = block_s3_public(event["bucket"])
        elif action == "disable_access_key":
            out = disable_access_key(event["user_name"], event["access_key_id"])
        else:
            out = result(action or "?", False, False, "unknown action; expected quarantine_ec2|block_s3_public|disable_access_key")
    except KeyError as e:
        out = result(action, False, False, f"missing required field: {e}")
    except ClientError as e:
        out = result(action, False, False, f"AWS error: {e.response['Error']['Code']}")
    return {"statusCode": 200 if out["ok"] else 400,
            "headers": {"Content-Type": "application/json"}, "body": json.dumps(out)}
