# Interview Defense Guide — AWS Cloud Detection & IR

## Honest framing
Designed and directed by Gilberto A. Cedillo Soto; implementation AI-assisted,
reviewed and validated with tests (analyzer detects all planted events with zero
false positives on benign records; scanner flags the vulnerable stack and passes
the secure one). Not yet run against a live AWS account — say exactly that.
Never claim "I run this in production" or "I hand-wrote every line from memory."

## 30-second pitch
> "My first SOC project monitored inside an EC2 host. This one covers the other
> half: the AWS control plane. CloudTrail records go to Athena queries and a
> Python analyzer implementing the same seven detections — root usage, console
> login without MFA, IAM changes, open security groups, public S3, launch
> bursts, and CloudTrail tampering — each mapped to MITRE ATT&CK for Cloud.
> Beside it there's a vulnerable-vs-secure Terraform pair with a small IaC
> scanner I wrote plus Checkov config, IR runbooks, and a remediation Lambda
> that can quarantine an instance, block a public bucket, or disable a key —
> dry-run by default."

## Design decisions to defend
1. **Control plane vs host telemetry:** Most cloud breaches are API calls, not
   malware on a host. Host agents miss `AttachUserPolicy`. CloudTrail sees every
   management action — different layer, different detections.
2. **Why GuardDuty alone isn't enough:** GuardDuty is a great managed detector
   but it's a black box, it doesn't cover every misconfiguration event, findings
   still need triage context, and you can't write your own logic into it. My
   detections are transparent, tunable, and portable — and GuardDuty findings
   feed the same runbooks.
3. **Athena (batch) vs EventBridge (real-time):** Athena is cheap and perfect
   for hunting/retro queries, but it's minutes-to-hours latent. Production
   answer: EventBridge patterns on CloudTrail events for DET-01..07 paging,
   Athena for investigation. Knowing the tradeoff is the point.
4. **Remediation safety gates:** Auto-remediation can cause the outage it
   prevents. So: DRY_RUN default, idempotent actions, disable-don't-delete keys
   (evidence + reversibility), quarantine-don't-terminate instances, and human
   approval for high-impact actions in a real account.
5. **Why write a mini-scanner when Checkov exists:** to learn what IaC scanners
   actually check. Production pipelines should use Checkov; the README says so.

## Likely Q&A
- **How do you detect a compromised key?** Correlate DET-01/02/03/06/07 by
  accessKeyId and source IP in Athena; impossible-travel and first-seen-IP
  heuristics; then runbook: disable key, inventory everything it touched.
- **CloudTrail tampering — if they stop logging, how do you know?** The
  StopLogging call itself is logged before logging stops, multi-region trail +
  log-file validation + a second log archive account in production; also alert
  on absence of expected events.
- **First thing you'd add in a real account?** AWS Config rules + Security Hub
  as aggregator, EventBridge real-time rules, and an SCP denying
  cloudtrail:StopLogging for non-break-glass principals.
- **Cost?** Trail is free for management events; Athena is per-TB scanned —
  partition by date; GuardDuty is the line item to watch, with a Budgets alarm.
