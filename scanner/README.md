# Scanner — mini-Checkov vs. real Checkov (honest comparison)

`scan_terraform.py` is a **zero-dependency teaching scanner**: regex/heuristics over
`.tf` text for the 5 misconfiguration families in this repo (SEC-01…SEC-05), emitting
JSON findings `{id, severity, resource, file, line, remediation}` and a CI exit code.

## Use the real tool in real pipelines

```bash
pip install checkov
checkov -d ../terraform-vulnerable/ --config-file ../.checkov.yml   # fails as expected
checkov -d ../terraform-secure/     --config-file ../.checkov.yml   # passes
```

| | `scan_terraform.py` (this repo) | Checkov |
|---|---|---|
| Coverage | 8 checks, this stack only | 1,000+ policies, AWS/Azure/GCP/K8s |
| Parsing | Regex on raw text | Full HCL/ARM/JSON graph evaluation |
| Variable/module resolution | No — can miss indirect values | Yes |
| Custom policies | Edit the PATTERNS list (Python) | YAML/Python custom policies, org sharing |
| Dependencies | None (stdlib) | pip package + updates |
| Best for | Learning the patterns, offline demos, CI in restricted envs | Production IaC gating |

**Interview line:** "I wrote a small scanner to learn exactly what IaC scanners look
for, then I gate real work with Checkov — my scanner is the study tool, not the
production control."
