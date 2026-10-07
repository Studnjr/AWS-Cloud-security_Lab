# Cloud Security Lab — Misconfiguration Detection & Remediation

A deliberately insecure AWS environment defined in Terraform, a scanning
workflow to find the misconfigurations, and documented findings that fix each
one in code.

The point of this project is not the vulnerable Terraform anyone can write an
open security group. The point is the **findings**: for each misconfiguration,
a writeup that explains the impact honestly, fixes it as code, and discusses how
you'd detect exploitation and how an attacker would evade that detection. That
reasoning is what cloud security roles actually assess.

> ⚠️ **Read [`SAFETY.md`](SAFETY.md) before deploying anything.** This repo builds
> real, internet-exposed, insecure infrastructure. Dedicated account, billing
> alarm, and `terraform destroy` when done — all non-negotiable.

---

## What's here

```
terraform/vulnerable/    the insecure environment (with teaching comments)
terraform/remediated/    the fixed version (you build this — see roadmap)
findings/                one markdown writeup per finding — the real deliverable
  TEMPLATE.md            reusable structure
  AWS-001-*.md           worked example, sets the quality bar
scripts/scan.sh          runs Checkov, tfsec, Prowler
SAFETY.md                read first
```

## Findings catalogue

Each is a self-contained writeup you build from the template. Severities are
starting points — part of your job is deciding whether you agree.

| ID | Finding | Domain | Severity | Deploy cost |
|---|---|---|---|---|
| AWS-001 | Public + enumerable S3 bucket | Storage | Critical | Free |
| AWS-002 | S3 no encryption at rest | Storage | Low* | Free |
| AWS-003 | S3 no versioning | Storage | Medium | Free |
| AWS-004 | S3 no access logging | Storage | Medium | Free |
| AWS-010 | IAM wildcard action + resource | IAM | High | Free |
| AWS-011 | Long-lived access keys | IAM | Medium | Free |
| AWS-012 | Role assumable by any principal | IAM | High | Free |
| AWS-013 | **PassRole privilege escalation chain** | IAM | High | Free |
| AWS-020 | SSH open to 0.0.0.0/0 | Network | High | Free |
| AWS-021 | RDP open to 0.0.0.0/0 | Network | High | Free |
| AWS-022 | Database port open to internet | Network | High | Free |
| AWS-023 | VPC Flow Logs disabled | Network | Medium | Free |
| AWS-030 | RDS publicly accessible | Data | High | **Billable** |
| AWS-031 | RDS unencrypted | Data | Medium | **Billable** |
| AWS-032 | Hardcoded DB credentials | Data | High | **Billable** |
| AWS-034 | EC2 IMDSv1 (SSRF → creds) | Compute | High | **Billable** |

\* AWS-002: S3 has applied default encryption since 2023, so verify whether this
is actually true before rating it. Catching that the scanner and reality
disagree is a genuinely good finding — see below.

**Start with AWS-013.** It's free to deploy, and it's the finding no static
scanner catches, which makes it the most impressive one to demonstrate.

## The workflow (one loop, repeated per finding)

1. **Deploy** (or scan statically): `terraform apply` in an isolated account.
2. **Scan:** `./scripts/scan.sh`. Static scanners (Checkov, tfsec) need no
   account; Prowler needs the live environment.
3. **Confirm manually.** A scanner finding is a claim. Prove it with the AWS CLI
   — an unauthenticated `curl` that returns data beats any severity rating.
4. **Write it up** using `findings/TEMPLATE.md`.
5. **Fix in code** in `terraform/remediated/`, and prove the fix.
6. **`terraform destroy`.**

### When scanners disagree, that's the good part

Checkov, tfsec, and Prowler will not produce identical findings. One flags things
another misses; both flag things that aren't real problems in context (AWS-002).
Reconciling three scanners and explaining the differences is a more valuable
skill than running one write it up as its own short document. Blindly trusting
a single scanner is the exact junior mistake this project lets you avoid.

## Tools you'll install locally

| Tool | Purpose | Account needed |
|---|---|---|
| Terraform | build/destroy the lab | for deploy |
| AWS CLI | manual confirmation | for deploy |
| [Checkov](https://www.checkov.io/) | static IaC scan | no |
| [tfsec](https://github.com/aquasecurity/tfsec) | static IaC scan | no |
| [Prowler](https://github.com/prowler-cloud/prowler) | live CSPM scan | yes |
| [gitleaks](https://github.com/gitleaks/gitleaks) | catch committed secrets | no |

## Roadmap

**Phase 1 — you are here.** Vulnerable environment + scanning workflow +
worked example finding. Your immediate work: install the tools, run the static
scanners (no account needed), and write up AWS-013 by tracing the escalation
chain in `iam.tf`.

**Phase 2 — findings.** Work through the catalogue. ~2–3 sessions each. This is
the bulk of the project and where the learning lives. Aim for depth over
coverage — eight thorough findings beat sixteen shallow ones.

**Phase 3 — remediation module.** Build `terraform/remediated/` as a genuinely
secure equivalent. Re-run the scanners and show a clean report next to the dirty
one. The before/after is your headline portfolio image.

**Phase 4 — detection.** Turn on CloudTrail and VPC Flow Logs, exploit a few
findings yourself, and capture the telemetry. Write detection logic for each.
**This is where this project connects to SOC/detection work** — the
misconfiguration is the cause, the alert is the effect, and you'll have shown
the whole chain. Real attacker traffic against your open SSH port is a bonus
dataset here.

**Phase 5 — writeup.** A blog post on one finding (AWS-013 is the strongest
candidate — few people can explain a PassRole chain clearly) plus a short demo
video. These get read; the code doesn't.

## Resume framing

Once Phase 2 has a handful of findings, this supports bullets like:

> Built an insecure-by-design AWS environment in Terraform and a multi-scanner
> CSPM workflow (Checkov, tfsec, Prowler); documented 12 misconfigurations
> across IAM, S3, and network with impact analysis, code remediation, and
> detection logic mapped to CIS benchmarks and MITRE ATT&CK.

> Demonstrated an IAM privilege-escalation chain (iam:PassRole + ec2:RunInstances
> → administrator) that static analysis does not detect, with CloudTrail-based
> detection and evasion analysis.

The second bullet is the one that gets a follow-up question in an interview.
Make sure you can answer it cold — walk the whole chain from developer
permissions to admin credentials without notes.

## Honest scope note

At a few hours a week this is a multi-month project, and that's fine — depth is
the point. It becomes resume-listable after Phase 2 has ~6 findings, well before
it's "finished". Don't wait for done to start talking about it.
