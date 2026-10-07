# AWS Cloud Security Lab

A deliberately-vulnerable AWS environment, built in Terraform, used to find, exploit, and remediate cloud misconfigurations. Mapped to CIS Benchmarks and MITRE ATT&CK.

> **Note:** This lab intentionally provisions insecure infrastructure for learning. It is deployed in an isolated account and torn down after each session. Do not deploy into a production account.

---

## What this project is

An end-to-end cloud security workflow built from scratch:

1. **Provision** a realistic but vulnerable AWS environment as code (Terraform).
2. **Scan** it for misconfigurations with static analysis (Checkov).
3. **Analyze** the results into proper findings — impact, remediation, and detection.
4. **Exploit** a finding against live infrastructure to prove it is real, not theoretical.

The goal was to practice the actual work of a cloud security / detection role: not just running a scanner, but reasoning about *why* a misconfiguration matters and *how* an attacker uses it.

---

## Tech used

`Terraform` · `AWS` (IAM, S3, VPC, EC2, RDS) · `Checkov` · `AWS CLI` · `PowerShell`

---

## What I did

- Built a Terraform environment of **30+ resources** across IAM, S3, networking, and compute, with intentional misconfigurations planted throughout.
- Ran **Checkov** static analysis across the Terraform and triaged the output separating real risks from scanner noise (e.g. a "secure" bucket failing low-priority hardening checks).
- Wrote **analyst-style findings** for each issue: summary, evidence, impact, remediation-as-code, and detection logic, mapped to CIS and MITRE ATT&CK.
- **Deployed the lab to live AWS and executed a privilege-escalation attack end to end**, then cleaned up all resources (including manually-created ones Terraform does not track).

---

## Key findings

### AWS-001 — Public, enumerable S3 bucket *(Critical)*
An S3 bucket with all four public-access protections disabled and a policy granting `GetObject` + `ListBucket` to `Principal: "*"`. Any anonymous user on the internet can list and download every object — no AWS account or credentials required.
**Fix:** re-enable Public Access Block and remove the public policy statements.

### AWS-013 — IAM privilege escalation via unscoped PassRole *(High)*
A low-privilege "developer" user holds `ec2:RunInstances` and `iam:PassRole` with `Resource: "*"`. Neither permission is dangerous alone, so **no static scanner flags it**. Combined, the user can launch an EC2 instance, attach an **admin** role to it, and read the admin credentials from the instance metadata service — escalating to full administrator.
**Fix:** scope `iam:PassRole` to a specific low-privilege role ARN instead of `*`.

> AWS-013 is the standout finding: a vulnerability invisible to automated tooling, found and exploited through manual analysis of how permissions combine.

---

## What I demonstrated / learned

- **Detection is only half the job.** Scanner output is a starting point; the value is in triaging false positives and explaining real-world impact.
- **Permission composition matters.** The most dangerous flaws (AWS-013) come from combinations that look safe individually the kind only manual review catches.
- **Secure cloud operations.** Isolated lab account, least-privilege IAM, ephemeral infrastructure (build/destroy per session), and budget alarms for cost control.
- **Real cleanup discipline.** Resources created outside Terraform (access keys, manually-launched instances) must be tracked and removed manually — and "stopped" is not "deleted."

---

## Repository structure

```
terraform/vulnerable/    # The insecure environment (IAM, S3, network, compute)
findings/                # Analyst write-ups for each finding
scripts/                 # Scanning helpers
SAFETY.md                # Safe-use rules for the lab
```

---

## Status

- **Complete:** vulnerable environment, static scanning workflow, findings (AWS-001, AWS-013), live exploitation.
- **In progress:** remediated/secure Terraform module (before-and-after), detection engineering with CloudTrail & VPC Flow Logs.
