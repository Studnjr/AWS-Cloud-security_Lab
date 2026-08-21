# SAFETY — read this before you run anything

This repository deliberately builds **insecure AWS infrastructure**. That is the
point — you cannot learn to find misconfigurations without misconfigurations to
find. Public vulnerable-cloud labs (CloudGoat, TerraGoat, flaws.cloud) work the
same way.

But it means the usual rules apply harder than normal.

## Non-negotiables

**1. Use a dedicated AWS account.** Not your employer's. Not one with anything
real in it. Create a fresh account for this lab and nothing else. If you ever
apply for cloud roles, "I keep my lab in an isolated account" is itself a good
answer.

**2. Never put real data in it.** The S3 bucket in this lab is world-readable by
design. Anything you upload is public to the internet. Use obviously fake data —
there's a `sample-data/` convention below for exactly this.

**3. Destroy when you're done.** Every session ends with:

```bash
terraform destroy
```

Leaving a world-open security group and a public bucket running for weeks is how
lab accounts get co-opted for crypto mining. This is not hypothetical; scanners
find open AWS resources within minutes.

**4. Set a billing alarm before your first `apply`.** Console → Billing →
Budgets → create a $5 budget with an email alert at 50% and 100%. Do this first,
today, before you write any Terraform.

**5. Enable MFA on the root account** and then never use root again. Create an
IAM user for yourself with `AdministratorAccess` and use that.

## Cost control

Resources in this lab are split by cost:

| Tier | Resources | Cost |
|---|---|---|
| Free | S3 (empty), IAM, security groups, VPC | ~$0 |
| Billable | RDS, EC2, NAT Gateway | Real money |

`enable_billable_resources` defaults to **false** in `variables.tf`. With the
default, `terraform apply` creates only free-tier resources. Flip it to `true`
only when you're actively working on that finding, and destroy the same day.

**Never create a NAT Gateway.** It's roughly $32/month and does not stop when
idle. There is none in this lab; don't add one.

## What NOT to do with this repo

- Don't point the scanners at infrastructure you don't own.
- Don't deploy this into an account that shares a VPC, org, or IAM trust
  relationship with anything real.
- Don't commit `terraform.tfstate` — it contains generated credentials in
  plaintext. The `.gitignore` handles this, but check before your first push.
- Don't commit real AWS access keys. Ever. Use `aws configure` or environment
  variables, and consider installing `gitleaks` as a pre-commit hook.

## If you'd rather not deploy at all

You can complete **Phase 1 of this project without an AWS account**, by writing
the Terraform and scanning it statically with Checkov or tfsec. You'll learn the
misconfiguration catalogue and the scanning workflow at zero cost and zero risk.

The tradeoff: static analysis can't teach you how IAM *actually behaves at
runtime*, which is the most valuable and least intuitive part. Deploy eventually.
Just deploy deliberately.
