# [ID] — [Short title]

> Copy this file for each finding. The writeup is the portfolio artifact —
> nobody clones your Terraform, but people do read one well-structured finding.
>
> Sections 6 and 7 are the ones that make you look experienced. Anyone can
> report a public bucket. Explaining what you'd break by fixing it, and how an
> attacker evades your fix, is the part almost nobody writes.
>
> Delete this block when you fill the template in.

| | |
|---|---|
| **Finding ID** | AWS-000 |
| **Severity** | Critical / High / Medium / Low / Informational |
| **Status** | Open / Remediated |
| **Affected resource** | `arn:aws:...` |
| **CIS AWS Benchmark** | e.g. 2.1.1 |
| **MITRE ATT&CK** | e.g. T1530 |
| **Detected by** | Prowler / Checkov / manual review |
| **Date** | YYYY-MM-DD |

---

## 1. Summary

Two or three sentences, written for someone who will not read the rest. What is
misconfigured, and what could an attacker do with it? No jargon.

## 2. Evidence

How you found it, with output. Include the scanner finding *and* independent
confirmation — a scanner alone is a claim, not proof.

```bash
# command you ran
```

```
# output, trimmed to what matters
```

Redact your real account ID if you publish this publicly. It isn't a secret
exactly, but it's an unnecessary detail to hand to strangers.

## 3. Reproduction

Numbered steps someone else could follow to confirm it. If you demonstrated
exploitation, show it — an unauthenticated `curl` that returns data is far more
convincing than a scanner rating.

## 4. Impact

Be specific and be honest. Not "this could lead to a breach" but:

- What data or capability is exposed
- Who can reach it (anonymous internet? any AWS account? one specific role?)
- What it chains into next

If the real-world impact is low, **say so**. Over-rating findings is the fastest
way to lose credibility with engineers, and demonstrating calibrated judgement
is more impressive than reporting everything as Critical.

## 5. Remediation

The fix as **code**, not console clicks:

```hcl
# corrected Terraform
```

Include the verification command that proves the fix worked.

## 6. Operational impact of the fix

*What breaks when you apply this?*

Who currently depends on the insecure behaviour? Does this need a maintenance
window? Is there a migration order? What's the rollback?

This section is why security engineers get listened to instead of ignored.

## 7. Detection & evasion

*If you can't fix it immediately, how would you know it was being exploited?*

- What log source would show it (CloudTrail event name, VPC Flow Log pattern)
- What the detection logic would be
- What the false positive sources are
- **How an attacker evades that detection**

The last bullet is the differentiator. Every control has a bypass; knowing yours
is the difference between security theatre and security engineering.

## 8. References

Link AWS documentation, the relevant CIS control, and any public incident where
this exact issue contributed to a breach. Real-world grounding makes a finding
land much harder than a benchmark citation alone.
