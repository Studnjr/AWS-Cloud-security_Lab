Summary 
Vulnerability - aws unscopediam:PassRole, which basically passes on the role to a EC2 instance which ultimately helps a low-privilege developer escalate to full admin role .

2. how the attack works
with the RunInstance role, the user launches the EC2 Instance and then assigns roles to the instance i.e the admin role, AWS automatically places the admin role's temporary credentials inside that running server. The server owner logs into the server and read the credentials from the metadata service, once they get their hands on the credentials, they use them from their own machine which makes them admin.
3. exact cause : Unscoped iam:PassRole with the Resource="\*".

4. Remediation:
instead of giving the iam:PassRole the unscoped field Change Resource = "\*" to the ARN of one specific low-privilege role, so PassRole can only pass that role and never the admin role. so that it has a low-privilege role

5. Scanner misses this because the combination of these two permission is normal where an ec2 instance is launched and the aws server is assigned roles.

