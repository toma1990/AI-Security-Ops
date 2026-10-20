# AI Security Operations Dashboard

A Python tool that aggregates findings from multiple AWS security 
services, uses AI to correlate and prioritise them, and generates 
a unified dashboard for security triage.

## What I set out to solve

Security teams often work across multiple tools simultaneously - 
GuardDuty for threat detection, IAM audits for identity issues, 
compliance scanners for configuration drift. Switching between 
dashboards makes it easy to miss patterns that only become visible 
when findings from different sources are viewed together.

This project combines findings from multiple sources into one place 
and uses AI to provide a correlation layer - identifying whether 
separate findings might represent a connected threat rather than 
unrelated issues.

## What I implemented

- Collects GuardDuty findings from the last 24 hours
- Runs IAM checks for missing MFA, admin access, and stale keys
- Combines all findings into a single list sorted by severity
- Sends findings to AWS Bedrock for AI-assisted triage and correlation
- Generates a dark-themed HTML dashboard with severity metrics and 
  AI analysis at the top

Note: collection runs sequentially, not in parallel. GuardDuty 
findings are retrieved first, then IAM checks run separately.

## What was actually tested

The tool was run against a live AWS account and processed four findings:

- Two GuardDuty findings - root credential usage from an external IP
- Two IAM findings - admin user without MFA

The AI analysis identified that root credential usage from an external 
IP combined with an unprotected admin account could represent a 
connected threat pattern. This was a test observation based on 
sample GuardDuty findings and a deliberately misconfigured test user - 
it is not a confirmed attack. The AI generated this correlation from 
the findings it received and it should be treated as a hypothesis 
to investigate, not a verified conclusion.

## How AI is used and its limitations

The AI component receives a structured list of findings and returns:
- An overall risk assessment
- Prioritised remediation actions
- Possible correlations between findings
- Quick wins

The AI does not have access to raw logs, network traffic, or any 
data beyond what the collection functions retrieve. Its analysis 
is based entirely on the structured finding summaries passed to it.

Important limitations:
- The model can produce incorrect correlations or miss relevant context
- Remediation suggestions should be verified against the original 
  finding before being acted on
- A high risk assessment from the AI does not confirm an attack 
  has occurred - it indicates findings that warrant investigation
- The current prototype does not automatically execute any AI recommendations
- Deterministic checks identify the findings - the AI summarises 
  and prioritises them, it does not decide whether a finding is valid

## Why I chose this approach

Combining multiple finding sources addresses a real alert fatigue 
problem. A GuardDuty finding and an IAM misconfiguration might look 
unrelated when viewed separately but could be connected. Having a 
human-readable correlation summary at the top of a combined dashboard 
is more useful than separate tools with separate outputs.

Bedrock was chosen over an external API because it keeps all data 
within the AWS environment and uses the same IAM credentials already 
configured for the other tools.

## Collection limitations

- GuardDuty retrieval is capped at 50 findings to control Bedrock costs
- IAM checks cover a limited subset of user risks, not effective 
  permissions across the full account
- Collection errors result in partial results being passed to the AI 
  without a clear indication that the scan was incomplete
- The dashboard does not show the status of each collection source

## What I would change before production

- Show collection status per source so incomplete scans are visible
- Add CloudTrail log analysis as a third finding source
- Paginate GuardDuty results fully rather than capping at 50
- Add a verification step between AI recommendations and any automated action
- Sanitise HTML output before inserting into the dashboard
- Schedule via Lambda so the dashboard updates automatically
