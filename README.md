# AI Security Operations Dashboard

A Python-based security operations tool that aggregates findings 
from multiple AWS security services, correlates them using AI, 
and generates a unified dashboard with prioritised remediation guidance.

## What it does

Pulls security findings from multiple sources in parallel:

- AWS GuardDuty - threat detection findings from the last 24 hours
- IAM security checks - missing MFA, overprivileged users, stale access keys

Feeds all findings into AWS Bedrock (Claude Haiku) which:

- Assesses overall risk level across the environment
- Identifies patterns and correlations across findings from different sources
- Prioritises the top 3 actions by urgency
- Flags quick wins that can be resolved in under 10 minutes

Generates a dark-themed HTML dashboard showing all findings by 
severity with the AI analysis at the top.

## Why I built this

Alert fatigue is one of the biggest problems in security operations. 
A GuardDuty finding and an IAM misconfiguration might look unrelated 
in isolation but could represent a coordinated attack pattern when 
viewed together.

This tool is an attempt to solve that - instead of checking multiple 
dashboards separately, everything feeds into one place and AI provides 
the correlation layer that a tier 1 analyst would otherwise do manually.

## Tech used

- Python 3
- boto3 (AWS SDK)
- AWS GuardDuty
- AWS IAM
- AWS Bedrock (Claude Haiku) for AI correlation and triage

## How to run it

Configure AWS CLI with appropriate permissions, then:

pip install boto3 markdown
python3 security_ops.py

The dashboard HTML file is saved to the reports/ folder.
Open it in any browser to view.

## Example output

The tool correlates findings across sources. In testing it identified 
that root credential usage from an external IP combined with an 
unprotected admin account represented a coordinated attack pattern 
rather than two separate issues - generating a single prioritised 
incident response plan rather than two unrelated alerts.

## What's next

Planning to add:
- CloudTrail log analysis as a third finding source
- SNS alerting when critical findings are detected
- Scheduled Lambda execution so the dashboard updates automatically
- Integration with the automated IR system to trigger response 
  workflows directly from dashboard findings
