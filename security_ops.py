import boto3
import json
import markdown
import re
from datetime import datetime, timezone, timedelta

# AWS clients
guardduty = boto3.client('guardduty', region_name='eu-west-2')
bedrock = boto3.client('bedrock-runtime', region_name='eu-west-2')
iam = boto3.client('iam', region_name='eu-west-2')

# How far back to pull findings
LOOKBACK_HOURS = 24

# Bedrock model
MODEL_ID = 'eu.anthropic.claude-haiku-4-5-20251001-v1:0'

def get_timestamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def clean_ai_response(text):
    # Strip emoji and convert markdown to HTML
    clean = re.sub(r'[^\x00-\x7F]+', '', text)
    return markdown.markdown(clean)

def get_guardduty_findings():
    # Pull all active findings from GuardDuty
    try:
        detectors = guardduty.list_detectors()
        if not detectors['DetectorIds']:
            return []
        
        detector_id = detectors['DetectorIds'][0]
        
        # Get all findings regardless of severity for full picture
        finding_ids = guardduty.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                'Criterion': {
                    'updatedAt': {
                        'Gte': int((datetime.now(timezone.utc) - 
                                   timedelta(hours=LOOKBACK_HOURS)).timestamp() * 1000)
                    }
                }
            }
        )
        
        if not finding_ids['FindingIds']:
            return []
        
        findings = guardduty.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids['FindingIds'][:50]  # cap at 50 to control costs
        )
        
        return [{
            'Source': 'GuardDuty',
            'Type': f['Type'],
            'Severity': f['Severity'],
            'Description': f['Description'],
            'Time': f['UpdatedAt'],
            'Resource': f.get('Resource', {}).get('ResourceType', 'unknown')
        } for f in findings['Findings']]
        
    except Exception as e:
        print(f"GuardDuty error: {e}")
        return []

def get_iam_findings():
    # Run IAM checks and return findings in standard format
    findings = []
    
    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                
                # Check MFA
                mfa = iam.list_mfa_devices(UserName=username)
                if not mfa['MFADevices']:
                    findings.append({
                        'Source': 'IAM',
                        'Type': 'IAM/NoMFAEnabled',
                        'Severity': 7.0,
                        'Description': f'User {username} has no MFA enabled',
                        'Time': get_timestamp(),
                        'Resource': f'IAMUser/{username}'
                    })
                
                # Check for admin access
                attached = iam.list_attached_user_policies(UserName=username)
                for policy in attached['AttachedPolicies']:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        findings.append({
                            'Source': 'IAM',
                            'Type': 'IAM/AdminAccessAttached',
                            'Severity': 8.0,
                            'Description': f'User {username} has AdministratorAccess policy attached',
                            'Time': get_timestamp(),
                            'Resource': f'IAMUser/{username}'
                        })
                
                # Check access key age
                keys = iam.list_access_keys(UserName=username)
                for key in keys['AccessKeyMetadata']:
                    age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if age > 90:
                        findings.append({
                            'Source': 'IAM',
                            'Type': 'IAM/StaleAccessKey',
                            'Severity': 5.0,
                            'Description': f'User {username} has access key {age} days old',
                            'Time': get_timestamp(),
                            'Resource': f'IAMUser/{username}'
                        })
    
    except Exception as e:
        print(f"IAM error: {e}")
    
    return findings

def ai_triage(all_findings):
    # Use Bedrock to prioritise and contextualise all findings
    if not all_findings:
        return "No findings to analyse - environment looks clean."
    
    # Build a concise summary for the model
    summary = []
    for f in all_findings:
        summary.append(
            f"[{f['Source']}] Severity {f['Severity']} - {f['Type']}: {f['Description']}"
        )
    
    prompt = f"""You are a senior cloud security engineer reviewing findings from multiple 
security tools across an AWS environment.

Findings from the last {LOOKBACK_HOURS} hours:

{chr(10).join(summary)}

Provide:
1. Overall risk assessment (Critical/High/Medium/Low) with one sentence explanation
2. Top 3 priority actions in order of urgency
3. Any patterns or correlations across findings worth noting
4. Quick wins - anything that can be fixed in under 10 minutes

Be direct and specific. This is for a security operations dashboard."""

    try:
        response = bedrock.invoke_model(
            modelId=MODEL_ID,
            body=json.dumps({
                'anthropic_version': 'bedrock-2023-05-31',
                'max_tokens': 1000,
                'messages': [{'role': 'user', 'content': prompt}]
            })
        )
        result = json.loads(response['body'].read())
        return clean_ai_response(result['content'][0]['text'])
    
    except Exception as e:
        print(f"Bedrock error: {e}")
        return "AI triage unavailable"

def generate_dashboard(all_findings, ai_analysis):
    # Generate HTML security operations dashboard
    timestamp = get_timestamp()
    filename = f"reports/secops_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    import os
    os.makedirs('reports', exist_ok=True)
    
    # Count by severity
    critical = [f for f in all_findings if f['Severity'] >= 9.0]
    high = [f for f in all_findings if 7.0 <= f['Severity'] < 9.0]
    medium = [f for f in all_findings if 4.0 <= f['Severity'] < 7.0]
    low = [f for f in all_findings if f['Severity'] < 4.0]
    
    # Count by source
    guardduty_count = len([f for f in all_findings if f['Source'] == 'GuardDuty'])
    iam_count = len([f for f in all_findings if f['Source'] == 'IAM'])
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Operations Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00d4ff; }}
        h2 {{ color: #00d4ff; border-bottom: 1px solid #333; padding-bottom: 8px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .metric {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 36px; font-weight: bold; }}
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff9900; }}
        .medium {{ color: #f0b400; }}
        .low {{ color: #44bb44; }}
        .finding {{ background: #16213e; border-left: 4px solid #444; margin: 8px 0; padding: 12px; border-radius: 4px; }}
        .finding.critical {{ border-left-color: #ff4444; }}
        .finding.high {{ border-left-color: #ff9900; }}
        .finding.medium {{ border-left-color: #f0b400; }}
        .ai-box {{ background: #0f3460; border-left: 4px solid #00d4ff; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .source-badge {{ background: #333; padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-right: 8px; }}
        .timestamp {{ color: #888; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>Security Operations Dashboard</h1>
    <p class="timestamp">Generated: {timestamp}</p>
    
    <div class="summary-grid">
        <div class="metric">
            <div class="metric-value critical">{len(critical)}</div>
            <div>Critical</div>
        </div>
        <div class="metric">
            <div class="metric-value high">{len(high)}</div>
            <div>High</div>
        </div>
        <div class="metric">
            <div class="metric-value medium">{len(medium)}</div>
            <div>Medium</div>
        </div>
        <div class="metric">
            <div class="metric-value low">{len(low)}</div>
            <div>Low</div>
        </div>
    </div>

    <div class="summary-grid">
        <div class="metric">
            <div class="metric-value">{len(all_findings)}</div>
            <div>Total Findings</div>
        </div>
        <div class="metric">
            <div class="metric-value">{guardduty_count}</div>
            <div>GuardDuty</div>
        </div>
        <div class="metric">
            <div class="metric-value">{iam_count}</div>
            <div>IAM</div>
        </div>
        <div class="metric">
            <div class="metric-value">{LOOKBACK_HOURS}h</div>
            <div>Window</div>
        </div>
    </div>

    <div class="ai-box">
        <h2>AI Security Analysis</h2>
        {ai_analysis}
    </div>

    <h2>All Findings ({len(all_findings)})</h2>
"""

    for f in sorted(all_findings, key=lambda x: x['Severity'], reverse=True):
        if f['Severity'] >= 9.0:
            sev_class = 'critical'
        elif f['Severity'] >= 7.0:
            sev_class = 'high'
        elif f['Severity'] >= 4.0:
            sev_class = 'medium'
        else:
            sev_class = 'low'
        
        html += f"""
    <div class="finding {sev_class}">
        <span class="source-badge">{f['Source']}</span>
        <strong>{f['Type']}</strong> — Severity {f['Severity']}
        <p>{f['Description']}</p>
        <p class="timestamp">{f['Time']} | {f['Resource']}</p>
    </div>"""

    html += """
</body>
</html>"""

    with open(filename, 'w') as f:
        f.write(html)
    
    print(f"Dashboard saved to: {filename}")
    return filename

if __name__ == "__main__":
    print("=== AI Security Operations Dashboard ===")
    print(f"Collecting findings from last {LOOKBACK_HOURS} hours...\n")
    
    # Collect from all sources
    print("Pulling GuardDuty findings...")
    gd_findings = get_guardduty_findings()
    print(f"Found {len(gd_findings)} GuardDuty findings")
    
    print("Running IAM security checks...")
    iam_findings = get_iam_findings()
    print(f"Found {len(iam_findings)} IAM findings")
    
    # Combine all findings
    all_findings = gd_findings + iam_findings
    print(f"\nTotal findings: {len(all_findings)}")
    
    # AI triage
    print("\nRunning AI triage...")
    analysis = ai_triage(all_findings)
    
    # Generate dashboard
    print("Generating dashboard...")
    dashboard_file = generate_dashboard(all_findings, analysis)
    
    print(f"\n=== Complete ===")
    print(f"Dashboard: {dashboard_file}")
    print(f"Open in Chrome to view")

