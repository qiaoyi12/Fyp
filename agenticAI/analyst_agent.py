# ─── Analyst Agent (FED) ─────────────────────────────────────────────────────
# Handles AI-powered incident report generation using OpenAI GPT-4o-mini.
# Called by the analyst blueprint route when user clicks "Generate Report".
# Author: FED role
# NOTE TO TEAM: Do not modify this file — it is owned by the FED role.

import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# ─── System prompt — scopes agent to cybersecurity report writing ──────────────
SYSTEM_PROMPT = """You are an expert cybersecurity analyst agent working within
a Security Operations Centre (SOC). Your task is to investigate a security alert
and generate a professional incident report.

The report must follow this exact structure:

# INCIDENT REPORT

## 1. Executive Summary
A 2-3 sentence summary of the incident for management.

## 2. Attack Analysis
Detailed analysis of the attack type, technique used, and how it works.

## 3. IP Reputation & History
Assessment of the source IP based on the history provided. Is this a repeat offender?

## 4. Impact Assessment
What systems are at risk? What data or services could be compromised?
Rate the business impact as: CRITICAL / HIGH / MEDIUM / LOW

## 5. Recommended Immediate Actions
Numbered list of actions the SOC analyst should take RIGHT NOW.

## 6. Prevention Measures
Numbered list of long-term measures to prevent recurrence.

## 7. Analyst Notes
Any additional observations or concerns worth flagging.

Write in a professional, formal tone suitable for a corporate security report.
Be specific and actionable. Do not be vague."""


def investigate_alert(alert, all_alerts):
    """
    Pre-report investigation phase.
    Cross-references the alert's source IP against all other alerts
    to determine if this is a repeat offender.
    Returns investigation context as a formatted string.
    """
    # ── Cross-reference source IP ──────────────────────────────────────────────
    related_alerts = [
        a for a in all_alerts
        if a['source'] == alert['source'] and a['id'] != alert['id']
    ]

    if related_alerts:
        ip_history = (
            f"This IP has appeared in {len(related_alerts)} other alert(s): "
            + ', '.join([a['description'] for a in related_alerts])
        )
    else:
        ip_history = "This is the first time this IP has been detected in the system."

    # ── Build investigation context ────────────────────────────────────────────
    related_summary = (
        '\n'.join([
            f"- {a['description']} ({a['severity'].upper()}) at {a['time']}"
            for a in related_alerts
        ])
        if related_alerts else "None found."
    )

    context = f"""
Alert Details:
- Description: {alert['description']}
- Severity: {alert['severity'].upper()}
- Source IP: {alert['source']}
- Affected System: {alert['destination']}
- Attack Type: {alert['type']}
- Timestamp: {alert['timestamp']}
- Model Confidence: {alert['confidence']}%
- Raw Log: {alert['raw_log']}

IP History Investigation:
{ip_history}

Related Alerts from same IP:
{related_summary}
"""
    return context, related_alerts


def generate_incident_report(alert, all_alerts):
    """
    Main analyst agent function.
    1. Investigates the alert (cross-references IP, assesses severity)
    2. Sends context to OpenAI GPT-4o-mini
    3. Returns the generated report as a string
    """
    # ── Phase 1: Investigate ───────────────────────────────────────────────────
    investigation_context, related_alerts = investigate_alert(alert, all_alerts)

    # ── Phase 2: Generate report with OpenAI ──────────────────────────────────
    response = openai_client.chat.completions.create(
        model='gpt-4o-mini',
        messages=[
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {
                'role': 'user',
                'content': f"Investigate this alert and generate a full incident report:\n{investigation_context}"
            }
        ],
        max_tokens=1500,
        temperature=0.3
    )

    report_content = response.choices[0].message.content
    return report_content, related_alerts
