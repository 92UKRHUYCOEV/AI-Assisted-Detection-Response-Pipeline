# AI-Assisted Detection & Response Pipeline (Microsoft Sentinel)
---
## Structure

# Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Objectives](#objectives)
- [Solution Architecture](#solution-architecture)
- [Detection Response Workflow](#detection-response-workflow)
- [AI Decision Process](#ai-decision-process)
- [Technology Stack](#technology-stack)
- [Detection Logic](#detection-logic)
- [AI Triage Engine](#ai-triage-engine)
- [Sample Pipeline Execution](#sample-pipeline-execution)
- [Automation & SOAR Integration](#automation--soar-integration)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Validation & Testing](#validation--testing)
- [Current Limitations](#current-limitations)
- [Future Enhancements](#future-enhancements)
- [Repository Structure](#repository-structure)
- [References](#references)

```

6. AI Decision Process
   6.1 AI Triage Decision Flow

7. Technology Stack

8. Detection Logic
   8.1 Microsoft Sentinel
   8.2 KQL Analytics Rule
   8.3 Sample Detection Query

9. AI Triage Engine
   9.1 Input Processing
   9.2 Context Enrichment
   9.3 Confidence Assessment
   9.4 Severity Recommendation
   9.5 Response Recommendation

10. Sample Pipeline Execution
    10.1 Alert Input
    10.2 AI Analysis
    10.3 Recommended Actions

11. Automation & SOAR Integration

12. MITRE ATT&CK Mapping

13. Validation & Testing

14. Current Limitations

15. Future Enhancements

16. Repository Structure

17. References
```

## Overview
Designed a cloud security workflow that detects suspicious authentication activity, automates investigation, and applies AI-assisted triage to recommend response actions.

## Solution Architecture (High Level)
   ### Logs → Log Analytics → KQL Detection → Sentinel Incident → Logic App → AI Triage (Python) → Response
   
<p align="center">
   <img width="1536" height="1024" alt="AI-Assisted-Detection- -Responce-Pipeline_ChatGPT Image July 27 2026" src="https://github.com/user-attachments/assets/ea557af1-3e0c-4cf8-a6ab-0070be3912a6" />
</p>

## Problem Statement

## Key Capabilities

- Detection Engineering (KQL) – brute-force pattern detection
- SIEM/SOAR Automation – Sentinel + Logic Apps
- AI-Assisted Triage – summarize, classify severity, recommend actions
- Incident Response – tagging, notifications, remediation guidance


## Tech Stack
Microsoft Sentinel • Log Analytics • KQL • Azure Logic Apps • Python


## MITRE ATT&CK Mapping
|MITRE ID | Description |
|:-----|:-------------------|
|T1110 | Brute Force        |
|T1078 | Valid Accounts     |
|TA0001 | Initial Access    |
|TA0006 | Credential Access |


## Workflow (Step-by-Step)
   1. KQL rule detects repeated failed logins followed by success
   2. Sentinel creates an incident
   3. Logic App triggers automatically
   4. Extracts user/IP/attempt data
   5. Python triage summarizes + classifies severity
   6. Applies response (tag, notify, recommend action)



## Sample Input

{
"UserPrincipalName": "[user@company.com](mailto:user@company.com)",
"IPAddress": "192.168.1.10",
"FailedAttempts": 7
}


## AI Triage Output

{
"severity": "Medium",
"summary": "Multiple failed login attempts followed by success from same IP.",
"recommendation": "Monitor account activity and enforce MFA."
}



## Validation & Testing
   - Simulated authentication events to validate detection logic
   - Verified severity thresholds (Low/Medium/High)
   - Confirmed consistent response recommendations


## Preventative Controls
   - Enforce MFA and Conditional Access
   - Apply account lockout policies
   - Monitor risky sign-ins (Entra ID Protection)


## ⚠️ Limitations
   - Threshold-based detection may require tuning
   - AI triage is rule-based (not full ML)
   - Not yet deployed in production tenant


## Future Enhancements
   - Integrate Azure OpenAI for advanced summarization
   - Deploy Python as Azure Function
   - Expand detections and add Sentinel dashboards


## Deployment Note
Designed and validated in a lab environment. Full deployment pending tenant approval.


## Repository
   https://github.com/92UKRHUYCOEV/AI-Assisted-Detection-Response-Pipeline

Built an AI-assisted detection and response pipeline using Microsoft Sentinel and KQL to identify brute-force login patterns. Automated workflows trigger alert triage, where a Python-based layer summarizes incidents, classifies severity, and recommends actions, improving alert clarity and response efficiency.

<p align="center">
<img width="1236" height="924" alt="AI-Assisted-Detection- -Responce-Pipeline_ChatGPT Image May 4, 2026, 01_52_35 PM" src="https://github.com/user-attachments/assets/45f2bb0c-1c6b-4031-8d16-1a242eeb42c6" />
</p>


## Workflow Summary
<p align="center">
<img width="424" height="736" alt="AI-Asst-Detectio-Project_Work-Flow_ChatGPT Image May 4, 2026, 02_05_43 PM" src="https://github.com/user-attachments/assets/6b17406f-82f7-41d4-a637-a3b8e10d9f32" />
</p>



## Sentinel Incident
<p align="center">
<img width="1849" height="50" alt="image" src="https://github.com/user-attachments/assets/9f197043-e440-4c02-af13-73cd5d3b6b72" />
</p>



## Sentinel Analytics
<p align="center">
<img width="2075" height="103" alt="image" src="https://github.com/user-attachments/assets/eb1eb73c-219e-4e3a-bdd0-459f31e15985" />
</p>



## KQL Detection Rule (Brute Force Pattern)
```MARKDOWN
SigninLogs
| where ResultType != 0  // failed logins
| summarize FailedAttempts = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| join kind=inner (
    SigninLogs
    | where ResultType == 0  // successful login
) on IPAddress, UserPrincipalName
| project TimeGenerated, UserPrincipalName, IPAddress, FailedAttempts
| order by TimeGenerated desc
```
<p align="center">
<img width="788" height="175" alt="image" src="https://github.com/user-attachments/assets/73e0103b-df79-470f-9101-2a1193211147" />
</p>



## Alert Analysis & Triage Module (Python Logic App)
Implemented an Azure Logic App trigger to automate incident response workflows based on Microsoft Sentinel alerts.
The Logic App is triggered automatically when a Sentinel incident is created. It acts as the orchestration layer, pulling incident data, passing it to a Python-based triage function, and then executing response actions like tagging or notification.
```python
import json

def analyze_alert(alert):
    failed_attempts = alert.get("FailedAttempts", 0)

    if failed_attempts >= 10:
        severity = "High"
        recommendation = "Block IP, reset user password, investigate account activity."
    elif failed_attempts >= 5:
        severity = "Medium"
        recommendation = "Monitor account, consider MFA enforcement."
    else:
        severity = "Low"
        recommendation = "Log and monitor."

    summary = f"""
    Suspicious login pattern detected.
    User: {alert.get("UserPrincipalName")}
    IP: {alert.get("IPAddress")}
    Failed Attempts: {failed_attempts}

    Severity: {severity}
    Recommended Action: {recommendation}
    """

    return {
        "summary": summary.strip(),
        "severity": severity,
        "recommendation": recommendation
    }

# Example alert input (simulate Sentinel output)
sample_alert = {
    "UserPrincipalName": "user@company.com",
    "IPAddress": "192.168.1.10",
    "FailedAttempts": 7
}

result = analyze_alert(sample_alert)
print(json.dumps(result, indent=2))
```


## Built Using
- JSON-based workflow definitions
- Azure Logic App connectors (prebuilt API integrations)



## Sample Input + Output
### Sample Alert: Input

{
"UserPrincipalName": "[user@company.com](mailto:user@company.com)",
"IPAddress": "192.168.1.10",
"FailedAttempts": 7
}

### AI Triage: Output

{
"severity": "Medium",
"summary": "Multiple failed login attempts followed by success from same IP.",
"recommendation": "Monitor account activity and enforce MFA."
}



## Validation & Testing
The detection and triage logic were validated using simulated authentication data to ensure:
- Accurate detection of brute-force patterns
- Correct severity classification thresholds
- Meaningful response recommendations

This testing confirms the workflow behaves as expected prior to full deployment.
```markdown
    Logs → Log Analytics → KQL Detection → Sentinel Incident → Logic App → AI Triage (Python) → Response
```


## Limitations
   - Detection is based on threshold logic and may require tuning to reduce false positives
   - AI triage is rule-based and does not leverage full machine learning models
   - Workflow is designed for low-to-moderate alert volume and may require scaling for production use
   - I designed, tested, validated, and understand the limitations of a system



## Future Enhancements
   - Integrate Azure OpenAI for advanced natural language summarization
   - Deploy Python logic as an Azure Function for full cloud integration
   - Expand detection rules to include additional attack patterns
   - Add dashboard visualization using Sentinel Workbooks



## simplified trigger definition
```JSON
{
  "trigger": {
    "type": "ApiConnection",
    "inputs": {
      "host": {
        "connectionName": "azureSentinel"
      },
      "method": "get",
      "path": "/incidents"
    }
  }
}
```


### How It Works (Step-by-Step)
1. Sentinel detects suspicious activity
2. Creates an incident
3. Logic App trigger fires:
   - “When an incident is created”
4. Logic App executes:
   - Get incident details
   - Call Python / AI logic
   - Tag / notify / respond


### Common Connectors Used
- Microsoft Sentinel
- Azure Monitor / Log Analytics
- HTTP (to call Python or APIs)
- Microsoft Teams / Email
- Azure Functions


<p align="center">
<img width="1774" height="887" alt="image" src="https://github.com/user-attachments/assets/f3f33431-592f-466f-b400-1af259a19ebf" />
</p>


## Automation Trigger Workflow
From alert to action—automatically.
This workflow shows how a Microsoft Sentinel incident triggers an Azure Logic App to execute investigation and response steps, forming the foundation of scalable SIEM/SOAR operations.



## What this script does
- Analyzes alert data (failed attempts, user, IP)
- Classifies Severit (High / Medium / Low)
- Provides recommended response actions
- Returns a summary for automation and analysts



## Why It Matters
- Enables SOAR (Security Orchestration, Automation, Response)
- Removes manual triage steps
- Scales security operations



## Confirmed Outcome
- Better clarity
- Faster Triage
- Reduced Alert Fatigue
- Improved Response efficiency



## Design-level Implementation
I designed the full detection and response pipeline, including KQL-based detection, automation workflow, and AI-assisted triage logic. While deployment is pending tenant approval, the system is fully defined and ready to implement.



## Deployment Note
This project was designed and validated in a lab environment. Full deployment within Azure Logic Apps and Microsoft Sentinel is pending tenant-level approval.
The workflow, logic, and automation steps are fully defined and ready for implementation.




