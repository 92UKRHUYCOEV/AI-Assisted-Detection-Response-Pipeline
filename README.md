# AI-Assisted-Detection-Response-Pipeline
Built an AI-assisted detection and response pipeline using Microsoft Sentinel and KQL to identify brute-force login patterns. Automated workflows trigger alert triage, where a Python-based layer summarizes incidents, classifies severity, and recommends actions, improving alert clarity and response efficiency.

<p align="center">
<img width="1236" height="924" alt="AI-Assisted-Detection- -Responce-Pipeline_ChatGPT Image May 4, 2026, 01_52_35 PM" src="https://github.com/user-attachments/assets/45f2bb0c-1c6b-4031-8d16-1a242eeb42c6" />
</p>
---

## 🎨 Workflow Summary
<p align="center">
<img width="424" height="736" alt="AI-Asst-Detectio-Project_Work-Flow_ChatGPT Image May 4, 2026, 02_05_43 PM" src="https://github.com/user-attachments/assets/6b17406f-82f7-41d4-a637-a3b8e10d9f32" />
</p>

---

## 🚨 Sentinel Incident
<p align="center">
<img width="1849" height="50" alt="image" src="https://github.com/user-attachments/assets/9f197043-e440-4c02-af13-73cd5d3b6b72" />
</p>

---

## 🚨 Sentinel Analytics
<p align="center">
<img width="2075" height="103" alt="image" src="https://github.com/user-attachments/assets/eb1eb73c-219e-4e3a-bdd0-459f31e15985" />
</p>

---

🧠 KQL Detection Rule (Brute Force Pattern)
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

---

## ⚓ Alert Analysis & Triage Module (Python Logic App)
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

## 🚧 Built Using
- JSON-based workflow definitions
- Azure Logic App connectors (prebuilt API integrations)


---

##🚨simplified trigger definition
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

### ⚙️ How It Works (Step-by-Step)
1. Sentinel detects suspicious activity
2. Creates an incident
3. Logic App trigger fires:
   - “When an incident is created”
4. Logic App executes:
   - Get incident details
   - Call Python / AI logic
   - Tag / notify / respond

### 🔗 Common Connectors Used
- Microsoft Sentinel
- Azure Monitor / Log Analytics
- HTTP (to call Python or APIs)
- Microsoft Teams / Email
- Azure Functions

---

<p align="center">
<img width="1774" height="887" alt="image" src="https://github.com/user-attachments/assets/f3f33431-592f-466f-b400-1af259a19ebf" />
</p>

## 🗝️ Automation Trigger Workflow
From alert to action—automatically.
This workflow shows how a Microsoft Sentinel incident triggers an Azure Logic App to execute investigation and response steps, forming the foundation of scalable SIEM/SOAR operations.

---

## 🤖 What this script does
- Analyzes alert data (failed attempts, user, IP)
- Classifies Severit (High / Medium / Low)
- Provides recommended response actions
- Returns a summary for automation and analysts

---

## 🧠 Why It Matters
- Enables SOAR (Security Orchestration, Automation, Response)
- Removes manual triage steps
- Scales security operations

---

## 🎯Outcome
- Better clarity
- Faster Triage
- Reduced Alert Fatigue
- Improved Response efficiency




