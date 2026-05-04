# AI-Assisted-Detection-Response-Pipeline
Built an AI-assisted detection and response pipeline using Microsoft Sentinel and KQL to identify brute-force login patterns. Automated workflows trigger alert triage, where a Python-based layer summarizes incidents, classifies severity, and recommends actions, improving alert clarity and response efficiency.

<img width="1236" height="924" alt="AI-Assisted-Detection- -Responce-Pipeline_ChatGPT Image May 4, 2026, 01_52_35 PM" src="https://github.com/user-attachments/assets/45f2bb0c-1c6b-4031-8d16-1a242eeb42c6" />

---

## 🎨 Workflow Summary
<img width="424" height="536" alt="AI-Asst-Detectio-Project_Work-Flow_ChatGPT Image May 4, 2026, 02_05_43 PM" src="https://github.com/user-attachments/assets/6b17406f-82f7-41d4-a637-a3b8e10d9f32" />

---

## 🚨 Sentinel Incident
<img width="1849" height="50" alt="image" src="https://github.com/user-attachments/assets/9f197043-e440-4c02-af13-73cd5d3b6b72" />

---

## 🚨 Sentinel Analytics
<img width="2075" height="103" alt="image" src="https://github.com/user-attachments/assets/eb1eb73c-219e-4e3a-bdd0-459f31e15985" />

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

<img width="788" height="175" alt="image" src="https://github.com/user-attachments/assets/73e0103b-df79-470f-9101-2a1193211147" />

---

## ⚓ Alert Analysis & Triage Module (Python)
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

---

## 🤖 What this script does
- Analyzes alert data (failed attempts, user, IP)
- Classifies Severit (High / Medium / Low)
- Provides recommended response actions
- Returns a summary for automation and analysts

---

## 🎯Outcome
- Better clarity
- Faster Triage
- Reduced Alert Fatigue
- Improved Response efficiency




