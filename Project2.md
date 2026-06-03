Azure Sentinel SOC Lab – MITRE ATT&CK Mapping and Threat Intelligence Integration
Project Summary

---

# Azure Security Project 2: MITRE ATT&CK Mapping and Cyber Threat Intelligence Lab

A continuation of the Azure Sentinel Security Project. This project adds MITRE ATT&CK mapping of simulated attacks, Cyber Threat Intelligence integration into Microsoft Sentinel, a Sentinel Workbook dashboard, and an ITIL-aligned incident response workflow.

**Role:** Cloud Security Analyst  
**Platform:** Microsoft Azure  
**Approach:** Azure Portal (GUI) + Azure Cloud Shell (SSH and simulation only)

---

## What This Project Demonstrates

| Skill | Evidence |
|---|---|
| MITRE ATT&CK Framework | Mapped 3 real techniques to lab activities |
| Threat Intelligence Integration | Uploaded IOCs and created threat match rule |
| KQL Query Writing | Detection rules and investigation queries |
| Sentinel Workbook | Visual attack dashboard with 3 charts |
| ITIL Incident Response | Full lifecycle documented |
| RBAC and Least Privilege | Standard user access tested and verified |

---

## Repository Structure

```
azure-sentinel-soc-project/
├── README.md
├── PROJECT2.md
├── Azure_Sentinel_Project.docx
├── Azure_Sentinel_Project_2.docx
├── docs/
│   ├── mitre-mapping.md
│   └── threat-intelligence.md
└── screenshots/
    ├── p2-01-brute-force-incident.png
    ├── p2-02-brute-force-logs.png
    ├── p2-03-vm-restart-denied.png
    ├── p2-05-user-defender-view.png
    ├── p2-06-nsg-open-port.png
    ├── p2-07-nsg-restricted.png
    ├── p2-08-nsg-block-malicious-ip.png
    ├── p2-09-threat-intel-enabled.png
    ├── p2-10-threat-indicators-uploaded.png
    ├── p2-11-threat-match-rule.png
    ├── p2-12-workbook-dashboard.png
    └── p2-13-incident-closed.png
```

---

## Part 1: MITRE ATT&CK Mapping

### Techniques Simulated

| Technique | Name | Tactic | Where in Lab |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | SSH failed logins on Linux VM |
| T1078 | Valid Accounts | Initial Access | Azure AD standard user login |
| T1190 | Exploit Public-Facing Application | Initial Access | Open SSH port in NSG |

---

### Step 1 - T1110: Brute Force Attack Simulation

SSH into the Linux VM from Azure Cloud Shell and ran the following command to simulate 20 failed login attempts:

```bash
for i in {1..20}; do logger -p auth.info "Failed password for invaliduser from 192.168.1.1 port 22 ssh2"; done
```

Verified the logs appeared in Microsoft Sentinel:

```kql
Syslog
| where SyslogMessage contains "Failed password"
| where TimeGenerated > ago(15m)
| take 20
```

![Brute Force Logs in Sentinel](project2-screenshots/p2-02-brute-force-logs.png)

![Sentinel Incident Generated](project2-screenshots/p2-01-brute-force-incident.png)

---

### Step 2 - T1078: Valid Account Abuse Simulation

1. Opened a private browser window
2. Logged into Azure Portal using the standard user account
3. Attempted to access Sentinel, Defender for Cloud, and Virtual Machines
4. Attempted to restart the VM — access was denied

Findings:

| Action | Result |
|---|---|
| View Sentinel incidents | Allowed — Security Reader role |
| View Defender recommendations | Allowed — Security Reader role |
| Restart VM | Denied — no VM role assigned |
| Create analytics rule | Denied — read only access |

This confirms that RBAC and Principle of Least Privilege are working correctly.

![VM Restart Denied](project2-screenshots/p2-03-vm-restart-denied.png)

![Standard User Sentinel View](project2-screenshots/p2-04-user-sentinel-view.png)

![Standard User Defender View](project2-screenshots/p2-05-user-defender-view.png)

Checked Sentinel SigninLogs for standard user login activity:

```kql
SigninLogs
| where UserPrincipalName contains "SOCAnalyst"
| where TimeGenerated > ago(1h)
| take 10
```

---

### Step 3 - T1190: Public-Facing Application Exposure

1. Documented that SSH Port 22 was open to the internet via NSG
2. Restricted the rule to allow SSH from analyst IP only
3. Added a Deny rule to block the simulated malicious IP

![NSG Open Port 22](project2-screenshots/p2-06-nsg-open-port.png)

![NSG Restricted to Analyst IP](project2-screenshots/p2-07-nsg-restricted.png)

Blocked the malicious IP via NSG:

| Field | Value |
|---|---|
| Source | IP Addresses |
| Source IP | 192.168.1.1 |
| Destination port | * |
| Protocol | Any |
| Action | Deny |
| Priority | 100 |
| Name | Block-Malicious-IP |

![NSG Block Malicious IP](project2-screenshots/p2-08-nsg-block-malicious-ip.png)

---

## Part 2: Cyber Threat Intelligence Lab

### Step 1 - Enable Threat Intelligence in Sentinel

1. Navigated to Sentinel -> Data Connectors
2. Enabled the Threat Intelligence connector
3. Navigated to Sentinel -> Threat Intelligence to verify

![Threat Intelligence Enabled](project2-screenshots/p2-09-threat-intel-enabled.png)

---

### Step 2 - Upload Threat Indicators

Created a CSV file with malicious IPs and domains and uploaded it to Sentinel:

```csv
Indicator,Type,Description
192.168.1.100,IP,Known malicious IP - brute force source
10.0.0.99,IP,Suspicious internal scanner
malicious-site.com,Domain,Known phishing domain
evil-malware.net,Domain,Known malware C2 server
```

![Threat Indicators Uploaded](project2-screenshots/p2-10-threat-indicators-uploaded.png)

---

### Step 3 - Create Threat Match Detection Rule

Navigated to Sentinel -> Analytics -> + Create -> Scheduled Query Rule

| Field | Value |
|---|---|
| Name | Threat Intelligence IP Match |
| Severity | High |
| Tactic | Command and Control |
| Run every | 5 minutes |
| Lookup last | 1 hour |

KQL Query:

```kql
ThreatIntelligenceIndicator
| where Active == true
| project NetworkIP, Description, ExpirationDateTime
| take 20
```

![Threat Match Analytics Rule](project2-screenshots/p2-11-threat-match-rule.png)

---

### Step 4 - Build Sentinel Workbook Dashboard

Created a Workbook in Sentinel -> Workbooks with 3 visualisations.

Widget 1 - Top Attacker IPs (Bar Chart):

```kql
Syslog
| where SyslogMessage contains "Failed password"
| extend AttackerIP = extract(@"from (\S+)", 1, SyslogMessage)
| summarize Attempts = count() by AttackerIP
| order by Attempts desc
| take 10
```

Widget 2 - Failed Logins Over Time (Line Chart):

```kql
Syslog
| where SyslogMessage contains "Failed password"
| summarize FailedLogins = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```

Widget 3 - Successful vs Failed Logins (Pie Chart):

```kql
Syslog
| where Facility == "auth" or Facility == "authpriv"
| extend LoginResult = iif(SyslogMessage contains "Accepted", "Successful", "Failed")
| summarize Count = count() by LoginResult
```

![Sentinel Workbook Dashboard](project2-screenshots/p2-12-workbook-dashboard.png)

---

### Step 5 - ITIL Incident Response Workflow

| ITIL Stage | Action Taken |
|---|---|
| Detection | Sentinel analytics rule triggered on Failed password entries |
| Logging | Azure Monitor stored all auth logs in Log Analytics Workspace |
| Investigation | KQL queries identified attacking IP and confirmed no unauthorised access |
| Response | Blocked malicious IP (192.168.1.1) via NSG Deny rule |
| Recovery | Confirmed VM not compromised, services operational |
| Lessons Learned | Updated NSG rules, restricted SSH access, documented findings |

![Incident Closed](project2-screenshots/p2-13-incident-closed.png)

---

## Roadblocks and Fixes

| Roadblock | Fix |
|---|---|
| SSH connection timing out repeatedly | NSG rule had old IP — updated to current IP |
| VM not booting correctly | Deleted and recreated the VM |
| VNet not appearing in VM networking tab | Region mismatch — matched VM region to VNet region |
| Standard user could restart VM | User had excess roles — removed Contributor role |
| sudo not working in Run Command | Run Command runs in restricted container — removed sudo |

---

## MITRE ATT&CK Summary

| Technique | Name | Simulated | Detected | Response |
|---|---|---|---|---|
| T1110 | Brute Force | Yes | Sentinel incident | Block IP via NSG |
| T1078 | Valid Accounts | Yes | SigninLogs | MFA and RBAC review |
| T1190 | Public-Facing App | Yes | Defender for Cloud | Restrict NSG rules |

---

## Key Lessons Learned

1. RBAC must be assigned at subscription level — resource-level only will not show portal resources
2. Dynamic IPs cause NSG lockouts — always verify your current IP before SSH troubleshooting
3. Run Command does not support sudo — limitation of the Azure restricted container environment
4. Recreating a broken VM is faster than troubleshooting a failed boot in a lab environment
5. LOG_DEBUG is essential for capturing all auth facility events in Syslog

---

## Project Checklist

| Task | Method | Status |
|---|---|---|
| T1110 Brute Force simulation and detection | Cloud Shell + Sentinel | Done |
| T1078 Valid Accounts simulation | Azure AD + Portal | Done |
| T1190 Public Exposure documentation | NSG + Portal | Done |
| Block malicious IP via NSG | Portal | Done |
| Enable Threat Intelligence in Sentinel | Portal | Done |
| Upload threat-indicators.csv | Portal | Done |
| Create Threat Match detection rule | Portal + KQL | Done |
| Build Sentinel Workbook dashboard | Portal + KQL | Done |
| ITIL incident response documented | Documentation | Done |
| docs/mitre-mapping.md created | GitHub | Done |
| docs/threat-intelligence.md created | GitHub | Done |
