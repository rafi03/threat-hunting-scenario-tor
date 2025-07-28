# 🔍 Advanced Threat Hunt: Unauthorized TOR Browser Detection

<div align="center">

![TOR Threat Hunt Banner](assets/images/tor-hunt-banner.png)

[![Microsoft Defender](https://img.shields.io/badge/Platform-Microsoft%20Defender%20for%20Endpoint-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://security.microsoft.com)
[![KQL](https://img.shields.io/badge/Language-KQL-FF6F00?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)
[![Threat Hunting](https://img.shields.io/badge/Type-Threat%20Hunting-DC382D?style=for-the-badge&logo=shield&logoColor=white)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

**🎯 Real-world threat hunting investigation showcasing enterprise security monitoring and incident response capabilities**

</div>

---

## 📋 Executive Summary

This investigation documents the **successful detection and containment** of unauthorized TOR browser usage on corporate workstation `rafi-win`. Through systematic threat hunting, we identified a complete attack chain from installation to active usage, demonstrating advanced EDR capabilities and rapid incident response.

### 🔑 Key Achievements

<table>
<tr>
<td align="center">
<h3>⏱️</h3>
<b>4 Minutes</b><br>
Detection Time
</td>
<td align="center">
<h3>📊</h3>
<b>52 Events</b><br>
Analyzed
</td>
<td align="center">
<h3>🎯</h3>
<b>15 IOCs</b><br>
Identified
</td>
<td align="center">
<h3>🛡️</h3>
<b>100%</b><br>
Contained
</td>
</tr>
</table>

---

## 🚨 Threat Scenario

**Context**: Management identified suspicious encrypted traffic patterns and connections to known TOR infrastructure. Anonymous reports indicated employees discussing methods to bypass security controls.

**Mission**: Detect, analyze, and remediate any TOR usage across the enterprise to maintain security compliance and prevent data exfiltration.

---

## 🏗️ Technical Architecture

<div align="center">

![Detection Architecture](assets/images/detection-architecture.svg)

</div>

### Environment Stack
- **Platform**: Microsoft Defender for Endpoint
- **Query Language**: Kusto Query Language (KQL)
- **Data Sources**: DeviceFileEvents, DeviceProcessEvents, DeviceNetworkEvents
- **Target OS**: Windows 10 Enterprise

---

## 🔬 Investigation Methodology

### Detection Strategy

```mermaid
graph LR
    A[🔍 Threat Intel] --> B[📁 File Analysis]
    B --> C[⚙️ Process Tracking]
    C --> D[🌐 Network Analysis]
    D --> E[📊 Timeline Build]
    E --> F[🚨 Response]
```

---

## 📊 Investigation Findings

### 📁 Phase 1: File System Analysis

<details>
<summary><b>Click to expand detection query and findings</b></summary>

```kql
// TOR File Detection - Comprehensive Analysis
DeviceFileEvents
| where DeviceName == "rafi-win"
| where InitiatingProcessAccountName == "rafi03"
| where FileName contains "tor" or FolderPath contains "Tor Browser"
| where Timestamp >= datetime(2025-07-26T05:58:42.8355435Z)
| extend 
    RiskScore = case(
        FileName endswith ".exe" and ActionType == "FileCreated", 10,
        FileName contains "tor-browser", 8,
        ActionType == "FileRenamed", 5,
        3
    )
| project Timestamp, ActionType, FileName, FolderPath, SHA256, RiskScore
| order by RiskScore desc, Timestamp asc
```

**Key Discovery**: TOR installer `tor-browser-windows-x86_64-portable-14.5.5.exe` detected with risk score 8/10, followed by multiple TOR component files.

![File Events](evidence/screenshots/file-events.png)

</details>

### ⚙️ Phase 2: Installation Detection

<details>
<summary><b>Click to expand detection query and findings</b></summary>

```kql
// TOR Installation Detection - Silent Install Analysis
DeviceProcessEvents
| where DeviceName == "rafi-win"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| extend 
    ThreatLevel = case(
        ProcessCommandLine contains "/S", "HIGH - Silent Install",
        ProcessCommandLine contains "/D=", "MEDIUM - Custom Directory",
        "LOW - Interactive Install"
    )
| project Timestamp, AccountName, FileName, ProcessCommandLine, ThreatLevel, SHA256
```

**Critical Finding**: Silent installation detected with ThreatLevel: "HIGH - Silent Install" using `/S` parameter at 12:00:04 PM.

![Installation Process](evidence/screenshots/installation-process.png)

</details>

### 🚀 Phase 3: Process Execution

<details>
<summary><b>Click to expand detection query and findings</b></summary>

```kql
// TOR Process Execution - Browser and Service Analysis
DeviceProcessEvents
| where DeviceName == "rafi-win"
| where FileName has_any("tor.exe", "firefox.exe") 
    and FolderPath contains "Tor Browser"
| extend 
    ProcessType = case(
        FileName == "tor.exe", "TOR Service",
        FileName == "firefox.exe", "TOR Browser",
        "Unknown"
    )
| summarize 
    ProcessCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by AccountName, ProcessType, FileName
| order by FirstSeen asc
```

**Confirmation**: TOR Browser (firefox.exe) launched at 12:01:01 PM, followed by 3 TOR service processes.

![Process Execution](evidence/screenshots/process-execution.png)

</details>

### 🌐 Phase 4: Network Analysis

<details>
<summary><b>Click to expand detection query and findings</b></summary>

```kql
// TOR Network Detection - Connection Analysis
let TorPorts = dynamic([9001, 9030, 9040, 9050, 9051, 9150]);
DeviceNetworkEvents
| where DeviceName == "rafi-win"
| where RemotePort in (TorPorts) 
    or InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where InitiatingProcessAccountName != "system"
| extend 
    ConnectionType = case(
        RemotePort == 9001, "TOR Relay",
        RemotePort == 9150, "SOCKS Proxy",
        RemoteIP startswith "127.", "Local Proxy",
        "Unknown TOR"
    )
| summarize 
    TotalConnections = count(),
    SuccessfulConnections = countif(ActionType == "ConnectionSuccess"),
    UniqueIPs = dcount(RemoteIP),
    FirstConnection = min(Timestamp)
    by InitiatingProcessFileName, ConnectionType, RemotePort
```

**Network Breach**: 18 total connections attempted, 5 successful. Primary TOR relay confirmed at `192.87.28.82:9001`.

![Network Connections](evidence/screenshots/network-connections.png)

</details>

---

## ⏱️ Attack Timeline

<div align="center">

| Time | Phase | Event | Severity |
|------|-------|-------|----------|
| **11:58:42** | Preparation | TOR installer staged in Downloads | 🟡 Medium |
| **12:00:04** | Installation | Silent installation executed (`/S` flag) | 🟠 High |
| **12:01:01** | Execution | TOR Browser launched | 🔴 Critical |
| **12:01:24** | Network | Connected to TOR relay network | 🔴 Critical |
| **12:01:43** | Activity | Multiple TOR connections attempted | 🟠 High |

</div>

---

## 🎯 Key Indicators of Compromise (IOCs)

### File Indicators
| Type | Value | Context |
|------|-------|---------|
| **SHA256** | `6d38a13c6a5865b373ef1e1ffcd31b3f359abe896571d27fa666ce71c486a40d` | TOR Installer |
| **SHA256** | `6872f0df504c7a4a308caa86a73c62a51bb6e573107681ab60edbd72126df766` | Firefox.exe (TOR) |
| **Path** | `C:\Users\Rafi03\Desktop\Tor Browser\` | Installation Location |

### Network Indicators
| IP Address | Port | Type |
|------------|------|------|
| 192.87.28.82 | 9001 | TOR Relay |
| 127.0.0.1 | 9150 | Local SOCKS |
| 45.141.215.63 | 9100 | TOR Node (Failed) |

---

## 🚓 Incident Response

### Immediate Actions Taken

<table>
<tr>
<td>✅ <b>Device Isolated</b><br>Network access terminated</td>
<td>✅ <b>Account Suspended</b><br>User access revoked</td>
<td>✅ <b>Evidence Preserved</b><br>Forensic data captured</td>
<td>✅ <b>Management Notified</b><br>Stakeholders informed</td>
</tr>
</table>

### Recommended Actions

1. **Immediate**
   - Deploy application whitelisting
   - Block TOR infrastructure at firewall
   - Conduct user security training

2. **Long-term**
   - Implement behavioral analytics
   - Enhance network monitoring
   - Regular threat hunting exercises

---

## 💡 Skills Demonstrated

This investigation showcases:

- **🔍 Advanced Threat Hunting** - Multi-source correlation and analysis
- **💻 Technical Expertise** - KQL mastery and EDR platform proficiency  
- **📊 Analytical Thinking** - Pattern recognition and timeline reconstruction
- **📝 Documentation Skills** - Clear, professional reporting
- **🚨 Incident Response** - Rapid containment and remediation

---

## 📁 Repository Structure

```
tor-threat-hunt/
├── 📄 README.md                    # This file
├── 📊 data/                        # Investigation data
│   └── [CSV files]                 # Raw event data
├── 🔍 queries/                     # Detection queries
│   └── [KQL files]                 # Reusable hunting queries
├── 📸 evidence/                    # Investigation artifacts
│   ├── screenshots/                # Visual evidence
│   └── iocs.json                   # Structured IOC data
└── 📚 docs/                        # Supporting documentation
    ├── methodology.md              # Detection methodology
    ├── timeline.md                 # Detailed timeline
    └── playbook.md                 # Response procedures
```

---

## 🛠️ Technologies Used

<div align="center">

![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-0089D0?style=flat-square&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-512BD4?style=flat-square&logo=microsoftazure&logoColor=white)
![Defender](https://img.shields.io/badge/Defender-0078D4?style=flat-square&logo=microsoft&logoColor=white)

</div>

---

## 📫 Connect with Me

<div align="center">

**[LinkedIn](https://linkedin.com/in/yourprofile)** | **[GitHub](https://github.com/yourusername)** | **[Email](mailto:your.email@example.com)**

*Passionate about cybersecurity and always eager to discuss threat hunting strategies!*

</div>

---

<div align="center">

**🛡️ Protecting Organizations Through Proactive Threat Detection 🛡️**

</div>