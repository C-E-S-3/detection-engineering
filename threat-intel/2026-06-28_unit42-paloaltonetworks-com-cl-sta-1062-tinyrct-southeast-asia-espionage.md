---
scraped_at: 2026-06-28T12:00:00Z
source_url: https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/
report_type: threat-intel
severity: high
title: "CL-STA-1062: Chinese-Speaking APT Deploys Novel TinyRCT C# Backdoor Against Southeast Asian Energy and Government Sectors"
---

## 1. IOCs

### IP Addresses

| Indicator | Type | Context |
|-----------|------|---------|
| 45.32.113[.]172 | IPv4 | TinyRCT C2 server; communicates via plain HTTP with AES-128-CBC-encrypted payloads (hardcoded key); 10-second beacon interval; confirmed in Unit 42 analysis of Q4 2025 campaign |
| 139.180.134[.]221 | IPv4 | Payload hosting/staging server; TinyRCT backdoor binary (PerfWatson2.exe) hosted at this IP prior to victim-side deployment; Unit 42 June 25 2026 disclosure |

### File Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| `PerfWatson2.exe` | Filename | TinyRCT backdoor binary masquerading as Microsoft Visual Studio telemetry component (legitimate binary lives in `C:\Program Files\Microsoft Visual Studio\*\Common7\IDE\`); deployed to `%LOCALAPPDATA%` |
| `chrome_setup.zip` | Filename | Delivery archive; contains legitimate-looking Chrome installer alongside a hidden malicious DLL; AppDomainManager injection loads TinyRCT from DLL silently inside trusted process |
| Malicious companion `.config` file | File type | Forces the .NET runtime to load attacker's AppDomainManager DLL via `APPDOMAIN_MANAGER_ASM` / `APPDOMAIN_MANAGER_TYPE` configuration directives |
| `ThisIsASecretKey87654321` | Hardcoded AES key | AES-128-CBC encryption key embedded in TinyRCT binary; used to encrypt all C2 traffic; key is constant across all observed samples |

### Behavioral

| Indicator | Type | Context |
|-----------|------|---------|
| Environment check: exit if not `%LOCALAPPDATA%` | Anti-sandbox | TinyRCT verifies it is running from `%LOCALAPPDATA%` at startup; terminates silently if executed from any other path (sandbox, analyst desktop, temp directory) |
| 40 KB gzip-compressed chunks | Data exfil pattern | Files exfiltrated in 40 KB AES-encrypted gzip-compressed chunks over HTTP |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | Initial intrusion via web shells on Internet-exposed servers; database record exfiltration from internal MSSQL server in September 2025 government intrusion |
| Initial Access | T1566 | Phishing | Delivery of chrome_setup.zip via phishing lure (inferred from delivery artifact naming) |
| Execution | T1574.014 | AppDomain Manager Injection | Malicious DLL in chrome_setup.zip leverages AppDomainManager injection to load TinyRCT inside a trusted .NET host process; trojanized `.config` file forces .NET runtime to load attacker's assembly |
| Defense Evasion | T1036.005 | Masquerade: Match Legitimate Name or Location | TinyRCT binary deployed as `PerfWatson2.exe` in `%LOCALAPPDATA%`, impersonating a legitimate Microsoft Visual Studio 2022 telemetry binary |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | Verifies execution path is `%LOCALAPPDATA%`; terminates silently if run from any other path to defeat sandbox detonation |
| Defense Evasion | T1070 | Indicator Removal | Self-deletion capability (`Delete` command); removes backdoor binary on operator command |
| Persistence | T1547 | Boot or Logon Autostart Execution | Persistence mechanism (specific key not publicly detailed by Unit 42; implied by dwell time across Oct–Dec 2025 campaign) |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Plain HTTP C2 with AES-128-CBC payload encryption; 10-second beacon interval to 45.32.113[.]172 |
| Command and Control | T1132.001 | Data Encoding: Standard Encoding | C2 traffic AES-128-CBC encrypted before transmission over HTTP |
| Collection | T1113 | Screen Capture | Screenshots captured as JPEG and exfiltrated; 40 KB gzip-compressed AES-encrypted chunks over HTTP |
| Collection | T1083 | File and Directory Discovery | Directory enumeration and file listing commands supported |
| Exfiltration | T1030 | Data Transfer Size Limits | Files exfiltrated in 40 KB gzip-compressed AES-encrypted chunks |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | TinyRCT runs arbitrary commands via cmd.exe and returns output to C2 |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| TinyRCT | C# RAT (Windows) | Custom lightweight backdoor; first observed by Unit 42 in 2025 campaign; C2 via plain HTTP with AES-128-CBC; hardcoded key `ThisIsASecretKey87654321`; capabilities: command execution (cmd.exe), file enum/read/exfil (40KB chunks), screenshot (JPEG), file download from URL, self-delete |
| AppDomainManager Injection DLL | C# DLL loader | Delivered via chrome_setup.zip alongside legitimate Chrome installer; trojanized `.config` file directs .NET CLR to load attacker's DLL as AppDomainManager inside trusted host process |
| Web shells | Web shell | Used for initial persistence on Internet-facing servers; database exfiltration from MSSQL; consistent with CL-STA-1062 intrusion methodology since 2022 |

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Cluster | CL-STA-1062 |
| Attribution | Chinese-speaking APT; consistent with PRC-aligned espionage objectives (critical infrastructure, government); active since at least March 2022 |
| Researcher | Unit 42 (Palo Alto Networks), published June 25, 2026 |
| Targeting | Southeast Asian government ministries, state-owned enterprises in energy sector; at least 10 organizations compromised October–December 2025 |
| Objectives | Strategic espionage; web-server source code harvesting; database exfiltration; prolonged persistent access (months-long dwell time) |
| Prior activity | September 2025: broke into Southeast Asian government network via web shells, pulled internal MSSQL records; October–December 2025: at least two state-owned critical energy organizations in same Southeast Asian country compromised |
| Toolset evolution | Prior campaigns used commodity tools and open-source frameworks; 2025–2026 shift to custom TinyRCT backdoor indicates maturation and deliberate anti-detection investment |

---

## 5. Splunk Detection Searches

### 5a. PerfWatson2.exe Executing from Non-Standard Path (Visual Studio Masquerade)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="PerfWatson2.exe"
  AND NOT Processes.process_path IN (
    "*\\Microsoft Visual Studio\\*\\Common7\\IDE\\*",
    "*\\Program Files\\Microsoft Visual Studio\\*",
    "*\\Program Files (x86)\\Microsoft Visual Studio\\*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process_path Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_path, "(?i)localappdata|appdata|temp|tmp|public|programdata"), 95,
    NOT match(process_path, "(?i)microsoft visual studio|program files"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process_path process risk_score
```

### 5b. AppDomainManager Injection via Suspicious .config File Write in Program Directories

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_name="*.config" OR Filesystem.file_name="*.exe.config")
  AND (Filesystem.file_path="*\\AppData\\Local\\*"
       OR Filesystem.file_path="*\\Temp\\*"
       OR Filesystem.file_path="*\\ProgramData\\*"
       OR Filesystem.file_path="*\\Users\\Public\\*")
  AND NOT Filesystem.process_name IN ("msiexec.exe","setup.exe","installer.exe","nuget.exe","dotnet.exe")
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)localappdata.*chrome|appdata.*chrome"), 90,
    match(process_name, "(?i)cmd|powershell|wscript|cscript"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

### 5c. HTTP Beaconing with Regular Interval to Known TinyRCT C2 IP

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN ("45.32.113.172","139.180.134.221")
by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest_ip dest_port process_name risk_score
```

### 5d. chrome_setup.zip Followed by PerfWatson2.exe Execution (Delivery Chain)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="chrome_setup.zip"
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| join type=left dest
    [| tstats `security_content_summariesonly` count min(_time) as exec_time
     from datamodel=Endpoint.Processes
     where Processes.process_name="PerfWatson2.exe"
     by Processes.dest Processes.user Processes.process_name Processes.process_path
     | `drop_dm_object_name(Processes)`]
| where isnotnull(exec_time) AND (exec_time - firstTime) < 3600
| `security_content_ctime(firstTime)`
| `security_content_ctime(exec_time)`
| eval risk_score=95
| table firstTime exec_time dest user file_path process_name process_path risk_score
```

---

## 6. Executive Summary

On June 25, 2026, Unit 42 (Palo Alto Networks) disclosed a sustained espionage campaign by the Chinese-speaking cluster **CL-STA-1062** targeting government ministries and state-owned critical energy enterprises in Southeast Asia. The disclosure introduces **TinyRCT**, a previously undocumented lightweight C# RAT that represents a maturation of the cluster's toolset from commodity frameworks to custom-developed backdoors.

**TinyRCT** is delivered via `chrome_setup.zip` — a malicious archive containing a legitimate Chrome installer alongside a hidden DLL. A companion `.config` file triggers **.NET AppDomainManager injection**, silently loading the malicious DLL inside a trusted .NET host process. The backdoor is deployed as `PerfWatson2.exe` to `%LOCALAPPDATA%`, masquerading as a Microsoft Visual Studio telemetry component. The binary performs an environment check on startup and terminates silently if not in `%LOCALAPPDATA%`, defeating sandbox-based detonation.

C2 communication runs over plain HTTP to **45.32.113[.]172** (10-second beacon interval), with all payloads AES-128-CBC encrypted using the hardcoded key `ThisIsASecretKey87654321`. Capabilities include arbitrary command execution via `cmd.exe`, file enumeration and exfiltration (40 KB gzip-compressed AES-encrypted chunks), JPEG screenshot capture, file download, and self-deletion.

Unit 42 documents at least **10 compromised organizations** across October–December 2025, including at least two state-owned critical energy companies in the same Southeast Asian country. Initial access was obtained through web shells on Internet-facing servers, with MSSQL database exfiltration observed in the September 2025 government network intrusion.

**Recommended actions:**
- Hunt for `PerfWatson2.exe` executing outside of Visual Studio installation directories.
- Block outbound HTTP/HTTPS connections to 45.32.113.172 and 139.180.134.221.
- Alert on `.config` file creation in `%LOCALAPPDATA%`, `%TEMP%`, or `ProgramData` paths by non-installer processes.
- Monitor for `chrome_setup.zip` followed by unusual process execution (AppDomainManager injection).
- Review `.NET` host processes (especially those loading external AppDomain assemblies) for unexpected network connections.
