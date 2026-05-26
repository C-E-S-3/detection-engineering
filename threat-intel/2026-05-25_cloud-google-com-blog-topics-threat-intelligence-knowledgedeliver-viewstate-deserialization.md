---
scraped_at: "2026-05-26T00:00:00Z"
source_url: "https://cloud.google.com/blog/topics/threat-intelligence/knowledgedeliver-viewstate-deserialization-vulnerability"
report_type: threat-intel
severity: high
title: "KnowledgeDeliver CVE-2026-5426: ViewState Deserialization via Hardcoded ASP.NET Machine Keys — BLUEBEAM Webshell and Cobalt Strike Deployment"
---

## 1. IOCs

### File Hashes

| Indicator | Type | Malware | Context |
|-----------|------|---------|---------|
| `7c1f99dca8e5a7897892f9d224a6495023a2cfd2671697d229d355978c415ed2` | SHA-256 | BLUEBEAM (Godzilla) web shell | `LoadLibrary.dll` — .NET in-memory web shell DLL deployed post-exploitation via CVE-2026-5426 |

### Anomalous User-Agent Patterns

These concatenated double-UA strings are artifacts of the attacker's exploitation tool and indicate ViewState deserialization exploitation attempts:

- `Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.2 (KHTML, like Gecko) Chrome/22.0.1216.0 Safari/537.2 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36`
- `Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.2.13) Gecko/20101213 Opera/9.80 (Windows NT 6.1; U; zh-tw) Presto/2.7.62 Version/11.01 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36`
- `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0) chromeframe/10.0.648.205 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36`

### Windows Event Log Signatures

- **Event ID 1316** (ASP.NET 4.0.30319.0), **Event code 4009** — "ViewState verification failed" — indicates active exploitation attempt or successful deserialization attack

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1190 | Exploit Public-Facing Application | Unauthenticated RCE via ViewState deserialization exploiting hardcoded `machineKey` values in `web.config` |
| Persistence | T1505.004 | Server Software Component: IIS Components | BLUEBEAM .NET in-memory web shell operates within IIS worker process (`w3wp.exe`) |
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Post-exploitation command execution via web shell |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `cmd.exe` spawned as child of `w3wp.exe` |
| Defense Evasion | T1036 | Masquerading | BLUEBEAM operates in memory within the IIS worker process, masking activity as legitimate web traffic |
| Persistence | T1547.014 | Boot or Logon Autostart Execution: Winlogon Helper DLL | Post-compromise persistence via Winlogon DLL |
| Lateral Movement | T1078.003 | Valid Accounts: Local Accounts | Attacker leverages compromised local accounts for lateral movement |
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | BLUEBEAM receives encrypted commands via HTTP POST to IIS; Cobalt Strike BEACON C2 via HTTP/HTTPS |
| Defense Evasion | T1197 | BITS Jobs | Post-exploitation payload download and staging via BITS |
| Execution | T1204.001 | User Execution: Malicious Link | Initial compromise vector includes fake security alert phishing link |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| BLUEBEAM (aka Godzilla) | .NET In-Memory Web Shell | Operates entirely in memory within `w3wp.exe` (IIS worker process); receives encrypted HTTP POST commands; `LoadLibrary.dll` hash above |
| Cobalt Strike BEACON | Post-Exploitation Framework | Deployed as second-stage payload via BLUEBEAM; beacon encrypted with organization-specific key; used for C2, lateral movement, and data collection |

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor:** Unknown; no attribution provided in the Mandiant report
- **Target:** KnowledgeDeliver LMS (Learning Management System) deployments, primarily in Japan; vendor is Digital Knowledge
- **Affected Versions:** All KnowledgeDeliver deployments prior to February 24, 2026
- **Root Cause:** Standardized `web.config` distributed to all customers with identical, pre-shared `machineKey` values — a pattern that affects any ASP.NET application using shared or published machine keys (e.g., default configurations, public GitHub repositories leaking `web.config`)
- **First Exploited:** Active exploitation confirmed before Mandiant investigation (pre-February 2026 patch)

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="w3wp.exe"
  AND Processes.process_name IN ("cmd.exe","powershell.exe","whoami.exe","net.exe","net1.exe",
      "ipconfig.exe","icacls.exe","certutil.exe","bitsadmin.exe","wscript.exe","cscript.exe",
      "mshta.exe","regsvr32.exe","rundll32.exe","nltest.exe","nslookup.exe","ping.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)(whoami|ipconfig|hostname|nltest|nslookup)"), 85,
    match(process_name, "(?i)(certutil|bitsadmin|mshta|wscript|cscript|regsvr32|rundll32)"), 80,
    match(process_name, "(?i)(powershell|cmd|ping)"), 75,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="LoadLibrary.dll"
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user file_path file_name risk_score
```

```spl
`wineventlog_application` EventCode=1316 EventData="*Event code: 4009*"
| rex field=EventData "(?i)event code:\s*4009"
| stats count min(_time) as firstTime max(_time) as lastTime by host, source
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime host source count risk_score
```

---

## 6. Executive Summary

On May 25, 2026, Mandiant published research documenting active exploitation of CVE-2026-5426, a ViewState deserialization vulnerability in KnowledgeDeliver, a Learning Management System (LMS) widely used in Japan. The vulnerability exists because Digital Knowledge distributed a standardized `web.config` containing identical `machineKey` values across all customer deployments. An attacker who obtains these shared keys can forge ViewState payloads that the ASP.NET runtime deserializes with full trust, enabling unauthenticated remote code execution.

Post-exploitation activity includes deployment of BLUEBEAM (the Godzilla .NET in-memory web shell), which operates entirely within the IIS worker process (`w3wp.exe`) to avoid file-based detection. Second-stage activity involves Cobalt Strike BEACON for lateral movement, credential theft, and data collection. The hardcoded-machineKey attack pattern is broadly applicable — any ASP.NET application with publicly known or shared machine keys is vulnerable to the same class of attack, making this technique relevant beyond KnowledgeDeliver specifically.

**Immediate actions:** Hunt for `w3wp.exe` spawning command shells, scan web-accessible ASP.NET applications for default or shared `machineKey` values in `web.config`, and monitor Windows Event ID 1316 (Event code 4009) for ViewState verification failures.
