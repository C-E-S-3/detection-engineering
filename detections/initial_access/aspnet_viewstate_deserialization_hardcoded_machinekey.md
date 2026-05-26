# ASP.NET ViewState Deserialization via Hardcoded or Shared Machine Key

## Description

Detects exploitation of ASP.NET applications that use hardcoded, default, or publicly known `machineKey` values in `web.config`. When a `machineKey` is known to an attacker, they can craft a malicious ViewState payload that the ASP.NET runtime deserializes with full CLR trust — enabling unauthenticated remote code execution on any ASP.NET Web Forms application.

This technique was actively exploited in the wild against KnowledgeDeliver (CVE-2026-5426), a Learning Management System that shipped identical `machineKey` values in standardized `web.config` templates. The resulting post-exploitation activity includes BLUEBEAM (.NET Godzilla web shell) and Cobalt Strike BEACON deployment. The technique is not limited to KnowledgeDeliver — any ASP.NET application whose `machineKey` is published on GitHub, in vendor documentation, or shared across deployments is vulnerable.

**Observable behaviors:**
- Windows Application event ID 1316 with Event code 4009 (ViewState verification failed) appearing before command execution — indicates exploitation attempts
- IIS worker process (`w3wp.exe`) spawning reconnaissance or administrative utilities as child processes
- Anomalous double-concatenated User-Agent strings (attacker exploitation tool artifact)
- Creation of unexpected DLL files (e.g., `LoadLibrary.dll`) in web root or temp directories

**False positives:**
- Legitimate IIS applications spawning child processes (rare; should be investigated)
- Event ID 1316 may fire from ViewState tampering in error cases unrelated to attack
- Load testing or web scanners may generate unusual User-Agent patterns

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Persistence |
| Secondary Tactic ID | TA0003 |
| Secondary Technique | Server Software Component: IIS Components |
| Secondary Technique ID | T1505.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="w3wp.exe"
  AND Processes.process_name IN ("cmd.exe","powershell.exe","whoami.exe","net.exe","net1.exe",
      "ipconfig.exe","icacls.exe","certutil.exe","bitsadmin.exe","wscript.exe","cscript.exe",
      "mshta.exe","regsvr32.exe","rundll32.exe","nltest.exe","nslookup.exe","ping.exe",
      "attrib.exe","sc.exe","tasklist.exe","systeminfo.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)(whoami|ipconfig|hostname|nltest|systeminfo)"), 85,
    match(process_name, "(?i)(certutil|bitsadmin|mshta|wscript|cscript|regsvr32|rundll32|attrib)"), 80,
    match(process_name, "(?i)(powershell|cmd)"), 75,
    match(process_name, "(?i)(net|net1|sc|tasklist|nslookup|ping)"), 70,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Reconnaissance commands (whoami, ipconfig, nltest, systeminfo) spawned by w3wp.exe | 85 | Near-certain post-exploitation; legitimate IIS processes never invoke these |
| LOLBins with download/execute capability (certutil, bitsadmin, mshta, regsvr32, rundll32) spawned by w3wp.exe | 80 | Strong indicator of payload staging or execution post-webshell |
| Interactive shells (powershell.exe, cmd.exe) spawned by w3wp.exe | 75 | Highly suspicious; legitimate IIS CGI invocations are rare and should use specific ASP.NET handlers |
| Network/AD discovery commands (net, sc, nslookup, ping) spawned by w3wp.exe | 70 | Suspicious; likely reconnaissance or lateral movement preparation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (KnowledgeDeliver CVE-2026-5426 exploiters) | [Mandiant — KnowledgeDeliver ViewState RCE (2026-05-25)](https://cloud.google.com/blog/topics/threat-intelligence/knowledgedeliver-viewstate-deserialization-vulnerability) |
| Multiple APT and cybercrime groups | [CISA — Hardcoded ASP.NET Machine Keys Enable ViewState Deserialization (2025)](https://www.cisa.gov/news-events/alerts/2025/02/06/cisa-and-ms-isac-release-advisory-exploited-aspnet-machine-key-vulnerability) |

## References

- [Mandiant — Exploitation of KnowledgeDeliver via ViewState Deserialization Vulnerability (2026-05-25)](https://cloud.google.com/blog/topics/threat-intelligence/knowledgedeliver-viewstate-deserialization-vulnerability)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.004: Server Software Component: IIS Components](https://attack.mitre.org/techniques/T1505/004/)
- [OWASP — ViewState Deserialization](https://owasp.org/www-community/vulnerabilities/ViewState_without_MAC_enabled)
