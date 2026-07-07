---
scraped_at: "2026-07-07T00:00:00Z"
source_url: "https://www.bleepingcomputer.com/news/security/dhs-confirms-hackers-breached-hsin-info-sharing-platform/"
report_type: threat-intel
severity: critical
title: "DHS Confirms HSIN Breach via ToolShell SharePoint Exploit Chain (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771)"
---

# DHS Confirms HSIN Breach via ToolShell SharePoint Exploit Chain (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771)

**Source:** BleepingComputer  
**Published:** 2026-07-05  
**Severity:** Critical  
**Tactic:** Initial Access (TA0001), Execution (TA0002), Collection (TA0009)

---

## 1. IOCs

### File Hashes

| Indicator | Type | Notes |
|-----------|------|-------|
| `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514` | SHA-256 | `spinstall0.aspx` — ToolShell webshell deployed on HSIN SharePoint server; from CISA MAR-251132.c1.v1 |

### CVEs Exploited (ToolShell Chain)

| CVE | Description | Role in Chain |
|-----|-------------|---------------|
| CVE-2025-49706 | SharePoint path traversal | Bypasses authentication; allows unauthenticated access to the `ToolPane.aspx` endpoint |
| CVE-2025-49704 | SharePoint path traversal (variant) | Auxiliary path traversal used in some ToolShell variants |
| CVE-2025-53771 | SharePoint path traversal → unauthenticated access | Primary step to reach `ToolPane.aspx` without authentication |
| CVE-2025-53770 | SharePoint deserialization RCE | Unauthenticated deserialization via `ToolPane.aspx`; arbitrary .NET code execution under IIS app pool identity |

No network IOCs (C2 domains or IPs) have been publicly attributed to this breach. CISA MAR-251132.c1.v1 contains the webshell hash above; full technical IOC set is in the classified HSIN advisory.

---

## 2. TTPs

| MITRE Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------------|-----------|-----------|--------------|-------|
| Initial Access | TA0001 | Exploit Public-Facing Application | T1190 | CVE-2025-53771 path traversal bypasses authentication on SharePoint, enabling unauthenticated reach to `ToolPane.aspx` |
| Execution | TA0002 | Exploitation for Client Execution | T1203 | CVE-2025-53770 deserialization of untrusted data via `ToolPane.aspx`; .NET code executes under `w3wp.exe` |
| Persistence | TA0003 | Server Software Component: Web Shell | T1505.003 | `spinstall0.aspx` webshell deployed to SharePoint `\inetpub\wwwroot\wss\` virtual directory |
| Collection | TA0009 | Data from Information Repositories | T1213.002 | SharePoint document library access; HSIN counterterrorism data, law enforcement profiles, World Cup 2026 security planning accessed |
| Defense Evasion | TA0005 | Masquerading | T1036 | Webshell named `spinstall0.aspx` — mimics SharePoint setup/installation file naming pattern |

---

## 3. Malware & Tools

### ToolShell

- **Type:** Webshell + exploit chain
- **CVEs:** CVE-2025-53771, CVE-2025-53770, CVE-2025-49706, CVE-2025-49704
- **Path:** SharePoint `ToolPane.aspx` endpoint reached via path traversal
- **Mechanism:** Path traversal bypasses authentication → deserialization of crafted payload → arbitrary .NET execution → webshell write
- **Webshell file:** `spinstall0.aspx` (SHA-256: `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514`)
- **Authentication required:** None — full exploit chain is unauthenticated
- **Affected versions:** SharePoint Server 2016, 2019, Subscription Edition

---

## 4. Breach Summary

| Attribute | Detail |
|-----------|--------|
| Target | Homeland Security Information Network (HSIN) — DHS sensitive-but-unclassified information sharing platform |
| Breach period | Late May – Early June 2026 |
| Public confirmation | July 5, 2026 (DHS statement) |
| Data accessed | Counterterrorism data, law enforcement threat profiles, World Cup 2026 security planning materials |
| Classification | Sensitive-but-unclassified (SBU) |
| Attribution | Unknown; tradecraft and target profile consistent with foreign intelligence collection (espionage motivation) |
| Entry vector | ToolShell exploit chain against HSIN's SharePoint deployment |

---

## 5. Splunk Detection Searches

### Search 1 — IIS/SharePoint: Access to ToolPane.aspx (Path Traversal Detection)

```spl
index=iis OR index=sharepoint
| rex field=cs_uri_stem "(?P<decoded_path>(?:%2e|\.){2,}[/\\\\].*toolpane\.aspx)"
| eval uri_clean=lower(cs_uri_stem)
| where match(uri_clean, "toolpane\.aspx") AND
    (match(cs_uri_stem, "(?i)%2e%2e|%2f|%5c|\.\.") OR
     match(cs_uri_stem, "(?i)/_layouts/") = 0)
| stats count min(_time) as firstTime max(_time) as lastTime, values(c_ip) as src_ips
  by s_computername, cs_uri_stem, sc_status, cs_method
| eval risk_score=if(sc_status=200, 95, 80)
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime s_computername cs_uri_stem sc_status src_ips count risk_score
```

Detects unauthenticated or path-traversal access to `ToolPane.aspx` on SharePoint servers — the initial exploitation step in the ToolShell chain. Requires IIS access log forwarding.

### Search 2 — Windows Event Logs: w3wp.exe Spawning Child Processes (Webshell Execution)

```spl
`sysmon` EventCode=1
  ParentImage="*\\w3wp.exe"
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\cscript.exe"
   OR Image="*\\wscript.exe" OR Image="*\\net.exe" OR Image="*\\whoami.exe"
   OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| stats count min(_time) as firstTime max(_time) as lastTime
  by host, user, ParentImage, Image, CommandLine, ParentCommandLine
| eval risk_score=case(
    match(Image,"(?i)powershell"), 90,
    match(Image,"(?i)cmd\.exe"), 85,
    1=1, 75)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host user ParentImage Image CommandLine risk_score
```

Detects `w3wp.exe` (IIS application pool) spawning command-line tools — the primary execution pattern when a webshell deployed via ToolShell or similar SharePoint exploits receives commands.

### Search 3 — Filesystem: New .aspx/.asmx/.ashx Files in SharePoint Web Directories

```spl
`sysmon` EventCode=11
  TargetFilename IN ("*\\inetpub\\wwwroot\\wss\\*","*\\inetpub\\wwwroot\\wss\\VirtualDirectories\\*")
  (TargetFilename="*.aspx" OR TargetFilename="*.asmx" OR TargetFilename="*.ashx")
| stats count min(_time) as firstTime max(_time) as lastTime
  by host, user, TargetFilename, Image
| eval risk_score=if(match(Image,"(?i)w3wp|powershell|cmd"), 95, 80)
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host user TargetFilename Image risk_score
```

Detects new `.aspx`, `.asmx`, or `.ashx` file creation within SharePoint's web root and virtual directories — consistent with webshell deployment via server-side code execution.

### Search 4 — File Integrity: Known ToolShell Webshell Hash (spinstall0.aspx)

```spl
`sysmon` EventCode=11
| eval sha256=lower(Hashes)
| where match(sha256, "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514")
| eval risk_score=100
| table _time host user TargetFilename Hashes risk_score
```

Detects creation of the specific `spinstall0.aspx` ToolShell webshell by SHA-256 hash (CISA MAR-251132.c1.v1). Requires Sysmon configured with file hash logging.

---

## 6. Executive Summary

On July 5, 2026, DHS publicly confirmed that the Homeland Security Information Network (HSIN) — the agency's sensitive-but-unclassified information sharing platform — was breached between late May and early June 2026 via the ToolShell exploit chain targeting on-premises SharePoint Server.

ToolShell chains four SharePoint CVEs: path traversal vulnerabilities (CVE-2025-53771, CVE-2025-49706, CVE-2025-49704) reach the `ToolPane.aspx` endpoint without authentication, and a deserialization vulnerability (CVE-2025-53770) in that endpoint yields arbitrary .NET code execution under the IIS app pool identity. The attackers deployed a webshell named `spinstall0.aspx` (SHA-256: `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514`), matching the naming pattern of SharePoint setup files to blend into the directory.

Data accessed includes counterterrorism data, law enforcement threat profiles, and World Cup 2026 security planning materials. Attribution remains unknown; the target profile and data of interest are consistent with foreign intelligence collection.

Organizations running SharePoint Server 2016, 2019, or Subscription Edition should apply Microsoft's patches for all four CVEs immediately, hunt for `spinstall0.aspx` and similar recently created `.aspx` files in IIS web directories, and review `w3wp.exe` process creation logs for signs of webshell command execution.

---

## References

- [BleepingComputer — DHS Confirms Hackers Breached HSIN (2026-07-05)](https://www.bleepingcomputer.com/news/security/dhs-confirms-hackers-breached-hsin-info-sharing-platform/)
- [CISA MAR-251132.c1.v1 — ToolShell Malware Analysis Report](https://www.cisa.gov/news-events/analysis-reports/ar26-251132)
- [Microsoft MSRC — SharePoint ToolShell Advisory](https://msrc.microsoft.com/update-guide/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003: Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1213.002: Data from SharePoint](https://attack.mitre.org/techniques/T1213/002/)
