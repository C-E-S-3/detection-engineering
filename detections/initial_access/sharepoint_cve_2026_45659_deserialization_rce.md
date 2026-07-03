# SharePoint Server Deserialization RCE — CVE-2026-45659

## Description

Detects exploitation of CVE-2026-45659, a CWE-502 deserialization of untrusted data vulnerability in Microsoft SharePoint Server (Subscription Edition, 2019, Enterprise Server 2016). A low-privileged authenticated user with Site Member access can send a crafted HTTP request that causes SharePoint to deserialize a malicious object payload, achieving arbitrary code execution in the IIS worker process context.

Post-exploitation code runs under `w3wp.exe` (IIS worker process). The primary behavioral indicator is `w3wp.exe` spawning unexpected child processes such as `cmd.exe`, `powershell.exe`, or `csc.exe`, or writing ASPX/ASMX files to the SharePoint web root. A secondary indicator is anomalous POST request patterns to SharePoint REST API endpoints (high body size, unusual Content-Type headers) from accounts not previously seen making API calls.

False positives may include legitimate SharePoint customizations, Timer Jobs, or third-party integrations that spawn child processes. Baseline w3wp.exe child process behavior in your environment before deploying the high-sensitivity variant.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | Server Software Component: Web Shell |
| Secondary Technique ID | T1505.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name="w3wp.exe"
        AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","csc.exe","certutil.exe",
                                         "bitsadmin.exe","mshta.exe","wscript.exe","cscript.exe",
                                         "rundll32.exe","regsvr32.exe","msiexec.exe","wmic.exe","net.exe",
                                         "net1.exe","whoami.exe","ipconfig.exe","nltest.exe"))
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.parent_process_id Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)(powershell|pwsh|csc)\.exe"), 90,
    match(process_name,"(?i)(certutil|bitsadmin|mshta|wscript|cscript)\.exe"), 85,
    match(process_name,"(?i)(rundll32|regsvr32|msiexec|wmic)\.exe"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Supplemental — webshell file creation in SharePoint web root:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where Filesystem.process_name="w3wp.exe"
        AND (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.asmx" OR Filesystem.file_name="*.ashx")
        AND (Filesystem.file_path="*\\inetpub\\wwwroot\\wss\\*"
             OR Filesystem.file_path="*\\SharePoint\\*"
             OR Filesystem.file_path="*\\WebSite*")
    by Filesystem.dest Filesystem.user Filesystem.process_name
       Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user process_name file_name file_path action risk_score
```

**Supplemental — IIS log anomalous POST to SharePoint API (requires Web data model or raw IIS logs):**

```spl
index=iis sourcetype=iis
    cs_uri_stem="*/_api/*" OR cs_uri_stem="*/sites/*/lists/*" OR cs_uri_stem="*/sites/*/_vti_bin/*"
    cs_method=POST
    sc_status IN (200, 201, 500)
| eval body_size_kb=round(cs_bytes/1024, 1)
| where body_size_kb > 50
| stats
    count as post_count
    sum(body_size_kb) as total_kb
    dc(cs_uri_stem) as distinct_endpoints
    min(_time) as firstTime
    max(_time) as lastTime
    values(cs_uri_stem) as endpoints
    by c_ip cs_username s_computername
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    post_count >= 20 AND total_kb >= 500, 85,
    post_count >= 5 AND total_kb >= 250, 75,
    total_kb >= 100, 65)
| where risk_score >= 65
| table firstTime lastTime s_computername cs_username c_ip post_count total_kb distinct_endpoints endpoints risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| w3wp.exe spawning PowerShell/pwsh/csc | 90 | Near-certain post-exploit code execution; .NET compilation or PowerShell cradle typical after deserialization |
| w3wp.exe spawning certutil/bitsadmin/mshta | 85 | Download-and-execute LOLBins indicating staged payload delivery |
| w3wp.exe spawning rundll32/regsvr32/msiexec | 80 | LOLBin execution for payload loading or lateral movement |
| w3wp.exe spawning cmd/system utilities | 70 | Reconnaissance (whoami, ipconfig, nltest) consistent with post-exploit enumeration |
| Webshell (.aspx/.asmx/.ashx) written by w3wp.exe to SharePoint web root | 95 | Near-certain webshell deployment; critical — persistent access |
| Anomalous large POST volume to SharePoint API (20+ reqs, >500KB) | 85 | Consistent with automated deserialization exploit delivery |
| Moderate anomalous POST volume (5+ reqs, >250KB) | 75 | Suspicious serialized payload delivery |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (CISA KEV active exploitation, attribution TBD) | [CISA KEV — CVE-2026-45659](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Nation-state APT groups (SharePoint historically targeted for document access) | [MITRE ATT&CK — T1190](https://attack.mitre.org/techniques/T1190/) |
| Ransomware affiliates (SharePoint as IAB staging target) | [BleepingComputer — SharePoint targeting trends](https://www.bleepingcomputer.com/tag/sharepoint/) |

## References

- [CISA KEV Catalog — CVE-2026-45659 (2026-07-01)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [CWE-502 — Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Threat Intel Report](../../threat-intel/2026-07-03_cisa-gov-cve-2026-45659-sharepoint-rce-kev-active-exploitation.md)
