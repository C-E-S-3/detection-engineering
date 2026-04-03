# Progress ShareFile Pre-Auth RCE via Webshell Upload (CVE-2026-2699, CVE-2026-2701)

## Description

Detects exploitation of a two-stage pre-authentication RCE chain in Progress ShareFile's Storage Zones Controller component. CVE-2026-2699 allows attackers to bypass authentication by manipulating HTTP redirect behavior and extract internal HMAC secrets. CVE-2026-2701 allows uploading malicious ASPX webshells to the application webroot once authentication is bypassed. Ransomware groups have historically targeted ShareFile (and similar managed file transfer platforms: MOVEit, GoAnywhere, Cleo) as high-value initial access vectors due to sensitive data stored in transit. Chained exploitation reaches RCE in a single automated pass. Common false positives: legitimate ShareFile administration and API integrations; authorized .NET deployment workflows should be baseline-excluded by process and source IP.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary techniques: T1059.007 (Command and Scripting Interpreter: JavaScript/ASP.NET — webshell execution), T1505.003 (Server Software Component: Web Shell), T1552 (Unsecured Credentials — HMAC secret extraction)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.http_method="POST"
    AND (Web.url="*.aspx" OR Web.url="*/Upload*" OR Web.url="*/UploadFile*"
         OR Web.url="*/StorageZone*" OR Web.url="*/SFAPI*")
    AND Web.status IN ("200","201","302")
    AND Web.dest_port IN ("443","80","8443")
  by Web.dest Web.src Web.url Web.http_method Web.status Web.bytes_in
     Web.http_user_agent
| `drop_dm_object_name(Web)`
| eval risk_score=case(
    match(url, "(?i)\.aspx$") AND match(url, "(?i)/upload|/storageZone"), 90,
    match(url, "(?i)/SFAPI") AND match(http_user_agent, "(?i)python|curl|java|wget|go-http"), 85,
    match(url, "(?i)/upload") AND bytes_in > 100000, 80,
    match(url, "(?i)\.aspx") AND http_method="POST", 80,
    1=1, 60)
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest src url http_method status bytes_in http_user_agent risk_score
```

**Supplemental: ASPX webshell creation on ShareFile Storage Zone host**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.aspx"
    AND (Filesystem.file_path="*\\inetpub\\*" OR Filesystem.file_path="*\\wwwroot\\*"
         OR Filesystem.file_path="*\\StorageCenter\\*" OR Filesystem.file_path="*\\SPS\\*")
    AND Filesystem.action IN ("created","modified")
    AND NOT Filesystem.process_name IN ("msiexec.exe","TrustedInstaller.exe","w3wp.exe")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
     Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| eval risk_score=case(
    NOT match(process_name, "(?i)msiexec|trustedinstaller|setup"), 90,
    match(file_path, "(?i)StorageCenter|SPS\\\\"), 85,
    1=1, 80)
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name file_path file_name risk_score
```

**Supplemental: Webshell execution — IIS worker spawning unexpected children**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="w3wp.exe"
    AND Processes.process_name IN ("cmd.exe","powershell.exe","powershell_ise.exe",
        "wscript.exe","cscript.exe","mshta.exe","certutil.exe","bitsadmin.exe",
        "net.exe","net1.exe","whoami.exe","ping.exe","nslookup.exe","curl.exe",
        "wget.exe","certreq.exe","bash.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process_name, "(?i)powershell") AND match(process, "(?i)-enc|-exec bypass|-nop"), 95,
    match(process_name, "(?i)cmd|powershell") AND match(process, "(?i)whoami|net user|net localgroup"), 90,
    match(process_name, "(?i)certutil|bitsadmin|curl|wget") AND match(process, "(?i)http"), 90,
    match(process_name, "(?i)cmd|powershell"), 85,
    1=1, 75)
| where risk_score >= 85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| ASPX file POST to /upload or /StorageZone path, 200 response | 90 | Webshell staged via CVE-2026-2701 exploit; no legitimate use case for ASPX uploads to these paths |
| ASPX file created in IIS webroot by non-installer process | 85-90 | Successful webshell placement; file write by web worker or exploit process |
| w3wp.exe spawning cmd.exe/PowerShell | 85-95 | Active webshell execution; IIS worker should never directly spawn CLI processes |
| w3wp.exe spawning download tools (certutil, curl, bitsadmin) | 90 | Second-stage payload download from active webshell |
| Automated User-Agent hitting ShareFile API | 85 | CVE-2026-2699 exploitation tooling fingerprint |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| LockBit Affiliates | Historically exploited MOVEit, GoAnywhere, and Cleo file transfer vulnerabilities; ShareFile is the same target category |
| Cl0p Ransomware Group | Pioneer of managed file transfer mass exploitation (MOVEit Transfer CVE-2023-34362); ShareFile CVE-2026-2699/2701 follows identical exploitation pattern |
| Various Ransomware Affiliates | Managed file transfer platforms are consistently targeted for sensitive data exfiltration before encryption; CVE chains enabling pre-auth RCE are immediately weaponized |

## References

- [BleepingComputer - Progress ShareFile CVE-2026-2699/2701](https://www.bleepingcomputer.com/news/security/new-progress-sharefile-flaws-can-be-chained-in-pre-auth-rce-attacks/)
- [MITRE ATT&CK - T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK - T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [Progress ShareFile Patch - Storage Zones Controller 5.12.4](https://www.progress.com/sharefile)
