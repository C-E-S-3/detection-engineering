# UNC6508 INFINITERED: REDCap Web Shell Upgrade-Intercepting Persistence

## Description

Detects INFINITERED malware deployed by China-nexus threat actor UNC6508 against internet-exposed REDCap research database servers. INFINITERED is a three-component implant that (1) injects a malicious PHP web shell (help.php) into the REDCap application, (2) intercepts REDCap upgrade packages to reinject the malicious code after every software update (making patch-based remediation ineffective), and (3) operates a backdoor communicating via HTTP Cookie REDCAP-TOKEN headers.

The detection focuses on the persistence mechanism: web (PHP/httpd) processes spawning OS command interpreters or download utilities, and known INFINITERED file hashes appearing in web server directories. False positives include legitimate PHP-exec-based REDCap plugins or administrator-level debugging sessions — tune with allowlists for known-good processes.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Server Software Component: Web Shell |
| Technique ID | T1505.003 |

Secondary Techniques:
- T1554 — Compromise Client Software Binary (upgrade interception)
- T1190 — Exploit Public-Facing Application (initial access via REDCap)
- T1056.003 — Input Capture: Web Portal Capture (credential harvesting)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_hash IN (
    "ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7",
    "db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136",
    "c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b",
    "8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec",
    "51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045",
    "4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b",
    "58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user file_name file_path file_hash risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("apache2", "httpd", "nginx", "php", "php-fpm", "php8", "php7", "php8.0", "php8.1", "php8.2")
    AND Processes.process_name IN ("bash", "sh", "dash", "id", "whoami", "wget", "curl", "nc", "ncat",
                                    "python", "python3", "perl", "ruby", "awk", "sed", "find")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("bash","sh","dash"), 85,
    process_name IN ("wget","curl","nc","ncat"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known INFINITERED file hash match | 100 | Hash match is definitive evidence of INFINITERED infection |
| Web server spawning download tool (wget/curl/nc/ncat) | 90 | Very high confidence web shell execution or reverse shell |
| Web server spawning shell interpreter (bash/sh/dash) | 85 | High confidence OS command execution via web shell |
| Web server spawning enumeration tool (id/whoami) | 75 | Suspicious but may have legitimate PHP-exec uses |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UNC6508 (China-nexus APT) | [Google GTIG — PRC Targets US Medical Research (2026-06-15)](https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research) |

## References

- [Google GTIG — Public and Private Medical Community Targeted by China-Nexus Threat Actor (2026-06-15)](https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research)
- [MITRE ATT&CK — T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1554 Compromise Client Software Binary](https://attack.mitre.org/techniques/T1554/)
- [BleepingComputer — Chinese hackers breach REDCap servers, steal medical research](https://www.bleepingcomputer.com/news/security/chinese-hackers-breach-redcap-servers-steal-medical-research/)
