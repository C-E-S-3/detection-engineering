# MALFEX — npm Postinstall Hook Executes AutoIt3 Overlord RAT via PNG Steganography

## Description

Detects the MALFEX npm supply chain campaign, in which eight malicious packages (including `function-flag`, `function-color`, `cdn-img-fetch`, and five others) use `postinstall` hooks to execute a multi-stage Windows payload chain. Node.js downloads a steganographically weaponized PNG file from a GitHub-hosted attacker account (`cavecrew`), extracts a hidden loader, then invokes the legitimate signed `AutoIt3.exe` binary to execute an encrypted `.a3x` script containing the **Overlord RAT**. A parallel stealer chain exfiltrates browser passwords, Discord tokens, and cryptocurrency wallet files.

First reported by Checkmarx and CloudSEK; campaign active since August 2023 with 40,767+ downloads. The operator (handle: Murizada) signs payloads using a shared coding identity, making attribution consistent across packages.

False positives for the `node.exe → AutoIt3.exe` chain are extremely rare in enterprise environments. The npm package name detection may generate false positives only if internal packages shadow the malicious names — verify the package registry origin. Tune the GitHub URL query to exclude known-legitimate development repositories in environments with heavy open-source development.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | System Binary Proxy Execution |
| Technique ID | T1218 |

Secondary mapping:

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Supply Chain Compromise: Software Dependencies | T1195.001 |
| Defense Evasion | Obfuscated Files or Information: Steganography | T1027.003 |
| Credential Access | Credentials from Web Browsers | T1555.003 |
| Command and Control | Web Service | T1102 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("node.exe","node","npm.exe","npm")
    Processes.process_name IN ("AutoIt3.exe","AutoIt3_x64.exe","autoit3.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("AutoIt3.exe","AutoIt3_x64.exe")
    (Processes.process="*.a3x*" OR Processes.process="*Oxygen*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="Oxygen.a3x" OR Filesystem.file_name="h.a3x"
     OR Filesystem.file_name="banner.png")
    (Filesystem.file_path="*\\node_modules\\*" OR Filesystem.file_path="*\\AppData\\*"
     OR Filesystem.file_path="*\\Temp\\*")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
     Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| node.exe/npm spawning AutoIt3.exe | 95 | Highly anomalous; AutoIt3 is not a standard Node.js dependency |
| AutoIt3.exe executing .a3x script | 95 | AutoIt3 running compiled scripts from user directories is the MALFEX Overlord RAT execution path |
| Oxygen.a3x or h.a3x file creation in npm/temp directories | 90 | Named payload artifacts from MALFEX campaign |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Murizada / MALFEX (unattributed solo operator) | [Checkmarx MALFEX Report](https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/) |

## References

- [MALFEX npm Malware Campaign — Checkmarx](https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/)
- [Eight Malicious npm Packages Deliver Overlord RAT — The Hacker News](https://thehackernews.com/2026/10/eight-malicious-npm-packages-downloaded.html)
- [Long-Running NPM Malware Campaign Accumulates 40,000 Downloads — SecurityWeek](https://www.securityweek.com/long-running-npm-malware-campaign-accumulates-40000-downloads/)
- [MITRE ATT&CK T1195.001 — Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [MITRE ATT&CK T1027.003 — Obfuscated Files or Information: Steganography](https://attack.mitre.org/techniques/T1027/003/)
