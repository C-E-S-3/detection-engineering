# UAT-11587 HTA/WSF Lure Execution Delivering Antino Backdoor

## Description

Detects `mshta.exe` or `wscript.exe`/`cscript.exe` executing HTA or WSF files from user-writable directories. This pattern is characteristic of UAT-11587, a China-nexus APT that delivers its custom Antino backdoor via spear-phishing lures disguised as government and institutional documents. Lures are hosted on Cloudflare Pages (`my-*.pages.dev`), Cloudflare R2 (`pub-*.r2.dev`), and AWS CloudFront infrastructure.

False positives are rare for `mshta.exe` in enterprise environments; it has virtually no legitimate business use. `wscript.exe` executing WSF files may occur in some legacy automation scripts — tune by adding a whitelist of known-good parent processes or approved script paths.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | User Execution: Malicious File |
| Technique ID | T1204.002 |
| Secondary Technique | System Binary Proxy Execution: Mshta |
| Secondary Technique ID | T1218.005 |
| Secondary Technique | Command and Scripting Interpreter: Windows Script Host |
| Secondary Technique ID | T1059.005 |

Secondary tactics: Initial Access (TA0001) via T1566.001 (Spearphishing Attachment)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="mshta.exe" OR Processes.process_name="wscript.exe"
         OR Processes.process_name="cscript.exe")
    AND (Processes.process="*\\Users\\*" OR Processes.process="*\\AppData\\*"
         OR Processes.process="*\\Downloads\\*" OR Processes.process="*\\Temp\\*"
         OR Processes.process="*\\Public\\*" OR Processes.process="*\\Desktop\\*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(process_name, "mshta.exe"), 80,
    (like(process_name, "wscript.exe") OR like(process_name, "cscript.exe"))
      AND like(process, "%.wsf%"), 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `mshta.exe` executing from user-writable path | 80 | `mshta.exe` has near-zero legitimate enterprise use; HTA execution from Downloads/Temp/AppData is high-confidence malicious activity |
| `wscript.exe` or `cscript.exe` executing a `.wsf` file from user-writable path | 75 | WSF execution from user-writable locations aligns with lure document delivery tradecraft used by UAT-11587 and other threat actors |
| Any of the above script hosts executing from user-writable path (other file type) | 50 | Baseline detection for analyst review; covers JS, VBS, and other scripts executed via wscript/cscript from untrusted paths |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UAT-11587 (China-nexus) | [Cisco Talos IOCs — GitHub](https://github.com/Cisco-Talos/IOCs/blob/main/2026/09/uat-11587-targets-gov.json) |

## References

- [Cisco Talos — UAT-11587 IOC File (GitHub)](https://github.com/Cisco-Talos/IOCs/blob/main/2026/09/uat-11587-targets-gov.json)
- [MITRE ATT&CK — T1204.002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK — T1218.005: System Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [MITRE ATT&CK — T1059.005: Windows Script Host](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK — T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK — T1622: Debugger Evasion](https://attack.mitre.org/techniques/T1622/)
