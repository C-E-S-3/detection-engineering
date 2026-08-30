# SparkRAT OPSWAT ardrv.sys BYOVD Driver Installation

## Description

Detects installation of the OPSWAT AppRemover kernel driver (`ardrv.sys`) as a Windows service, which is the Bring Your Own Vulnerable Driver (BYOVD) technique observed in the Cambodia-focused SparkRAT campaign (Acronis TRU, August 2026). The driver contains CVE-2026-36425 — an improper access control flaw in IOCTL handler 0x2420031 — that allows any unprivileged process to terminate arbitrary processes, including EDR and AV agents running as SYSTEM.

Legitimate installations of OPSWAT AppRemover are uncommon in enterprise environments. Any detection of `ardrv.sys` being registered as a service should be treated as high-confidence malicious activity unless OPSWAT AppRemover is an authorized, documented tool in the environment.

False positives: organizations that legitimately deploy OPSWAT AppRemover for uninstalling AV/security products as part of managed endpoint migration workflows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |

Secondary techniques: T1574.002 (Hijack Execution Flow: DLL Side-Loading), T1620 (Reflective Code Loading)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Services
where Services.driver_path="*ardrv.sys*"
by Services.dest Services.user Services.service_name Services.driver_path Services.start_mode
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(driver_path, "(?i)ardrv\.sys"), 85)
| where risk_score >= 85
| table firstTime lastTime dest user service_name driver_path start_mode risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process="*ardrv.sys*" OR
      (Processes.process_name="sc.exe" AND Processes.process="*type= kernel*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)ardrv\.sys"), 85,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `ardrv.sys` in `driver_path` (Services data model) | 85 | Direct match on known BYOVD driver filename; CVE-2026-36425 actively exploited in SparkRAT campaign; no legitimate enterprise use cases in most environments |
| `sc.exe` creating kernel-type service (Processes data model) | 50 | Suspicious but not definitive; kernel service creation from command line is unusual outside IT operations |
| `ardrv.sys` in `sc.exe` command line | 85 | Combined: sc.exe registering the specific BYOVD driver |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Cambodia-Focused SparkRAT Cluster (unattributed) | [Acronis TRU (2026-08-27)](https://www.acronis.com/en/tru/posts/cambodia-focused-cluster-uses-multi-stage-infection-chain-with-localized-lures/) |
| Scattered Spider | [MITRE ATT&CK G1015](https://attack.mitre.org/groups/G1015/) |
| BlackByte | [CISA Advisory (2023)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a) |
| Medusa Ransomware | [CISA Advisory AA24-058A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-058a) |

## References

- [Acronis TRU — Cambodia-Focused Cluster Uses Multi-Stage Infection Chain with Localized Lures (2026-08-27)](https://www.acronis.com/en/tru/posts/cambodia-focused-cluster-uses-multi-stage-infection-chain-with-localized-lures/)
- [CVE-2026-36425 — OPSWAT AppRemover ardrv.sys Improper Access Control](https://nvd.nist.gov/vuln/detail/CVE-2026-36425)
- [MITRE ATT&CK — T1562.001 Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK — T1574.002 Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1620 Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
- [MITRE ATT&CK — SparkRAT S1039](https://attack.mitre.org/software/S1039/)
