# N-able N-central 4EverAble2Shell — Apache Axis RCE Post-Compromise Execution (CVE-2026-90436)

## Description

Detects post-exploitation process execution on N-able N-central RMM servers consistent with the "4EverAble2Shell" attack chain (CVE-2026-90436). The chain abuses an Apache Axis flaw in N-central's Legacy API to achieve unauthenticated root-level code execution. Requires Legacy API to be enabled, which is non-default. Observed post-compromise payloads include shell scripts downloading XMRig Monero miners.

Triggers on Java-based N-central/Tomcat parent processes spawning OS shell interpreters (`sh`, `bash`), download utilities (`curl`, `wget`), or crypto mining binaries. False positives may occur if N-central runs legitimate scheduled maintenance scripts from Java — correlate with unexpected outbound connections or unusual child process arguments.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution |
| Tactic ID | TA0002 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary tactics: Privilege Escalation (TA0004 / T1068), Impact (TA0040 / T1496 — Resource Hijacking)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("java", "java.exe", "catalina.sh", "startup.sh")
    AND Processes.process_name IN ("sh", "bash", "dash", "curl", "wget", "xmrig")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "xmrig"), 95,
    match(process_name, "curl|wget") AND match(process, "http|\.sh"), 85,
    match(process_name, "bash|sh|dash") AND match(process, "-c "), 70,
    1=1, 55)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `xmrig` spawned from Java parent | 95 | Direct cryptominer execution — confirmed post-compromise payload for 4EverAble2Shell |
| `curl`/`wget` from Java parent with HTTP URL or shell script argument | 85 | Payload download stage matching observed 4EverAble2Shell post-exploitation chain |
| `sh`/`bash`/`dash` from Java parent with `-c` inline command flag | 70 | Inline shell command from app server — high suspicion for exploitation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Opportunistic financially motivated actors | [BleepingComputer — 4EverAble2Shell exploited for XMRig deployment](https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/) |

## References

- [BleepingComputer — New N-able "4EverAble2Shell" zero-day exploited hours after PoC released](https://www.bleepingcomputer.com/news/security/new-n-able-4everable2shell-zero-day-exploited-hours-after-poc-released/)
- [SecurityWeek — Hackers Exploit New N-central Zero-Day Hours After PoC Publication](https://www.securityweek.com/hackers-exploit-new-n-central-zero-day-hours-after-poc-publication/)
- [The Hacker News — New N-central Exploits Work Against Patched Servers, Enable Root RCE](https://thehackernews.com/2026/11/new-n-central-exploits-work-against.html)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1496 Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
