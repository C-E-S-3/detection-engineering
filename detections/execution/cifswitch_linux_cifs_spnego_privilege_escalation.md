# CIFSwitch Linux Local Privilege Escalation via cifs.spnego Key Forgery

## Description

Detects exploitation of CIFSwitch (CVE pending), a 19-year-old Linux kernel local privilege escalation vulnerability disclosed May 28, 2026. The flaw allows any unprivileged local user to forge `cifs.spnego` kernel key requests, inject malicious content into a privileged binary's page cache, and achieve deterministic root access. The public PoC is a 732-byte Python3 script using only the standard library.

This detection targets the primary observable: a Python interpreter (non-root) spawning a root-owned shell, which is the expected outcome of a successful CIFSwitch exploit. Secondary detection covers `keyctl` invocations with cifs-related arguments from unprivileged users.

**False positive sources:** Legitimate automation frameworks (Ansible, SaltStack) running Python on managed Linux nodes may spawn privileged shells. Suppress known automation service accounts from the `user` field. CI/CD pipeline runners may also trigger on ephemeral Linux containers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation (TA0004) — note: placed in `execution/` folder due to repo structure |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |
| Secondary Technique | Command and Scripting Interpreter: Python |
| Secondary Technique ID | T1059.006 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| comment "Query 1: Python spawning root shell — primary CIFSwitch exploit indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("bash", "sh", "dash", "zsh")
    AND Processes.user="root"
    AND Processes.parent_process_name IN ("python3", "python", "python2")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    parent_process_name="python3" AND user="root", 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
| comment "Query 2: keyctl with cifs/spnego arguments by non-root user — exploit preparation"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="keyctl"
    AND Processes.user!="root"
    AND (Processes.process="*cifs*" OR Processes.process="*spnego*" OR Processes.process="*request-key*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Python3 parent spawning root-owned bash/sh | 90 | Direct behavioral indicator of CIFSwitch PoC execution — unprivileged Python achieving root shell |
| Python2/python parent spawning root shell | 75 | Older interpreter, same attack pattern |
| `keyctl` + cifs/spnego args from non-root | 80 | Exploit preparation step; `cifs.spnego` key manipulation is the exploit's core mechanism |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any local attacker with unprivileged account | [BleepingComputer — CIFSwitch disclosure (2026-05-30)](https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/) |
| Asim Manizada (researcher, PoC author) | [heyitsas.im — CIFSwitch technical writeup](https://heyitsas.im/posts/cifswitch/) |

## References

- [BleepingComputer — New CIFSwitch Linux flaw gives root on multiple distributions (2026-05-30)](https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/)
- [Asim Manizada — CIFSwitch technical writeup](https://heyitsas.im/posts/cifswitch/)
- [AlmaLinux — CIFSwitch (2026-05-28)](https://almalinux.org/blog/2026-05-28-cifswitch/)
- [oss-security — CIFSwitch disclosure](https://seclists.org/oss-sec/2026/q2/717)
- [MITRE ATT&CK T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1059.006 — Python](https://attack.mitre.org/techniques/T1059/006/)
