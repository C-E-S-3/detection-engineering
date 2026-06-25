# Linux Kernel Copy Fail Local Privilege Escalation (CVE-2026-31431)

## Description

Detects exploitation of CVE-2026-31431 (Copy Fail), a Linux kernel local privilege escalation in the `algif_aead` module of the AF_ALG (userspace crypto API). Introduced in 2017 (commit 72548b09), the flaw allows an unprivileged local user to perform a controlled 4-byte write into the kernel's page cache of any readable file — including setuid binaries — by racing the kernel's AEAD in-place crypto operation via `socket(AF_ALG, ...)` and `splice()` syscalls approximately 40 times. Successful exploitation achieves root access in seconds.

The vulnerability is in the CISA Known Exploited Vulnerabilities (KEV) catalog (added May 2026) and is being actively exploited. All kernels since 2017 are affected. A public 732-byte Python3 PoC was released by Theori on April 29, 2026.

**Detection approach:** AF_ALG (address family 38) socket creation is extremely rare in production Linux environments outside of `cryptsetup` and `systemd-cryptsetup`. Any non-crypto process opening an AF_ALG socket is immediately suspicious. The exploit's race-condition loop (~40 iterations) creates a frequency burst detectable within a 60-second window.

**False positive sources:** `cryptsetup`, `systemd-cryptsetup`, strongSwan's `charon` IKE daemon, and `openssl` use AF_ALG for kernel-accelerated encryption — these are excluded in the high-confidence rule (102802). An `openssl speed` benchmark may generate brief AF_ALG bursts but well below the 15-event/60s frequency threshold.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation (TA0004) — placed in `execution/` per repo structure |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |
| Secondary Technique | Setuid and Setgid |
| Secondary Technique ID | T1548.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| comment "Query 1: AF_ALG socket burst by non-root — primary Copy Fail exploit-loop indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*socket*AF_ALG*"
    OR Processes.process="*socket*38*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    user!="root" AND count >= 15, 95,
    user!="root" AND count >= 5, 80,
    1=1, 40)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name count risk_score
```

```spl
| comment "Query 2: Non-root process spawning root shell within 2min of AF_ALG activity (auditd source)"
| index=wazuh sourcetype=wazuh
  rule.groups IN ("copy_fail","af_alg")
| stats count by hostname, audit.auid, _time
| join type=left hostname
    [ search index=wazuh sourcetype=wazuh rule.groups="privilege_escalation" audit.key="priv_esc"
    | fields hostname, audit.auid, _time
    | rename _time as priv_time ]
| where abs(_time - priv_time) <= 120
| eval risk_score=92
| table _time priv_time hostname audit.auid risk_score
```

```spl
| comment "Query 3: Frequency of AF_ALG socket events per user per host per hour"
| index=wazuh sourcetype=wazuh rule.id IN (102800, 102801, 102802)
| bin _time span=1h
| stats count by _time, hostname, audit.auid
| where count >= 5 AND audit.auid != "0" AND audit.auid != "4294967295"
| eval risk_score=case(
    count >= 40, 95,
    count >= 15, 85,
    count >= 5, 65,
    1=1, 40)
| where risk_score >= 65
| table _time hostname audit.auid count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| ≥40 AF_ALG events from non-root in 60s | 95 | Direct match for Copy Fail race-condition loop (exploit completes in ~40 iterations) |
| ≥15 AF_ALG events from non-root in 60s | 85 | High-frequency burst below typical PoC iteration count; strong exploitation indicator |
| AF_ALG by non-root non-crypto binary | 82 | Completely unexpected AF_ALG usage outside cryptsetup/systemd-cryptsetup/charon |
| AF_ALG burst followed by privilege escalation within 2min | 92 | Exploitation chain behavioral correlation — highest confidence |
| AF_ALG by non-root + splice() by same user | 75 | Two-syscall exploit prerequisites observed from same user |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Any local attacker / initial access broker | [Theori PoC (2026-04-29) — CVE-2026-31431 GitHub](https://github.com/theori-io/copy-fail-CVE-2026-31431) |
| Cloud-hosted threat actors (container escape) | [Sysdig — Copy Fail container escape vector](https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds) |
| APT initial access → root escalation chain | [CISA KEV — CVE-2026-31431 actively exploited](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |

## References

- [Microsoft Security Blog — CVE-2026-31431 enables Linux root privilege escalation (2026-05-01)](https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/)
- [Unit42 (Palo Alto) — Copy Fail deep dive](https://unit42.paloaltonetworks.com/cve-2026-31431-copy-fail/)
- [Elastic Detection Rules — potential_copy_fail_cve_2026_31431 via AF_ALG socket](https://www.elastic.co/guide/en/security/8.19/potential-copy-fail-cve-2026-31431-exploitation-via-af-alg-socket.html)
- [Cloudflare — How we responded to Copy Fail](https://blog.cloudflare.com/copy-fail-linux-vulnerability-mitigation/)
- [CERT-EU — High Vulnerability in Linux Kernel (Copy Fail)](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [MITRE ATT&CK — T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [Wazuh rules — `wazuh/rules/linux_cve_2026_31431_copy_fail.xml` (rules 102800-102806)](../../wazuh/rules/linux_cve_2026_31431_copy_fail.xml)
