# Linux Proc Filesystem and Shadow File Credential Dumping

## Description

Detects OS credential dumping on Linux hosts via two primary techniques:

1. **T1003.007 — /proc Filesystem**: Attackers use `ptrace(PTRACE_PEEK*)`, `process_vm_readv`, or direct `/proc/<pid>/mem` reads to extract credentials from process memory. Common tools include `gdb`, `gcore`, and custom Python/C scripts. `/proc/kcore` exposes raw kernel memory and is a high-severity target.

2. **T1003.008 — /etc/passwd and /etc/shadow**: Direct reads of `/etc/shadow` by unprivileged users to obtain password hashes for offline cracking. The shadow file is normally root-readable only; any non-root access is anomalous.

**False positive sources:**
- Legitimate `gdb` debugging sessions by developers (expect `auid` matching a known developer account)
- Security scanning tools that read `/proc/kcore` (rare; should be in a known maintenance window)
- Backup agents that access `/etc/shadow` (should run as root; flag non-root reads)

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | OS Credential Dumping: /proc Filesystem |
| Technique ID | T1003.007 |
| Sub-technique | OS Credential Dumping: /etc/passwd and /etc/shadow |
| Sub-technique ID | T1003.008 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
index=linux sourcetype=auditd
(key="credential_dumping" OR key="proc_kcore" OR key="etcpasswd")
| eval risk_score=case(
    key="proc_kcore", 95,
    key="credential_dumping" AND uid!="0", 90,
    key="credential_dumping" AND uid="0", 60,
    key="etcpasswd" AND uid!="0", 85,
    key="etcpasswd" AND uid="0", 30,
    1=1, 40)
| where risk_score >= 60
| stats min(_time) as firstTime max(_time) as lastTime count by host uid auid key syscall risk_score
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
| eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| table firstTime lastTime host uid auid key syscall count risk_score
| sort - risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `/proc/kcore` accessed (any user) | 95 | Raw kernel memory; no legitimate use case in production |
| ptrace PEEK or process_vm_readv by non-root | 90 | Strong indicator of credential dumping post-compromise |
| ptrace PEEK or process_vm_readv by root | 60 | Could be legitimate debugging, but unusual outside maintenance |
| `/etc/shadow` read by non-root | 85 | Shadow file is root-only; non-root access = compromise |
| `/etc/shadow` read by root | 30 | Routine in some backup/auth scenarios |

## Wazuh Rules

These detections are implemented as Wazuh auditd rules:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100620 | 11 | /etc/passwd or /etc/shadow accessed (any access) |
| 100623 | 14 | /etc/shadow accessed by unprivileged user (T1003.008) |
| 100624 | 13 | ptrace PEEK or process_vm_readv detected (T1003.007) |
| 100625 | 15 | Process memory read by unprivileged user (T1003.007) |
| 100626 | 15 | /proc/kcore accessed (T1003.007) |

Rules 100624-100626 require auditd keys `credential_dumping` and `proc_kcore` deployed via the `ubuntu-auditd-security` and `proxmox-auditd-security` roles (inframan PR #111).

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| APT29 (Cozy Bear) | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/) — uses proc filesystem dumping post-compromise |
| Lazarus Group | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) — credential harvesting via /etc/shadow |
| Generic post-exploitation | Tools: mimipenguin, LaZagne, pspy, gdb credential extraction |

## References

- [MITRE ATT&CK T1003.007](https://attack.mitre.org/techniques/T1003/007/)
- [MITRE ATT&CK T1003.008](https://attack.mitre.org/techniques/T1003/008/)
- [Atomic Red Team T1003.007](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.007/T1003.007.md)
- [mimipenguin — Linux credential dumper](https://github.com/huntergregal/mimipenguin)
- [Linux auditd ptrace monitoring](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
