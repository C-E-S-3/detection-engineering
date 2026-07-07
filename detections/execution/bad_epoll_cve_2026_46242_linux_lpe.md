# Bad Epoll Linux Kernel Local Privilege Escalation (CVE-2026-46242)

## Description

Detects exploitation of CVE-2026-46242 ("Bad Epoll"), a use-after-free race condition in the Linux kernel's `epoll` subsystem affecting kernels 5.10–6.11 and Android kernel 6.4+. The vulnerability allows an unprivileged local user to achieve root by rapidly adding and removing file descriptors from an epoll instance, winning a race window that frees a kernel object while a live reference persists.

The public PoC by Jaeyoung Chung (Seoul National University) achieves root with approximately 99% reliability using paired goroutines racing on `epoll_ctl(EPOLL_CTL_ADD)` and `epoll_ctl(EPOLL_CTL_DEL)` calls. Exploitation generates a distinctive burst of epoll syscalls from a single unprivileged process.

**Primary detection opportunity:** auditd syscall logging for rapid `epoll_ctl` bursts. Secondary signal: an unprivileged process calling `setuid(0)` successfully.

**Expected false positives:** Some high-performance server applications (io_uring-heavy workloads, event-driven servers) may generate elevated epoll syscall rates. Tune the burst threshold to your environment; `setuid(0)` success from a non-root parent is near-zero false-positive.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation (TA0004), Execution (TA0002) |
| Technique | Exploitation for Privilege Escalation (T1068) |
| Sub-technique | N/A |

## Lockheed Martin Kill Chain

| Field | Value |
|-------|-------|
| Phase | Exploitation |

## Splunk Detection Query

### Query 1 — Auditd: Rapid epoll Syscall Burst (Race Exploitation Pattern)

```spl
index=linux_audit type=SYSCALL syscall IN ("epoll_ctl","epoll_create","epoll_create1")
| bucket _time span=10s
| stats count as syscall_count, dc(pid) as unique_pids, values(syscall) as syscalls
  by host, auid, uid, _time
| where syscall_count >= 50
| eval risk_score=case(syscall_count >= 200, 90, syscall_count >= 100, 75, 1=1, 60)
| where risk_score >= 60
| `security_content_ctime(_time)`
| table _time host auid uid syscall_count unique_pids syscalls risk_score
```

Requires auditd configured with: `-a always,exit -F arch=b64 -S epoll_ctl,epoll_create,epoll_create1`

### Query 2 — Auditd: Unprivileged setuid(0) Success (Post-LPE Signal)

```spl
index=linux_audit type=SYSCALL syscall="setuid" success="yes" a0="0x0"
| where uid != "0" AND euid != "0"
| stats count min(_time) as firstTime max(_time) as lastTime
  by host, pid, uid, exe, comm
| eval risk_score=95
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host uid pid exe comm risk_score
```

### Query 3 — Sysmon for Linux: Root Process Spawned from Non-Root Parent

```spl
`sysmon_linux` EventCode=1
| where NOT (User="root" OR User="0")
| eval parent_uid=replace(ParentUser, "\\(.*\\)", "")
| where User="root" AND parent_uid != "root" AND parent_uid != "0"
| stats count min(_time) as firstTime max(_time) as lastTime
  by Computer, User, ParentUser, Image, CommandLine, ParentImage
| eval risk_score=90
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime Computer ParentUser User ParentImage Image CommandLine risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | Non-root process successfully calls `setuid(0)` (Query 2) — near-certain LPE |
| 90 | Root process spawned from non-root parent (Query 3) |
| 90 | epoll syscall burst ≥ 200 events in 10s from single UID (Query 1) |
| 75 | epoll syscall burst ≥ 100 events in 10s from single UID (Query 1) |
| 60 | epoll syscall burst ≥ 50 events in 10s from single UID (Query 1) |

## Associated Threat Actors

| Actor | Notes |
|-------|-------|
| Any local attacker | No attribution — public PoC available; any user with local code execution on a vulnerable kernel can exploit |
| Post-exploitation escalation | Common follow-on after RCE, SSH brute force, or container escape to unprivileged shell on Linux host |

## References

- [The Hacker News — Bad Epoll CVE-2026-46242 (2026-07-04)](https://thehackernews.com/2026/07/new-bad-epoll-linux-kernel-flaw-lets.html)
- [GitHub PoC — J-jaeyoung/bad-epoll](https://github.com/J-jaeyoung/bad-epoll)
- [NVD — CVE-2026-46242](https://nvd.nist.gov/vuln/detail/CVE-2026-46242)
- [Linux kernel patch commit a6dc643c6931](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a6dc643c6931)
- [MITRE ATT&CK — T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [Threat Intel — CVE-2026-46242 Bad Epoll Report](../../threat-intel/2026-07-07_thehackernews-com-cve-2026-46242-bad-epoll-linux-lpe.md)
