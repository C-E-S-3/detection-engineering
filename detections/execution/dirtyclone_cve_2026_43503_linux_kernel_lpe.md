# DirtyClone Linux Kernel LPE via vmsplice/splice Page-Cache Corruption (CVE-2026-43503)

## Description

Detects exploitation of CVE-2026-43503 ("DirtyClone"), a high-severity (CVSS 8.8) Linux kernel local privilege escalation vulnerability affecting kernels 6.1–6.12, patched in v7.1-rc5 (May 24, 2026). An unprivileged local user (UID ≥ 1000) exploits a flaw in `vmsplice()` + `splice()` syscall interaction to corrupt the kernel page cache of privileged files without triggering disk writes, bypassing file-integrity monitoring tools entirely. The attack chain also uses XFRM policy creation from a user namespace as a kernel memory primitive and installs netfilter TEE rules on the loopback interface to observe the corrupted data.

**Expected false positives:** Legitimate uses of `vmsplice()` from unprivileged processes are extremely rare and almost exclusively restricted to specific media transcoding or IPC frameworks; any observation of both `vmsplice` and `splice` from the same non-root PID should be treated as high-priority. Netfilter TEE rules on loopback from non-root are essentially never legitimate.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation (TA0004) / Defense Evasion (TA0005) |
| Technique | T1068 — Exploitation for Privilege Escalation |
| Sub-technique | N/A |
| Secondary technique | T1562 — Impair Defenses (netfilter TEE channel) |

## Lockheed Martin Kill Chain Phase

| Phase | Applies |
|-------|---------|
| Exploitation | Yes — kernel exploit triggered post-initial-access to escalate from local user to root |
| Actions on Objectives | Yes — post-LPE, attacker reads /etc/shadow, SSH keys, or modifies setuid binaries |

## Splunk Detection Query

### Query 1 — vmsplice() + splice() Syscall Pair from Unprivileged UID

```spl
`linux_audit` syscall IN ("vmsplice","splice")
    NOT (auid="-1" OR auid="4294967295" OR uid="0" OR auid="0")
| eval auid_n=tonumber(auid), uid_n=tonumber(uid)
| where auid_n >= 1000 OR uid_n >= 1000
| stats count values(syscall) as syscalls_seen
    min(_time) as firstTime max(_time) as lastTime
    values(exe) as executables values(comm) as commands
    by host pid auid uid
| where mvcount(syscalls_seen) >= 2
| eval risk_score=case(
    match(mvjoin(executables," "), "^/tmp|^/dev/shm|^/run/user|^/var/tmp"), 95,
    match(mvjoin(executables," "), "^/home"), 85,
    1=1, 75)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime host uid auid pid executables commands syscalls_seen count risk_score
```

### Query 2 — Netfilter TEE Rule on Loopback Interface by Non-Root

```spl
`linux_audit` syscall="execve"
    (comm="iptables" OR comm="ip6tables" OR comm="nft" OR comm="xtables-multi")
    NOT (uid="0" OR auid="0")
| where match(_raw, "(?i)TEE|-j TEE|jump.*TEE|TEE.*gw")
    AND match(_raw, "(?i) lo | -i lo | -o lo |loopback")
| eval auid_n=tonumber(auid)
| where auid_n >= 1000
| eval risk_score=95
| `security_content_ctime(_time)`
| rename _time as observedTime
| table observedTime host uid auid pid comm risk_score
```

### Query 3 — XFRM Policy Creation from User Namespace by Unprivileged Process

```spl
`linux_audit` type="SYSCALL" syscall="setsockopt"
| where match(_raw, "(?i)XFRM|AF_KEY|xfrm_policy|NETLINK_XFRM")
| eval auid_n=tonumber(auid), uid_n=tonumber(uid)
| where (auid_n >= 1000 OR uid_n >= 1000)
    AND NOT (auid_n=4294967295 OR auid_n=-1)
| eval risk_score=85
| `security_content_ctime(_time)`
| rename _time as observedTime
| table observedTime host uid auid pid exe comm risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 95 | vmsplice+splice pair from executable in /tmp, /dev/shm, /run/user, /var/tmp (staging paths) |
| 95 | Netfilter TEE rule on loopback interface by non-root |
| 85 | vmsplice+splice pair from executable in /home (user space) |
| 85 | XFRM policy from user namespace by unprivileged UID |
| 75 | vmsplice+splice pair from non-root UID in any other path |

## Associated Threat Actors

| Actor | Notes | References |
|-------|-------|-----------|
| Any local attacker (CVE-2026-43503) | CVE-2026-43503 requires only local unprivileged access; no public exploit actor attribution as of June 28, 2026; high risk from insider threat, post-exploitation lateral movement in shared systems, and CI/CD runner compromise | [JFrog Security Research — CVE-2026-43503](https://research.jfrog.com/post/cve-2026-43503-dirtyclone-linux-kernel-lpe/), [LatestHackingNews](https://latesthackingnews.com/2026/06/28/cve-2026-43503-dirtyclone-linux-kernel-lpe-analysis/) |

## References

- [JFrog Security Research — CVE-2026-43503 DirtyClone](https://research.jfrog.com/post/cve-2026-43503-dirtyclone-linux-kernel-lpe/)
- [LatestHackingNews — CVE-2026-43503 Analysis](https://latesthackingnews.com/2026/06/28/cve-2026-43503-dirtyclone-linux-kernel-lpe-analysis/)
- [NVD — CVE-2026-43503](https://nvd.nist.gov/vuln/detail/CVE-2026-43503)
- [MITRE ATT&CK — T1068](https://attack.mitre.org/techniques/T1068/)
- [Linux Kernel v7.1-rc5 Changelog](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/?h=v7.1-rc5)
