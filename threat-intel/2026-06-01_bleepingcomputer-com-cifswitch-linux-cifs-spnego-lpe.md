---
scraped_at: 2026-06-01T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/
report_type: threat-intel
severity: high
title: "CIFSwitch: 19-Year-Old Linux Kernel Local Privilege Escalation via cifs.spnego Key Forgery (CVE Pending)"
---

## 1. IOCs

No network IOCs (domains, IPs, or file hashes) are applicable — CIFSwitch is a **local privilege escalation** vulnerability with no C2 component. Exploitation produces host-level forensic indicators only.

**Behavioral / Host IOCs:**
- Non-root Python3 process spawning a root-owned shell (`bash`, `sh`, `dash`)
- `keyctl` invocations involving `cifs.spnego` key type by unprivileged users
- Short-lived Python3 process using socket and splice syscalls immediately before a privilege change
- New root shell without prior `sudo`/`su` authentication event in surrounding audit log

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Any local user exploits logic flaw in `cifs.spnego` key type handling to inject forged kernel key requests and achieve root access via a deterministic 732-byte Python script |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | Published PoC is a self-contained Python3 script using only the standard library (socket, setsockopt, splice, sendmsg, recvmsg); requires no external dependencies |
| Defense Evasion | T1027 | Obfuscated Files or Information | Exploit leaves minimal forensic footprint; uses only standard kernel syscalls with no dropped binaries |

**Attack Chain:**
1. An attacker with any local, unprivileged account on a vulnerable Linux system runs the CIFSwitch PoC Python3 script.
2. The script forges a `cifs.spnego` key description, abusing a 19-year-old (2007) optimization in the kernel's CIFS client — the `algif_aead` cryptographic template improperly allows user-mode writes into kernel page cache.
3. By targeting a setuid binary (e.g., `/usr/bin/passwd`), the attacker overwrites its in-memory page cache copy, replacing the binary content with a malicious payload.
4. When the setuid binary is next executed, the malicious payload runs with root privileges, yielding a root shell.
5. Exploitation is deterministic — no race conditions or kernel offsets required; a single Python script succeeds reliably across all affected distributions.

## 3. Malware & Tools

| Tool | Description |
|------|-------------|
| CIFSwitch PoC (Python3, 732 bytes) | Public proof-of-concept published by researcher Asim Manizada; uses Python standard library only; exploits cifs.spnego key type to gain root on affected distributions |

No malware family has been publicly linked to CIFSwitch exploitation at the time of this report. Given the public PoC availability and reliability, post-exploitation activity should be assumed once successful privilege escalation occurs.

## 4. Threat Actor / Campaign Attribution

No threat actor has been publicly attributed to CIFSwitch exploitation. The vulnerability was discovered and disclosed by security researcher **Asim Manizada** (heyitsas.im) on **May 28, 2026**, following coordinated disclosure with major Linux distribution security teams under embargo through May 27, 2026.

**Exploitation prerequisites:**
1. Vulnerable kernel version (introduced 2007; fixed in kernels including mainline commit `a664bf3d603d`)
2. `cifs-utils` ≥ 6.14 installed (some older variants also affected)
3. Unprivileged user namespaces enabled (default on most desktop Linux distros)
4. SELinux or AppArmor policy that does not block the attack chain (default-exploitable on listed distributions)

**Confirmed stock-exploitable distributions (default install, no additional hardening):**
- AlmaLinux 9.7 Workstation and Azure cloud image
- Rocky Linux 9 Workstation
- CentOS Stream 9 GNOME
- Linux Mint Cinnamon 21.3 and 22.3
- Kali Linux 2021.4 through 2026.1 (headless)
- SUSE Linux Enterprise Server (SLES) 15 SP7 and SAP variants

**Not exploitable by default (blocking SELinux/AppArmor policies):**
Ubuntu 26.04, Fedora 40–44, CentOS Stream 10, Rocky Linux 10, SLES 16, AlmaLinux 10, openSUSE Leap 16

**CVE:** Pending assignment at time of publication.

## 5. Splunk Detection Searches

```spl
| comment "Search 1: Python3 spawning a root shell — primary signal for CIFSwitch PoC execution"
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
| comment "Search 2: keyctl invocation by non-root user with cifs-related arguments — exploit preparation signal"
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

```spl
| comment "Search 3: Unexpected privilege gain — non-root user spawning processes that run as root without sudo/su"
index=os sourcetype IN ("linux_secure", "linux_audit") (type=EXECVE OR "execve")
| rex field=_raw "uid=(?P<uid>\d+).*euid=(?P<euid>\d+)"
| where uid!="0" AND euid="0"
| eval suspicious=if(match(_raw,"(?i)(python|bash|sh|dash|nc|ncat|socat)"), "yes", "no")
| where suspicious="yes"
| stats count min(_time) as firstTime max(_time) as lastTime values(_raw) as events by host
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime host count risk_score events
```

**Tuning notes:**
- Search 1 is the highest-confidence behavioral indicator for the published PoC: a Python parent process spawning a root shell. Filter out known automation tooling (Ansible managed nodes, configuration management) via a lookup of `dest` values.
- Search 3 requires Linux audit daemon (`auditd`) or `linux_secure` log ingestion; it detects any UID 0 privilege escalation involving common interpreter or shell processes regardless of the specific exploit used.
- CIFSwitch requires `cifs-utils` to be installed. Run `rpm -q cifs-utils` or `dpkg -l cifs-utils` in your environment to scope exposed hosts before deploying detections.

## 6. Executive Summary

Security researcher Asim Manizada publicly disclosed CIFSwitch on May 28, 2026 — a 19-year-old local privilege escalation vulnerability in the Linux kernel's CIFS client. The flaw lies in the `cifs.spnego` key type's improper validation of key descriptions, allowing any unprivileged local user to forge kernel key requests and inject malicious content into the page cache of a privileged binary, ultimately achieving deterministic root access.

Unlike many kernel exploits that rely on race conditions or specific memory layouts, CIFSwitch is reliable: a public 732-byte Python3 PoC exploits the vulnerability reproducibly across distributions with a single command. No external dependencies are required beyond the Python standard library.

Exploitation is **not universal** — it requires several prerequisites including a vulnerable `cifs-utils` version, unprivileged user namespaces enabled, and permissive SELinux/AppArmor policies. Many major distributions (Ubuntu 26.04, Fedora 40+, RHEL 10) are not exploitable in their default configurations. However, a significant number of enterprise-deployed distributions (AlmaLinux 9, Rocky Linux 9, CentOS Stream 9, SLES 15) **are** exploitable out of the box.

No CVE has been assigned as of the time of this report.

**Immediate actions:**
1. Apply kernel updates from your distribution vendor that include the upstream fix (mainline commit `a664bf3d603d`).
2. If patching is not immediately possible, remove `cifs-utils` if CIFS/SMB mounting is not required in your environment.
3. Alternatively, disable unprivileged user namespaces: `sysctl -w kernel.unprivileged_userns_clone=0`.
4. Confirm whether your distribution's default SELinux/AppArmor policy blocks the attack chain (consult your distro's security advisory).
5. Hunt for Python3 processes spawning root shells in audit and EDR telemetry.

## References

- [BleepingComputer — New CIFSwitch Linux flaw gives root on multiple distributions (2026-05-30)](https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/)
- [Asim Manizada — CIFSwitch: a non-universal Linux local root vulnerability](https://heyitsas.im/posts/cifswitch/)
- [AlmaLinux — CIFSwitch: Help Us Test the Patched Kernels (2026-05-28)](https://almalinux.org/blog/2026-05-28-cifswitch/)
- [TuxCare — CIFSwitch Linux Kernel Flaw Grants Local Root on cifs-utils](https://tuxcare.com/blog/cifswitch-cve/)
- [oss-security mailing list — CIFSwitch disclosure](https://seclists.org/oss-sec/2026/q2/717)
- [MITRE ATT&CK T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
- [MITRE ATT&CK T1059.006 — Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
