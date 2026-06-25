---
scraped_at: 2026-06-24T00:00:00Z
source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
report_type: threat-intel
severity: critical
title: "CISA KEV June 2026: CVE-2022-0492 Linux cgroups v1 Container Escape + CVE-2026-11645 Chrome V8 Zero-Day + QV Ransomware (Windows/ESXi)"
---

## 1. IOCs

### CVE-2022-0492 — Linux Kernel cgroups v1 Container Escape

| Indicator | Type | Notes |
|-----------|------|-------|
| `/sys/fs/cgroup/*/release_agent` | File path | Written to during exploitation; contains attacker command executed as host root |
| `unshare -UrmCpf` | Command pattern | First step of container escape; creates new user+cgroup namespace |
| `mount -t cgroup` | Command pattern | Mounts cgroupfs inside new namespace to get write access to release_agent |
| `nsenter -C -U` | Command pattern | Alternative namespace entry for escape |

### CVE-2026-11645 — Google Chromium V8 Zero-Day

| Indicator | Type | Notes |
|-----------|------|-------|
| Chrome < 149.0.7827.102 | Software version | Vulnerable; patch: 149.0.7827.102/.103 |
| chrome.exe spawning cmd.exe/powershell.exe | Process behavior | Post-exploitation action after sandbox escape |
| Chrome renderer process spawning subprocess | Process behavior | Sandbox escape indicator; renderer should not spawn children |
| Chrome outbound connection on non-80/443 port | Network | Post-exploitation C2 or stager download |

### QV Ransomware

| Indicator | Type | Notes |
|-----------|------|-------|
| `Qv Ransomware.txt` | Filename | Ransom note dropped in each encrypted directory |
| `.Qv` | File extension | Appended to encrypted files as `<email>.<victimID>.Qv` |
| AES-256-CBC + RSA-2048 | Encryption | File data AES, key wrapped with RSA-2048 public key |
| Randomized 6-12 char lowercase alphanumeric | Service name | Persistence: Windows service with randomized name |
| `vssadmin.exe Delete Shadows /all /quiet` | Command | VSS deletion for recovery prevention |
| `wmic shadowcopy delete /nointeractive` | Command | Alternate VSS deletion method |
| `/vmfs/volumes/**/*.vmdk` | File path | ESXi VMDK encryption target |

## 2. TTPs

### CVE-2022-0492 (T1611, T1068)

| TTP | Technique | Notes |
|-----|-----------|-------|
| T1611 | Escape to Host | Core attack: container escape via cgroups v1 release_agent abuse |
| T1068 | Exploitation for Privilege Escalation | cgroup_release_agent_write() missing auth check allows local privilege escalation |
| T1610 | Deploy Container | May chain into host compromise of all pods on node |

### CVE-2026-11645 Chrome V8 (T1203, T1059.001)

| TTP | Technique | Notes |
|-----|-----------|-------|
| T1203 | Exploitation for Client Execution | V8 OOB read/write via crafted HTML page |
| T1059.001 | PowerShell | Post-exploitation payload delivery via spawned PowerShell |
| T1566.002 | Spearphishing Link | Delivery vector: malicious HTML page via phishing/malvertising |
| T1571 | Non-Standard Port | C2 traffic on non-HTTP port post sandbox escape |

### QV Ransomware (T1486, T1490, T1543.003, T1053.005, T1497)

| TTP | Technique | Notes |
|-----|-----------|-------|
| T1486 | Data Encrypted for Impact | AES-256-CBC encryption of all files including VMDK |
| T1490 | Inhibit System Recovery | VSS deletion via vssadmin + wmic |
| T1543.003 | Windows Service | Randomized service name for persistence |
| T1053.005 | Scheduled Task | Logon-triggered scheduled task for persistence |
| T1497 | Virtualization/Sandbox Evasion | Registry/CPUID VM detection before running |
| T1485 | Data Destruction | ESXi VMDK destruction if datastores accessible |

## 3. Wazuh Detection Rules

| Rule ID | Description | MITRE |
|---------|-------------|-------|
| 103474 | unshare with user+cgroup namespace flags | T1611 |
| 103475 | cgroupfs mount by unprivileged user | T1611 |
| 103476 | nsenter with cgroup+user namespace | T1611 |
| 103477 | Write to cgroup release_agent (CRITICAL) | T1611/T1068 |
| 103478 | Correlation: unshare + cgroupfs mount in 60s | T1611 |
| 103479 | Container escape + Docker socket access | T1611/T1610 |
| 103480 | Chrome spawning shell/script process (Windows) | T1203 |
| 103481 | Chrome renderer spawning unexpected child | T1203 |
| 103482 | Chrome outbound connection on non-HTTP port | T1203/T1571 |
| 103483 | Chromium spawning shell (Linux) | T1203/T1059.004 |
| 103484 | Vulnerability detection: Chrome unpatched | T1203 |
| 103485 | VSS deletion via vssadmin | T1490 |
| 103486 | VSS deletion via WMIC shadowcopy | T1490 |
| 103487 | Ransom note "Qv Ransomware.txt" created | T1486 |
| 103488 | File with .Qv extension created | T1486 |
| 103489 | Mass .Qv encryption (10+ files/60s) | T1486 |
| 103490 | Service with randomized name from temp path | T1543.003 |
| 103491 | Scheduled task at logon from temp path | T1053.005 |
| 103492 | Anti-VM registry query | T1497 |
| 103493 | Correlation: VSS deletion + service install | T1486/T1490 |
| 103494 | ESXi VMDK modification by non-VMware process | T1486 |
| 103495 | bcdedit disabling boot recovery | T1490 |

## 4. Remediation Notes

### CVE-2022-0492
- Upgrade Linux kernel to ≥ 5.17 or apply vendor backport
- Enable SELinux, AppArmor, or Seccomp on all container hosts
- Run containers as non-root (`--user` flag; `runAsNonRoot: true` in K8s)
- Disable cgroups v1 where possible; migrate to cgroupsv2 with systemd
- Add auditd watch: `-w /sys/fs/cgroup -p wa -k cgroup_release_agent`
  (companion inframan PR required to deploy this audit key)
- FCEB remediation deadline: June 5, 2026

### CVE-2026-11645
- Upgrade Chrome to ≥ 149.0.7827.102
- Remediation deadline: June 23, 2026 (FCEB)

### QV Ransomware
- Maintain offline immutable backups separate from network
- Disable VSS deletion rights for non-admin accounts
- Restrict service installation to SYSTEM/admin accounts only
- Block outbound access to non-essential external IPs from endpoints
- ESXi: restrict datastore access; enable vSphere lockdown mode

## 5. Sources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Adds Cisco, Chrome, Arista Flaws](https://thehackernews.com/2026/06/cisa-adds-cisco-chrome-and-arista-flaws.html)
- [CVE-2022-0492 Container Escape — Sysdig](https://www.sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig)
- [CVE-2022-0492 — AquaSec](https://www.aquasec.com/blog/new-linux-kernel-vulnerability-escaping-containers-by-abusing-cgroups/)
- [CVE-2026-11645 Chrome V8 — HelpNetSecurity](https://www.helpnetsecurity.com/2026/06/09/google-chrome-zero-day-cve-2026-11645/)
- [CYFIRMA QV Ransomware Report](https://www.cyfirma.com/news/weekly-intelligence-report-12-jun-2026/)
