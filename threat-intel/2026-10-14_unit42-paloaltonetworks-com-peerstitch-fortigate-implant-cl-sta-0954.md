---
scraped_at: "2026-10-14T00:00:00Z"
source_url: "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
report_type: threat-intel
severity: high
title: "Unit 42 October 14 2026: PEERSTITCH — Memory-Resident ARM64 FortiGate Implant Deployed via CVE-2024-47575 and CVE-2025-61624; Cluster CL-STA-0954"
---

## 1. IOCs

### Domains

No domains published at time of report.

### IPs

| Indicator | Context |
|-----------|---------|
| 23.240.77[.]233 | PEERSTITCH C2/staging infrastructure; Unit 42 confirmed active October 2026 |
| 47.18.167[.]159 | PEERSTITCH C2/staging infrastructure; Unit 42 confirmed active October 2026 |

### Hashes

No hashes available — PEERSTITCH is memory-resident and leaves no persistent binary on disk. Disk-resident artifacts were not published.

### Behavioral Indicators

| Indicator | Context |
|-----------|---------|
| Unexpected outbound connections from FortiGate/FortiManager to non-Fortinet IPs on ports 443/8443 | PEERSTITCH communicates out through patched daemon network stack |
| miglogd or iked processes establishing external TCP connections | Normal operation does not involve external C2 traffic from these daemons |
| ptrace syscall activity against miglogd or iked | PEERSTITCH injector uses ptrace to write shellcode into target daemon process memory |
| Unauthorized FortiGate unit registration in FortiManager | CVE-2024-47575 exploitation involves rogue FortiGate devices registering with a target FortiManager |

---

## 2. TTPs

| MITRE Technique | ID | Description |
|----------------|-----|-------------|
| Exploit Public-Facing Application | T1190 | CVE-2024-47575 (CVSS 9.8) FortiManager unauthorized device registration/RCE used for initial access |
| Exploit Public-Facing Application | T1190 | CVE-2025-61624 (CVSS not yet published) FortiOS pre-auth vulnerability used as alternate access vector |
| Process Injection: ptrace System Calls | T1055.008 | PEERSTITCH injector uses Linux ptrace API to write ARM64 shellcode into miglogd or iked daemon memory |
| Rootkit | T1014 | Memory-resident implant patches running daemon code in-place; no binary written to disk; persists across ASLR rerandomization via daemon restart patching |
| Hijack Execution Flow | T1574 | Daemon function pointers overwritten in memory to redirect execution to implant shellcode |
| Non-Standard Port | T1571 | C2 communications observed over non-standard ports leveraging hijacked daemon network sockets |
| Masquerading | T1036 | Implant executes within the address space of legitimate Fortinet daemons (miglogd, iked) |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| PEERSTITCH | Memory-resident network implant | ARM64 ELF shellcode injected into miglogd (log management daemon) or iked (IKEv2 daemon) via ptrace; no disk artifact; capabilities include reverse shell, file transfer, and command execution via hijacked daemon sockets |
| PEERSTITCH Injector | Deployment tool | Binary (likely dropped post-exploitation) that performs the ptrace injection; removed after injection succeeds |

---

## 4. Threat Actor/Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Cluster | CL-STA-0954 (Unit 42 designation) |
| Suspected nexus | Unknown; targeting and TTPs consistent with nation-state espionage |
| Targeting | Network security appliances (Fortinet FortiGate, FortiManager) in government, critical infrastructure, and financial sectors |
| Exploitation chain | CVE-2024-47575 (FortiManager, patched October 2024) OR CVE-2025-61624 (FortiOS, patched Q3 2025) → PEERSTITCH deployment → persistent memory-resident C2 |
| Persistence mechanism | No persistent binary — implant lives only in daemon memory; survives until daemon restart; re-infection likely via re-exploitation or a separate installer mechanism |
| Confidence | Medium — unit attribution pending; Chinese-nexus suspected based on toolchain and targeting, not confirmed |

---

## 5. Splunk Detection Searches

### Network Traffic to Known PEERSTITCH Staging IPs

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest="23.240.77.233" OR All_Traffic.dest="47.18.167.159")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_port action risk_score
```

### FortiManager Unauthorized Device Registration (CVE-2024-47575 Pattern)

```spl
`fortimanager`
| where (event_type="device_registration" OR message="*unauthorized*" OR message="*unregistered*")
    AND src_ip!="*10.*" AND src_ip!="*192.168.*" AND src_ip!="*172.1[6-9].*" AND src_ip!="*172.2[0-9].*" AND src_ip!="*172.3[0-1].*"
| stats count min(_time) as firstTime max(_time) as lastTime by src_ip dest_ip device_id serial_number
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 75
| table firstTime lastTime src_ip dest_ip device_id serial_number risk_score
```

---

## 6. Executive Summary

PEERSTITCH is a highly sophisticated memory-resident implant targeting Fortinet network appliances, disclosed by Unit 42 on October 14, 2026 and attributed to cluster CL-STA-0954. The implant is injected into the address space of running FortiGate daemons — primarily `miglogd` (log management) or `iked` (IKEv2 VPN) — using Linux ptrace, leaving no persistent binary on disk and making traditional file-based detection ineffective. Initial access exploits CVE-2024-47575 (CVSS 9.8, FortiManager unauthorized device registration) or CVE-2025-61624 (FortiOS), both of which should have been patched in 2024–2025. Two confirmed staging/C2 IPs (23.240.77[.]233, 47.18.167[.]159) have been added to ip.csv. Priority actions: (1) verify FortiManager and FortiOS patches for CVE-2024-47575 and CVE-2025-61624 are applied; (2) hunt for outbound connections from FortiGate management interfaces to the published staging IPs; (3) review FortiManager device registration logs for unauthorized FortiGate enrollments; (4) consider network traffic anomaly monitoring on FortiGate management interfaces for unexpected external connections from daemon processes.
