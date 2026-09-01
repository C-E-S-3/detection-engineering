---
scraped_at: 2026-09-01T00:00:00Z
source_url: https://www.sygnia.co/threat-intelligence-reports/fire-ant-cisco-ios-xr-tacacs-espionage/
report_type: threat-intel
severity: high
title: "Fire Ant / UNC3886 Overlap: Cisco IOS XR TACACS+ Implant (TacTap) for Espionage Persistence"
---

# Fire Ant / UNC3886 Overlap: Cisco IOS XR TACACS+ Implant (TacTap)

**Date Reported:** 2026-08-31  
**Source:** Sygnia Threat Intelligence  
**Severity:** High  
**Note:** China-nexus APT; network infrastructure persistence via IOS XR TACACS+ daemon implant. Partial IOC data — full indicator set in Sygnia report.

## 1. IOCs

### File Hashes

| Hash | Type | Component | Context |
|------|------|-----------|---------|
| `be6b27f429324a4af05a310d8ec9635e37c68a94` | SHA-1 | `/usr/bin/acpid` (IOS XR implant) | Malicious binary replacing the ACPI daemon on Cisco IOS XR; provides persistent remote access |

### File System Artifacts

- `/usr/bin/acpid` — legitimate ACPI daemon replaced by implant on Cisco IOS XR devices
- `libseconfd.so` — malicious shared library injected into the `tac_plus` TACACS+ daemon process (TacTap component)

### Behavioral Indicators

- GRE tunnel interfaces created with no corresponding `show running-config` or commit log entry
- `tac_plus` process exhibiting unexpected network connections or abnormal memory footprint
- `/usr/bin/acpid` with non-standard binary size or modified timestamp vs. known-good baseline

## 2. TTPs

| Tactic | Technique | Details |
|--------|-----------|---------|
| Persistence | T1542.005 — Pre-OS Boot: ROMMON | IOS XR implant survives standard process restarts; persists across daemon reload |
| Persistence | T1505.003 — Server Software Component: Web Shell | TACACS+ daemon implant (TacTap) provides persistent authentication bypass and command injection |
| Defense Evasion | T1036.005 — Masquerading: Match Legitimate Name or Location | `/usr/bin/acpid` masquerades as legitimate ACPI power management daemon |
| Defense Evasion | T1027 — Obfuscated Files or Information | XOR 0xEF byte obfuscation of TacTap C2 strings and configuration |
| Defense Evasion | T1070.003 — Indicator Removal: Clear Command History | GRE tunnel created with no commit history; appears absent from running config |
| Command & Control | T1572 — Protocol Tunneling | GRE tunneling for covert lateral movement and C2 traffic |
| Lateral Movement | T1021 — Remote Services | Compromised TACACS+ authentication allows lateral movement across authenticated network segments |
| Collection | T1557.003 — Adversary-in-the-Middle: DHCP Spoofing | Positional access via TACACS+ implant enables traffic interception on managed network segments |

**MITRE Tactics:** TA0003, TA0005, TA0008, TA0009, TA0011  
**Kill Chain Phases:** Installation, C2, Actions on Objectives

## 3. Malware & Tools

### TacTap
A shared library (`libseconfd.so`) injected into the `tac_plus` TACACS+ authentication daemon process on Cisco IOS XR devices. TacTap hooks into TACACS+ authentication workflows to:
1. Provide a persistent authentication bypass using a hardcoded credential
2. Accept encoded commands embedded in authentication request fields
3. Execute commands in the context of the TACACS+ daemon (typically root on IOS XR)

C2 strings are XOR-obfuscated with the single byte `0xEF`. The implant name is derived from its target: TACACS+ daemon tap.

### /usr/bin/acpid (IOS XR implant)
A malicious binary deployed in place of the legitimate Advanced Configuration and Power Interface daemon. Provides a secondary persistence mechanism and remote access channel independent of the TACACS+ implant. SHA-1: `be6b27f429324a4af05a310d8ec9635e37c68a94`.

### GRE Tunnel (stealth lateral movement)
Threat actor creates GRE tunnel interfaces on IOS XR devices without using the standard commit workflow, resulting in tunnel interfaces that are functional but absent from `show running-config` output and have no entries in the configuration change log. This evades standard network change-management auditing.

## 4. Threat Actor

**Fire Ant** is the Sygnia designation for this intrusion cluster. Significant TTPs and infrastructure overlap with **UNC3886**, a China-nexus espionage group known for targeting network infrastructure (Fortinet, VMware, Juniper) and deploying custom implants in network OS processes. UNC3886 was previously documented deploying REPTILE, MEDUSA, and MOPSLED implants on Juniper JunOS.

The targeting of Cisco IOS XR TACACS+ infrastructure suggests interest in organizations where IOS XR devices serve as authentication policy enforcement points — large enterprise, government, and telco environments.

## 5. Splunk Detection Searches

### Detect new process from TACACS+ daemon (tac_plus) — potential injection
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("tac_plus", "tac_plus_s")
    AND Processes.process_name NOT IN ("tac_plus", "tac_plus_s")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect GRE tunnel interface creation without config commit (network device syslog)
```spl
index=network_devices sourcetype IN ("cisco_ios", "cisco_iosxr")
  ("tunnel" OR "GRE" OR "gre")
  NOT "LINEPROTO" NOT "changed state to"
| rex field=_raw "interface (?P<tunnel_intf>Tunnel\d+)"
| eval config_commit=if(searchmatch("commit"), "yes", "no")
| where config_commit="no" AND isnotnull(tunnel_intf)
| stats count min(_time) as firstTime max(_time) as lastTime by host tunnel_intf
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime host tunnel_intf count risk_score
```

### Detect replacement of /usr/bin/acpid (hash-based — Linux endpoint)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="/usr/bin/acpid"
    AND Filesystem.action IN ("created", "modified")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user file_path file_name risk_score
```

## 6. Executive Summary

Sygnia disclosed on 2026-08-31 that a China-nexus APT cluster designated **Fire Ant** (with significant UNC3886 overlap) deployed a novel TACACS+ daemon implant called **TacTap** on Cisco IOS XR network infrastructure. TacTap consists of a malicious shared library (`libseconfd.so`) injected into the `tac_plus` process that provides authentication bypass and covert command execution. A secondary implant replaces `/usr/bin/acpid` for independent persistent access.

Most notably, the actor creates GRE tunnel interfaces that exist functionally but do not appear in `show running-config` or the configuration commit history — a technique specifically designed to evade network change-management controls. This TTPs pattern is consistent with UNC3886's established practice of targeting network device operating systems where endpoint detection tools have no visibility.

Detection in Splunk is limited for network devices; recommended approaches include syslog parsing for unexpected tunnel interface creation without corresponding config commits, FIM monitoring of `/usr/bin/acpid`, and anomaly detection on `tac_plus` process behavior. Organizations running Cisco IOS XR as TACACS+ authentication points should audit running config vs. commit log consistency.

## References

- [Sygnia — Fire Ant: Cisco IOS XR TACACS+ Espionage Implant (2026-08-31)](https://www.sygnia.co/threat-intelligence-reports/fire-ant-cisco-ios-xr-tacacs-espionage/)
- [Mandiant — UNC3886 Juniper JunOS Implants (prior campaign)](https://www.mandiant.com/resources/blog/unc3886-juniper-junos-backdoors)
- [MITRE ATT&CK — T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
