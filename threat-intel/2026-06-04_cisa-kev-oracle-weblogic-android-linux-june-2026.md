---
scraped_at: 2026-06-04T06:00:00Z
source_url: https://www.cisa.gov/news-events/alerts/2026/06/02/cisa-adds-two-known-exploited-vulnerabilities-catalog
report_type: threat-intel
severity: high
title: "CISA KEV June 2026: Oracle WebLogic CVE-2024-21182, Android Zero-Day CVE-2025-48595, Linux Cgroups CVE-2022-0492 Confirmed Actively Exploited"
---

# CISA KEV June 2026: Oracle WebLogic CVE-2024-21182, Android Zero-Day CVE-2025-48595, Linux Cgroups CVE-2022-0492 Confirmed Actively Exploited

CISA added three vulnerabilities to the Known Exploited Vulnerabilities (KEV) catalog on June 1–2, 2026, confirming active exploitation in the wild.

## 1. IOCs

No campaign-specific IOCs (domains, IPs, file hashes) have been publicly disclosed for any of the three vulnerabilities as of June 4, 2026. Exploitation detection relies on behavioral indicators detailed in Section 5.

## 2. TTPs (MITRE ATT&CK)

### CVE-2024-21182 — Oracle WebLogic Server (KEV Added: June 1, 2026)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Exploit Public-Facing Application | T1190 | Unauthenticated remote attacker with network access via T3 or IIOP protocols can compromise Oracle WebLogic Server; CVSS 7.5; affects versions 12.2.1.4.0 and 14.1.1.0.0; 1,592+ vulnerable instances exposed on Shodan |
| Execution | Exploitation for Client Execution | T1203 | Java deserialization gadget chains executed via T3/IIOP protocol messages enabling arbitrary code execution on the WebLogic server process (JVM) |

### CVE-2025-48595 — Android Framework Integer Overflow (KEV Added: June 2, 2026)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Integer overflow (CWE-190) in Android Framework enables local privilege escalation to higher-privileged context; CVSS 8.4; affects Android 14–16 and 16-QPR2; no user interaction required; Google notes "limited, targeted exploitation" consistent with commercial spyware or nation-state targeting |
| Defense Evasion | Exploitation for Defense Evasion | T1211 | Privilege escalation bypasses application sandboxing, enabling malicious apps to access restricted data and APIs |

### CVE-2022-0492 — Linux Kernel cgroups v1 Container Escape (KEV Added: June 2, 2026)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Privilege Escalation | Escape to Host | T1611 | Improper authentication check in `cgroup_release_agent_write()` in Linux cgroups v1 subsystem allows a local attacker to bypass container namespace isolation and escape to host with root privileges; first patched in 2022 but now confirmed exploited in containerized cloud environments |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Local privilege escalation via cgroups release agent allowing root-level access on the underlying host |

## 3. Malware & Tools

**CVE-2024-21182:** Oracle WebLogic T3/IIOP exploitation historically weaponized by China-nexus actors (UNC1945, APT41/Winnti) deploying Java web shells (JSP/JSPX), Cobalt Strike BEACON, and custom RATs. No specific malware family confirmed for current exploitation wave.

**CVE-2025-48595:** Android framework LPE zero-days with "limited targeted exploitation" are consistent with commercial surveillance vendors (Paragon, Cellebrite, NSO Group variants) or nation-state mobile exploit frameworks. No public disclosure of responsible tool or actor.

**CVE-2022-0492:** Container escape vulnerabilities are used by cloud-targeting threat actors and cryptomining campaigns to break out of containerized workloads and access host system resources including cloud instance metadata.

## 4. Threat Actor / Campaign Attribution

| CVE | Attribution | Confidence |
|-----|-------------|-----------|
| CVE-2024-21182 | Unknown; Oracle WebLogic historically targeted by China-nexus APTs and financially motivated actors | Low |
| CVE-2025-48595 | Unknown; "limited targeted exploitation" pattern is strongly associated with commercial spyware vendors or nation-state intelligence operations targeting journalists, activists, or government officials | Low |
| CVE-2022-0492 | Unknown; container escape targeting consistent with cloud-based threat actors and cryptomining groups | Low |

CISA remediation deadlines under BOD 22-01:
- CVE-2024-21182: June 4, 2026 (FCEB agencies)
- CVE-2025-48595: June 5, 2026 (FCEB agencies)
- CVE-2022-0492: June 5, 2026 (FCEB agencies)

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("java.exe", "java")
  AND Processes.process_name IN ("cmd.exe", "powershell.exe", "sh", "bash", "curl", "wget", "nc", "whoami", "id")
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
   Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("cmd.exe","powershell.exe","bash","sh"), 85,
    process_name IN ("curl","wget","nc"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (7001, 7002) AND All_Traffic.app="tcp"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_in
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes_in > 100000, 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src dest dest_port bytes_in count risk_score
```

## 6. Executive Summary

CISA added three vulnerabilities to the KEV catalog on June 1–2, 2026, confirming active in-the-wild exploitation across server, mobile, and container platforms.

**CVE-2024-21182** targets Oracle WebLogic Server via its T3/IIOP Java deserialization protocol channels — an unauthenticated attack vector historically favored by Chinese APT groups. With over 1,592 vulnerable instances indexed on Shodan and a patch two years old, a large unpatched population remains exposed.

**CVE-2025-48595** is a zero-day integer overflow in the Android Framework enabling local privilege escalation without user interaction. Google's characterization of "limited, targeted exploitation" indicates a likely advanced threat actor (commercial spyware vendor or state intelligence service) exploiting this vulnerability against specific high-value mobile targets. Patched in the June 2026 Android Security Bulletin.

**CVE-2022-0492** is a four-year-old Linux cgroups v1 vulnerability now confirmed exploited, likely in cloud or container environments. Organizations using unpatched Linux kernels in containerized workloads should prioritize kernel upgrades to prevent container escape and host compromise.

## References

- [CISA KEV — June 1, 2026: CVE-2024-21182](https://www.cisa.gov/news-events/alerts/2026/06/01/cisa-adds-one-known-exploited-vulnerability-catalog)
- [CISA KEV — June 2, 2026: CVE-2025-48595 + CVE-2022-0492](https://www.cisa.gov/news-events/alerts/2026/06/02/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [BleepingComputer — Oracle WebLogic CVE-2024-21182 KEV (2026-06-01)](https://www.bleepingcomputer.com/news/security/cisa-orders-feds-to-patch-actively-exploited-oracle-weblogic-flaw/)
- [BleepingComputer — CISA Warns Android + Linux Kernel Exploited (2026-06-02)](https://www.bleepingcomputer.com/news/security/cisa-warns-of-active-attacks-exploiting-android-linux-bugs/)
- [SOCRadar — CVE-2025-48595 Android Zero-Day Analysis](https://socradar.io/blog/june-2026-android-security-cve-2025-48595/)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1611: Escape to Host](https://attack.mitre.org/techniques/T1611/)
