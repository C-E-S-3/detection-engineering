# BYOVD Vulnerable Driver Loading

## Description

Detects the loading of known vulnerable kernel drivers commonly abused in Bring Your Own Vulnerable Driver (BYOVD) attacks. Adversaries deploy legitimate, signed drivers with known vulnerabilities to gain kernel-level access, typically to disable endpoint security tools. This detection matches against a curated list of vulnerable driver file names and known-bad file hashes associated with BYOVD abuse.

False positive sources: Legitimate installations of software that bundle vulnerable driver versions (e.g., MSI Afterburner, older Dell BIOS utilities, GIGABYTE system utilities). Tuning: whitelist specific driver paths associated with known-good software installations and validate against your asset inventory for systems that legitimately require these drivers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |

Secondary mapping:

| Field | Value |
|-------|-------|
| Tactic | Privilege Escalation |
| Tactic ID | TA0004 |
| Technique | Exploitation for Privilege Escalation |
| Technique ID | T1068 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name IN (
    "RTCore64.sys", "RTCore32.sys",
    "DBUtil_2_3.sys",
    "gdrv.sys", "gdrv2.sys",
    "iqvw64e.sys",
    "WinRing0x64.sys", "WinRing0.sys",
    "AsIO.sys", "AsIO64.sys",
    "HW.sys", "HW64.sys",
    "PROCEXP152.sys",
    "KProcessHacker.sys",
    "zemana.sys", "zamguard64.sys",
    "viragt64.sys",
    "aswArPot.sys", "aswSP.sys",
    "mhyprot2.sys", "mhyprot3.sys",
    "atillk64.sys",
    "kEvP64.sys",
    "NalDrv.sys",
    "echo_driver.sys",
    "rentdrv2.sys",
    "LenovoDiagnosticsDriver.sys",
    "dbutildrv2.sys"
)
by Filesystem.dest Filesystem.user Filesystem.file_name
   Filesystem.file_path Filesystem.file_create_time
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_name IN ("RTCore64.sys", "RTCore32.sys", "DBUtil_2_3.sys", "gdrv.sys", "iqvw64e.sys"), 90,
    file_name IN ("mhyprot2.sys", "mhyprot3.sys", "echo_driver.sys", "rentdrv2.sys"), 90,
    file_name IN ("PROCEXP152.sys", "KProcessHacker.sys"), 75,
    file_name IN ("WinRing0x64.sys", "WinRing0.sys", "HW.sys", "HW64.sys"), 80,
    1=1, 70)
| eval risk_reason=case(
    risk_score>=90, "Known high-abuse BYOVD driver - frequently used by ransomware and APT groups",
    risk_score>=75, "Dual-use driver with legitimate and malicious applications",
    risk_score>=70, "Vulnerable driver that may be exploited for kernel access")
| where risk_score >= 70
| table firstTime lastTime dest user file_name file_path risk_score risk_reason
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| High-abuse drivers (RTCore64, DBUtil_2_3, gdrv, iqvw64e, mhyprot2, echo_driver, rentdrv2) | 90 | Most commonly weaponized drivers with public exploits used by multiple threat actors |
| Dual-use tools (PROCEXP152, KProcessHacker) | 75 | Legitimate security tools that are also abused for kernel-level process termination |
| Hardware utility drivers (WinRing0, HW) | 80 | Low-level hardware access drivers commonly abused for kernel read/write primitives |
| Other known vulnerable drivers | 70 | Documented vulnerable drivers with potential for BYOVD exploitation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Scattered Spider (UNC3944) | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/), [Mandiant - Scattered Spider BYOVD](https://www.mandiant.com/resources/blog/scattered-spider-advisory) |
| BlackByte Ransomware | [Sophos - BlackByte BYOVD RTCore64](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/) |
| Cuba Ransomware (BurntCigar) | [Mandiant - Cuba Ransomware BYOVD](https://www.mandiant.com/resources/blog/unc2596-cuba-ransomware) |
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [ESET - Lazarus FudModule BYOVD](https://www.welivesecurity.com/2022/09/30/amazon-themed-campaigns-lazarus-netherlands-belgium/) |
| RobbinHood Ransomware | [Sophos - RobbinHood GIGABYTE Driver](https://news.sophos.com/en-us/2020/02/06/living-off-another-land-ransomware-borrows-vulnerable-driver-to-remove-security-software/) |
| AvosLocker Ransomware | [Trend Micro - AvosLocker BYOVD](https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-virus-solutions.html) |
| Medusa Ransomware | [Elastic - Medusa BYOVD Techniques](https://www.elastic.co/security-labs/medusa-ransomware-escalation) |

## References

- [MITRE ATT&CK - Impair Defenses: Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK - Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068/)
- [LOLDrivers Project - Living Off The Land Drivers](https://www.loldrivers.io/)
- [Sophos - BYOVD Attacks: The Vulnerable Driver Threat](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/)
- [Mandiant - Threat Actors Increasingly Leverage BYOVD](https://www.mandiant.com/resources/blog/scattered-spider-advisory)
