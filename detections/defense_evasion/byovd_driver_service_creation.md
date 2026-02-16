# BYOVD Kernel Driver Service Creation

## Description

Detects the creation of kernel driver services (service type "kernel") via sc.exe or through Windows Service creation events, which is the primary mechanism adversaries use to load BYOVD drivers into the kernel. Legitimate kernel driver installations are uncommon in day-to-day operations and are typically associated with software installation or hardware driver updates. Adversaries create temporary kernel services to load vulnerable drivers, exploit them for kernel access, then remove the service to cover their tracks.

False positive sources: Legitimate driver installations during software updates, hardware driver deployments, and IT management tools deploying agents. Tuning: create an allowlist of known-good driver service names and paths associated with approved software, and correlate with change management tickets.

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
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Create or Modify System Process: Windows Service |
| Technique ID | T1543.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="sc.exe"
      Processes.process IN ("*create*", "*config*")
      Processes.process IN ("*kernel*", "*type= kernel*", "*type=kernel*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval service_binary=coalesce(
    mvindex(split(process, "binPath= "), 1),
    mvindex(split(process, "binpath= "), 1))
| eval risk_score=case(
    match(process, "(?i)(RTCore|DBUtil|gdrv|iqvw64e|WinRing0|mhyprot|echo_driver|rentdrv)"), 95,
    match(parent_process_name, "(?i)(cmd\.exe|powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe)"), 85,
    match(process, "(?i)(\\\\temp\\\\|\\\\tmp\\\\|\\\\appdata\\\\|\\\\public\\\\|\\\\downloads\\\\)"), 80,
    user!="SYSTEM", 75,
    1=1, 60)
| eval risk_reason=case(
    risk_score>=95, "Kernel service creation referencing known BYOVD driver name",
    risk_score>=85, "Kernel service created from scripting interpreter - likely automated BYOVD deployment",
    risk_score>=80, "Kernel driver loaded from suspicious temporary or user-writable path",
    risk_score>=75, "Kernel service created by non-SYSTEM user - unusual for legitimate driver installs",
    risk_score>=60, "Kernel driver service creation detected - verify against change management")
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process service_binary risk_score risk_reason
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known BYOVD driver name in command line | 95 | Direct match against known-weaponized vulnerable drivers |
| Parent process is a scripting interpreter (cmd, powershell, wscript) | 85 | Kernel services are rarely created via scripts; indicates automated BYOVD tooling |
| Driver binary path in temp/user-writable directory | 80 | Legitimate drivers are typically installed to System32\drivers, not temp directories |
| Non-SYSTEM user creating kernel service | 75 | Legitimate driver installs typically run as SYSTEM during software setup |
| Any other kernel service creation | 60 | Baseline alert for kernel driver service creation, which is infrequent in normal operations |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Scattered Spider (UNC3944) | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/) |
| BlackByte Ransomware | [Sophos - BlackByte BYOVD](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/) |
| Cuba Ransomware (BurntCigar) | [Mandiant - Cuba Ransomware](https://www.mandiant.com/resources/blog/unc2596-cuba-ransomware) |
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |
| RobbinHood Ransomware | [Sophos - RobbinHood BYOVD](https://news.sophos.com/en-us/2020/02/06/living-off-another-land-ransomware-borrows-vulnerable-driver-to-remove-security-software/) |

## References

- [MITRE ATT&CK - Impair Defenses: Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK - Create or Modify System Process: Windows Service (T1543.003)](https://attack.mitre.org/techniques/T1543/003/)
- [LOLDrivers Project - Living Off The Land Drivers](https://www.loldrivers.io/)
- [Elastic - Stopping Vulnerable Driver Attacks](https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks)
