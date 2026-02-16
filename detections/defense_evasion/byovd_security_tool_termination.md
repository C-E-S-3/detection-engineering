# BYOVD Security Tool Process Termination

## Description

Detects the rapid termination of multiple security tool processes, which is the primary objective of most BYOVD attacks. After loading a vulnerable kernel driver, adversaries use the kernel-level access to forcibly terminate endpoint detection and response (EDR) agents, antivirus software, and other security tools that cannot be killed from user-mode. This detection identifies multiple security-related processes being terminated within a short time window on a single host.

False positive sources: Security tool upgrades or migrations where agents are deliberately stopped, endpoint management platforms performing controlled uninstalls, and system administrators troubleshooting security software. Tuning: correlate with change management systems and exclude known maintenance windows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Impair Defenses: Disable or Modify Tools |
| Technique ID | T1562.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN (
    "MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseCncProxy.exe",
    "CSFalconService.exe", "CSFalconContainer.exe", "falcon-sensor*",
    "cb.exe", "CbDefense.exe", "CbOsR.exe", "RepMgr.exe",
    "SentinelAgent.exe", "SentinelOne.exe", "SentinelServiceHost.exe",
    "CylanceSvc.exe", "CylanceUI.exe",
    "taniumclient.exe", "TaniumDetectEngine.exe",
    "xagt.exe", "xagtnotif.exe",
    "bdagent.exe", "vsserv.exe", "updatesrv.exe",
    "savservice.exe", "SophosFileScanner.exe", "SSPService.exe",
    "avp.exe", "kavfs.exe",
    "eset_service.exe", "ekrn.exe",
    "sfc.exe", "WRSA.exe",
    "coreServiceShell.exe", "ds_agent.exe"
)
  Processes.action IN ("stopped", "terminated", "blocked")
by Processes.dest Processes.process_name Processes.action
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats count as terminated_count dc(process_name) as unique_tools
  values(process_name) as terminated_processes
  min(firstTime) as firstTime max(lastTime) as lastTime
  by dest
| eval time_span_minutes=round((lastTime - firstTime) / 60, 2)
| eval risk_score=case(
    unique_tools >= 3 AND time_span_minutes <= 5, 95,
    unique_tools >= 2 AND time_span_minutes <= 10, 85,
    unique_tools >= 2, 75,
    terminated_count >= 3 AND time_span_minutes <= 5, 80,
    1=1, 60)
| eval risk_reason=case(
    risk_score>=95, "Multiple security tools terminated rapidly - strong BYOVD indicator",
    risk_score>=85, "Two or more security tools terminated within 10 minutes",
    risk_score>=75, "Multiple security tools terminated on same host",
    risk_score>=80, "Repeated termination of security process in short window",
    risk_score>=60, "Security tool process termination detected")
| where risk_score >= 60
| table firstTime lastTime dest terminated_processes unique_tools
  terminated_count time_span_minutes risk_score risk_reason
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| 3+ different security tools terminated within 5 minutes | 95 | Highly indicative of automated BYOVD kill chain targeting multiple security products |
| 2+ different security tools terminated within 10 minutes | 85 | Strong indicator of deliberate security tool neutralization |
| 2+ different security tools terminated (any timeframe) | 75 | Multiple security tools stopping on same host warrants investigation |
| 3+ termination events for same tool within 5 minutes | 80 | Repeated forced termination suggests kernel-level process killing |
| Any security tool termination event | 60 | Baseline alert for security tool process termination |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Scattered Spider (UNC3944) | [MITRE - Scattered Spider (G1015)](https://attack.mitre.org/groups/G1015/) |
| BlackByte Ransomware | [Sophos - BlackByte EDR Bypass](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/) |
| Cuba Ransomware (BurntCigar) | [Mandiant - Cuba BurntCigar EDR Killer](https://www.mandiant.com/resources/blog/unc2596-cuba-ransomware) |
| Lazarus Group (HIDDEN COBRA) | [ESET - Lazarus FudModule Rootkit](https://www.welivesecurity.com/2022/09/30/amazon-themed-campaigns-lazarus-netherlands-belgium/) |
| Medusa Ransomware | [Elastic - Medusa EDR Evasion](https://www.elastic.co/security-labs/medusa-ransomware-escalation) |
| AvosLocker Ransomware | [Trend Micro - AvosLocker BYOVD](https://www.trendmicro.com/en_us/research/22/e/avoslocker-ransomware-variant-abuses-driver-file-to-disable-anti-virus-solutions.html) |
| RobbinHood Ransomware | [Sophos - RobbinHood EDR Bypass](https://news.sophos.com/en-us/2020/02/06/living-off-another-land-ransomware-borrows-vulnerable-driver-to-remove-security-software/) |

## References

- [MITRE ATT&CK - Impair Defenses: Disable or Modify Tools (T1562.001)](https://attack.mitre.org/techniques/T1562/001/)
- [LOLDrivers Project - Living Off The Land Drivers](https://www.loldrivers.io/)
- [Sophos - BYOVD: The Rising Threat of Vulnerable Driver Abuse](https://news.sophos.com/en-us/2022/10/04/blackbyte-ransomware-returns/)
- [Elastic - Stopping Vulnerable Driver Attacks](https://www.elastic.co/security-labs/stopping-vulnerable-driver-attacks)
