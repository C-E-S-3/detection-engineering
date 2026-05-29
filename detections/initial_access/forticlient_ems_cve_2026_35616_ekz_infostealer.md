# FortiClient EMS CVE-2026-35616 Exploitation Spawning EKZ Infostealer

## Description

Detects FortiClient Endpoint Management Server (EMS) processes spawning PowerShell with download cradles or execution-policy-bypass flags, consistent with active exploitation of CVE-2026-35616. The vulnerability is a pre-authentication API access bypass (CVSS 9.1) that allows unauthenticated attackers to send privileged scripting commands to EMS-managed endpoints. In May 2026 campaigns observed by Arctic Wolf, attackers used this pathway to download and silently execute the **EKZ Infostealer**, disguised as a Fortinet endpoint update, which harvests credentials and cookies from Chrome and Firefox.

**False positive sources:** Legitimate FortiClient EMS deployment and compliance scripts may invoke PowerShell, but will not include download cradles (`Invoke-WebRequest`, `DownloadFile`, `DownloadString`) or execution-policy-bypass flags under normal operation. Exceptions may be required for known patch distribution workflows.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution |
| Secondary Tactic ID | TA0002 |
| Secondary Technique | Command and Scripting Interpreter: PowerShell |
| Secondary Technique ID | T1059.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("FortiESNAC.exe","fmon.exe","FortiClient.exe","FcConfig.exe")
    AND Processes.process_name="powershell.exe"
    AND (Processes.process="*DownloadFile*"
         OR Processes.process="*DownloadString*"
         OR Processes.process="*Invoke-WebRequest*"
         OR Processes.process="*iwr *"
         OR Processes.process="*WebClient*"
         OR Processes.process="*-ExecutionPolicy Bypass*"
         OR Processes.process="*-ep bypass*"
         OR Processes.process="*-WindowStyle Hidden*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)DownloadFile|DownloadString|Invoke-WebRequest|iwr "), 90,
    match(process, "(?i)-ExecutionPolicy Bypass|-ep bypass|-WindowStyle Hidden"), 80,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| FortiClient parent + PowerShell with download cradle (`DownloadFile`, `DownloadString`, `Invoke-WebRequest`, `iwr`) | 90 | Direct download behavior — high confidence malicious; EKZ delivery method |
| FortiClient parent + PowerShell with execution policy bypass or hidden window | 80 | Strong indicator of malicious scripting; legitimate EMS operations do not require these flags |
| FortiClient parent + PowerShell (other suspicious patterns) | 75 | Suspicious process relationship warranting investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (EKZ campaign, May 2026) | [BleepingComputer — FortiClient EMS CVE-2026-35616](https://www.bleepingcomputer.com/news/security/hackers-exploit-forticlient-ems-flaw-to-push-infostealer-malware/), [Arctic Wolf — EKZ Infostealer](https://arcticwolf.com/resources/blog/forticlient-ems-exploited-via-cve-2026-35616-to-deliver-ekz-infostealer-disguised-as-a-fortinet-patch/) |

## References

- https://www.bleepingcomputer.com/news/security/hackers-exploit-forticlient-ems-flaw-to-push-infostealer-malware/
- https://arcticwolf.com/resources/blog/forticlient-ems-exploited-via-cve-2026-35616-to-deliver-ekz-infostealer-disguised-as-a-fortinet-patch/
- https://nvd.nist.gov/vuln/detail/CVE-2026-35616
- https://attack.mitre.org/techniques/T1190/
- https://attack.mitre.org/techniques/T1059/001/
