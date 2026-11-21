# ROMULUS ClickFix MotW Bypass and CNCMachineRMS RAT Delivery

## Description

Detects the ROMULUS ClickFix delivery chain: obfuscated PowerShell stripping Mark-of-the-Web (Zone.Identifier ADS) from a downloaded MSI before silent execution via msiexec.exe, and network connections to known ROMULUS/CNCMachineRMS C2 infrastructure. ROMULUS is a multi-payload ClickFix delivery platform; CNCMachineRMS is the RAT payload. The delivery chain also uses BabaDeda-style DLL sideloading via signed IBM SPSS IDE (WinWrapIDE.exe).

False positives: Legitimate software packaging scripts occasionally strip Zone.Identifier from downloaded installers; tune on specific MSI file names (IconEdit2Turb.msi) or combined MotW-strip plus msiexec invocation from non-administrative contexts. C2 IP detections are higher confidence.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |

**Secondary Techniques:** T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell), T1553.005 (MotW Bypass), T1218.007 (Msiexec), T1574.002 (DLL Side-Loading)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe")
    AND (Processes.process="*Unblock-File*" OR Processes.process="*Zone.Identifier*")
    AND (Processes.process="*msiexec*" OR Processes.process="*IconEdit2Turb*"
         OR Processes.process="*\.msi*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)IconEdit2Turb"), 95,
    match(process,"(?i)Zone\.Identifier") AND match(process,"(?i)msiexec"), 85,
    match(process,"(?i)Unblock-File") AND match(process,"(?i)\.msi"), 80,
    1=1, 60)
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| PowerShell references IconEdit2Turb.msi | 95 | Direct IOC match for ROMULUS loader MSI |
| PowerShell strips Zone.Identifier AND invokes msiexec | 85 | MotW removal immediately before MSI execution is the ROMULUS chain signature |
| PowerShell Unblock-File on .msi extension | 80 | High suspicion — legitimate software rarely needs MotW removal before MSI install |
| PowerShell MotW operations without MSI | 60 | Moderate suspicion — requires correlation with other signals |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| ROMULUS ClickFix operators (unattributed) | [Blackpoint Cyber ROMULUS/CNCMachineRMS Analysis](https://blackpointcyber.com/blog/romulus-cncmachinerms/) |
| SmartApeSG (delivery sub-campaign) | [malware-traffic-analysis.net Nov 12 2026](https://www.malware-traffic-analysis.net/2026/11/12/index.html) |

## References

- [Blackpoint Cyber: ROMULUS Campaign CNCMachineRMS RAT Analysis](https://blackpointcyber.com/blog/romulus-cncmachinerms/)
- [Forescout: ROMULUS Multi-Payload ClickFix Delivery Platform Analysis](https://www.forescout.com/blog/romulus-analysis-of-a-new-multi-payload-clickfix-delivery-platform/)
- [LevelBlue/Trustwave SpiderLabs: CNCMachineRMS BabaDeda Chain](https://www.levelblue.com/blogs/spiderlabs-blog/cncmachinerms-the-undocumented-rat-at-the-end-of-a-babadeda-chain)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK T1553.005 — Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/)
