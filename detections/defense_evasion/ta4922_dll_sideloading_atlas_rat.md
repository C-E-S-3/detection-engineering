# TA4922 DLL Sideloading Delivering Atlas RAT

## Description

Detects two complementary indicators of TA4922 Atlas RAT activity: (1) outbound TCP connections to port 886, the non-standard port used by Atlas RAT for C2 communication, and (2) execution of binaries from user-writable paths consistent with HR-themed phishing ZIP file delivery via DLL sideloading.

TA4922 (Chinese-speaking cybercrime actor, active since spring 2025) delivers Atlas RAT by convincing victims to execute a file from an HR-themed or invoice-themed ZIP archive. The ZIP contains a signed legitimate binary paired with a malicious DLL in the same directory; when the victim runs the legitimate binary, the OS loads the malicious DLL via DLL sideloading. Atlas RAT then beacons to its C2 on TCP port 886 — an unusual port that should trigger immediate investigation. The actor expanded from East Asia to Germany, Italy, UK, and South Africa by early 2026.

False positives for the port 886 rule are extremely rare; port 886 is unassigned and almost never used in enterprise environments. The user-path execution rule may generate false positives for legitimate portable applications run from Downloads folders; enrichment with code-signing status (unsigned binaries) reduces noise significantly.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Defense Evasion |
| Tactic ID | TA0005 |
| Technique | Hijack Execution Flow: DLL Side-Loading |
| Technique ID | T1574.002 |

Secondary techniques: T1566.002 (Phishing via Link — ZIP on GoFile/MediaFire), T1204.002 (User Execution: Malicious File), T1571 (Non-Standard Port for C2)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=886
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.bytes_out All_Traffic.bytes_in
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    dest IN ("206.238.115.58","154.211.86.110","43.156.77.97","103.214.172.33"), 97,
    1=1, 85)
| where risk_score >= 85
| table firstTime lastTime src dest dest_port bytes_out bytes_in risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*"
    OR Processes.process_path="*\\AppData\\Roaming\\*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_path,"(?i)Downloads"), 60,
    match(process_path,"(?i)AppData.Local.Temp"), 65,
    match(process_path,"(?i)AppData.Roaming"), 60,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Outbound TCP to port 886 matching known TA4922 C2 IP | 97 | Near-certain Atlas RAT C2 beacon; specific IOC match |
| Any outbound TCP to port 886 (unknown dest) | 85 | Port 886 is unassigned and not used by legitimate software |
| Process execution from Downloads path | 60 | Common initial execution path after ZIP delivery |
| Process execution from AppData Local Temp | 65 | Slightly higher risk; commonly used by malware post-extraction |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| TA4922 (Chinese-speaking cybercrime actor) | [Proofpoint — TA4922: The Suspected Chinese Crime Group is Going Global (2026-06-05)](https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global) |
| ValleyRAT / Winos 4.0 operators | [MITRE ATT&CK — T1574.002 DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/) |

## References

- [Proofpoint — TA4922: The Suspected Chinese Crime Group is Going Global](https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global)
- [BleepingComputer — Chinese hackers use new Atlas RAT malware in European cyberattacks](https://www.bleepingcomputer.com/news/security/chinese-hackers-use-new-atlas-rat-malware-in-european-cyberattacks/)
- [MITRE ATT&CK — T1574.002 Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK — T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571/)
