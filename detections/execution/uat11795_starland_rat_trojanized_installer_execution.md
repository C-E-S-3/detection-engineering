# UAT-11795: Starland RAT Trojanized Installer Execution and WLDR C2 Implant

## Description

Detects execution of the Starland RAT (Python-based backdoor) and WLDR PowerShell C2 implant deployed by UAT-11795, a financially motivated, Russian-speaking threat actor targeting victims in the United States and Europe since June 2025. UAT-11795 distributes trojanized versions of popular software installers — MobaXterm, Webex Client, FaceIt, DBeaver Community Edition, and Zoom — through SEO-poisoned download pages and direct messaging. When a victim executes the fake installer, it silently deploys Starland RAT as a Python process alongside the legitimate application to avoid suspicion. Starland RAT establishes HTTP C2 to actor-controlled VPS servers and registered domains; if those endpoints are unreachable, it falls back to polling a Polygon blockchain smart contract for instructions — a C2 fallback that cannot be sinkholed through DNS intervention. After initial access, Starland RAT injects WLDR — a memory-resident PowerShell agent — for keylogging, screenshot capture, and credential harvesting. Secondary payloads include CastleStealer and Remcos RAT.

Three detection signals are provided: Python spawned by a trojanized installer process (high confidence), Python spawning hidden PowerShell matching the WLDR injection pattern (high confidence), and network/DNS connections to the 6 known C2 IPs and 8 C2 domains (critical confidence).

False positives: Legitimate software that bundles Python as a runtime dependency and runs the Python interpreter from an installer process. These can be distinguished by whether the Python process subsequently spawns hidden PowerShell. The specific trojanized installer filenames (MobaXterm_v26.1.exe, WebEx_Client.exe, FaceitInstaller_x64.exe, dbeaver-ce-windows-x86_64.exe) do not correspond to any official distribution from the legitimate vendors.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Execution, Command and Control |
| Tactic ID | TA0002, TA0011 |
| Technique | User Execution: Malicious File; Command and Script Interpreter: Python; Command and Script Interpreter: PowerShell; Web Service |
| Technique ID | T1204.002, T1059.006, T1059.001, T1102 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Command & Control (C2) |

## Splunk Detection Query

### Query 1: Trojanized Installer Spawning Python (Starland RAT Execution)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("python.exe", "python3.exe", "pythonw.exe")
  AND (Processes.parent_process IN ("*MobaXterm*", "*WebEx_Client*", "*FaceitInstaller*",
    "*dbeaver-ce-windows-x86_64*", "*Zoom*Installer*")
  OR Processes.parent_process_name IN ("MobaXterm_v26.1.exe", "WebEx_Client.exe",
    "FaceitInstaller_x64.exe", "dbeaver-ce-windows-x86_64.exe"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 2: Python Spawning Hidden PowerShell (WLDR Implant Injection)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="powershell.exe"
  AND Processes.parent_process_name IN ("python.exe", "python3.exe", "pythonw.exe")
  AND (Processes.process IN ("*-windowstyle hidden*", "*-w hidden*", "*-WindowStyle Hidden*")
    OR Processes.process IN ("*-encodedcommand*", "*-enc *"))
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Query 3: Network Connections to UAT-11795 C2 Infrastructure

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest IN ("104.248.233.104", "192.81.216.250", "74.114.119.201",
  "178.255.126.39", "193.149.176.254", "185.238.191.234")
  OR All_Traffic.dest_host IN ("eorthopaedics.com", "sastoro.com", "zynaris.io",
  "alphabitcapital.info", "niggerdemon.in", "web-devtools.com",
  "aipythondevs.com", "windowscreenrepairnearme.com")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src dest dest_host dest_port app risk_score
```

### Query 4: DNS Resolution of UAT-11795 C2 Domains

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
  "eorthopaedics.com", "sastoro.com", "zynaris.io", "alphabitcapital.info",
  "niggerdemon.in", "web-devtools.com", "aipythondevs.com", "windowscreenrepairnearme.com"
)
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src query answer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Python spawned by MobaXterm_v26.1.exe, WebEx_Client.exe, FaceitInstaller_x64.exe, dbeaver-ce-windows-x86_64.exe, or Zoom Installer parent process | 90 | Legitimate versions of these installers do not bundle or spawn Python; high-confidence Starland RAT execution |
| powershell.exe with hidden window or encoded command spawned by python.exe/python3.exe | 85 | Matches WLDR implant injection pattern; Python-to-hidden-PowerShell is rare in legitimate software |
| Network connection to UAT-11795 C2 IP (6 known IPs) | 100 | Direct IOC match; IPs attributed exclusively to UAT-11795 infrastructure by Talos |
| DNS resolution of UAT-11795 C2 domain (8 known domains) | 100 | Direct IOC match; domains registered by UAT-11795 for this campaign |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UAT-11795 | [Cisco Talos — UAT-11795 Starland RAT and WLDR Implant (2026-07-17)](https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/) |

## References

- [Cisco Talos — UAT-11795 Deploys Novel Starland RAT and Bespoke WLDR C2 Implant (2026-07-17)](https://blog.talosintelligence.com/uat-11795-deploys-novel-starland-rat-and-bespoke-wldr-c2-implant-in-financially-motivated-campaign/)
- [Cisco Talos IOCs (raw)](https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/07/new-starland-rat-and-WLDR-implant-campaign.txt)
- [MITRE ATT&CK — T1204.002: User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK — T1059.006: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK — T1102: Web Service](https://attack.mitre.org/techniques/T1102/)
