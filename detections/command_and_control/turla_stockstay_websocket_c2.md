# Turla STOCKSTAY WebSocket C2 via Cloud Hosting Platforms

## Description

Detects STOCKSTAY, Turla's multi-component .NET backdoor ecosystem, establishing WebSocket-based C2 connections through legitimate cloud hosting platforms (Render.com, Glitch.me, theworkpc.com). STOCKSTAY.STOCKBROKER tunnels commands over encrypted WebSocket (WSS://) connections to attacker-controlled controller instances. Because the traffic leverages legitimate cloud services on standard port 443, it blends with normal SaaS activity and evades network-layer blocklists.

The detection hunts two behaviors: (1) DNS queries for known STOCKSTAY C2 subdomain patterns, and (2) non-browser processes initiating connections to Render.com, Glitch.me, or theworkpc.com — which is anomalous for endpoint processes and highly indicative of an implant using legitimate infrastructure for C2 purposes.

False positives: Legitimate developer workstations running code on Render.com/Glitch.me may generate similar DNS queries. Analyst should validate the querying process (expected: mshta, PowerShell, svchost, or unknown executables; not expected: browsers).

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Sub-technique note | WebSocket (WSS://) tunneling via legitimate cloud hosting |

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service |
| Technique ID | T1102 |
| Sub-technique note | C2 hosted on legitimate cloud platforms to blend with benign traffic |

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Encrypted Channel: Asymmetric Encryption |
| Technique ID | T1573.002 |
| Sub-technique note | RSA 4096-bit key exchange for session establishment |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
  "wool-basalt-clock.glitch.me",
  "weatherdataai.theworkpc.com",
  "canal1zac1a.onrender.com",
  "driverx86-adobe.onrender.com",
  "google-ai-labs-it.onrender.com"
)
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query record_type risk_score
```

Broader hunt for non-browser processes connecting to cloud hosting platforms known to host STOCKSTAY C2:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_dns="*.onrender.com" OR All_Traffic.dest_dns="*.glitch.me"
       OR All_Traffic.dest_dns="*.theworkpc.com")
  AND All_Traffic.process_name NOT IN (
    "chrome.exe","firefox.exe","msedge.exe","iexplore.exe","safari","opera.exe",
    "brave.exe","vivaldi.exe","waterfox.exe","seamonkey.exe"
  )
by All_Traffic.src All_Traffic.dest All_Traffic.dest_dns All_Traffic.dest_port All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)mshta|wscript|cscript|powershell|rundll32|regsvr32"), 90,
    match(process_name, "(?i)svchost|services|lsass"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src dest dest_dns dest_port process_name risk_score
```

Filename-based hunt for known STOCKSTAY component names across endpoint and file data:

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN (
  "StockMarketNews.exe","StockMarketView.exe","StockMarketNet.exe","StockMarketSystem.exe",
  "SMEditor.exe","SMNet.exe","MSViewer.exe","MSDriver.exe","MSRender.exe",
  "ClientMNGR2.exe","GR3.exe","MicrosoftUpdateOneDrive.exe"
)
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query matches known STOCKSTAY C2 domain exactly | 95 | Near-certain true positive; domains unique to STOCKSTAY campaign |
| Non-browser process connecting to *.onrender.com or *.glitch.me; parent is script interpreter | 90 | Very high confidence — script interpreters have no legitimate WSS reason to reach these platforms |
| Non-browser process connecting to *.onrender.com or *.glitch.me; generic endpoint process | 65–80 | Suspicious; warrants investigation; may have legitimate developer use |
| Known STOCKSTAY component filename detected in process execution | 100 | Exact IOC match — confirmed infection |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Turla (Secret Blizzard, VENOMOUS BEAR, SUMMIT, UAC-0194) — Russia FSB Center 16 | [MITRE ATT&CK G0010](https://attack.mitre.org/groups/G0010/), [Google GTIG — STOCKSTAY (2026-06-25)](https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering) |

## References

- [Google GTIG — STOCKSTAY Another Day: The Latest Addition to Turla's Intelligence Gathering Apparatus (2026-06-25)](https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering)
- [MITRE ATT&CK — T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK — T1102 Web Service](https://attack.mitre.org/techniques/T1102/)
- [MITRE ATT&CK — T1573.002 Encrypted Channel: Asymmetric Encryption](https://attack.mitre.org/techniques/T1573/002/)
- [Microsoft — Kazuar Anatomy of a Nation-State Botnet (2026-05-14)](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/)
