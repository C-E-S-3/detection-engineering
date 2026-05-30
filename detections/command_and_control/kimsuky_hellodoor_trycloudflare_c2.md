# Kimsuky HelloDoor TryCloudflare C2 and VS Code Tunnel Abuse

## Description

Detects Kimsuky's **HelloDoor** Rust-based backdoor communicating via Cloudflare temporary tunnels (`*.trycloudflare.com`) and the actor's post-exploitation use of **VS Code Remote Tunneling** and **DWAgent** as covert C2 channels. HelloDoor is a DLL-based PebbleDash variant, first identified in August 2025, that fetches a TryCloudflare-assigned subdomain at startup and communicates via HTTP POST to `*.trycloudflare.com/index.php`. The associated **JSONPing** delivery technique also generates anomalous localhost HTTP traffic from fake installer processes.

Detection covers four behaviors:
1. DNS resolution of known HelloDoor and new httpMalice C2 domains
2. Non-browser processes resolving `*.trycloudflare.com` (high-risk: indicates process abuse of transient Cloudflare tunnel)
3. Fake Korean security software installer names (`nos-setup.exe`, `astx-setup.exe`) or intermediate downloader (`mTSTCv8.mdxm`) executing
4. VS Code (`code.exe`) invoked with tunnel flags from scripting-interpreter parent processes (malicious VS Code tunnel C2 setup)

**False positives:** TryCloudflare is used legitimately by developers. Correlate `*.trycloudflare.com` DNS resolutions with process name — browser-initiated resolutions have low risk. VS Code tunnel invocations from `cmd.exe` or PowerShell in development environments are possible; correlate with other Kimsuky indicators. DWAgent is a legitimate RMM tool used by some IT teams.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Remote Access Software |
| Technique ID | T1219 |
| Secondary Tactic | Command and Control |
| Secondary Technique | Web Service |
| Secondary ID | T1102.001 |
| Tertiary Tactic | Command and Control |
| Tertiary Technique | Application Layer Protocol: Web Protocols |
| Tertiary ID | T1071.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
    "female-disorder-beta-metropolitan.trycloudflare.com",
    "pyrotech.co.kr",
    "newjo-imd.com",
    "yespp.co.kr"
    )
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("nos-setup.exe","astx-setup.exe")
   OR (Processes.process_name="powershell.exe" AND Processes.process="*mTSTCv8*")
   OR Processes.process_name="mTSTCv8.mdxm"
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name IN ("code.exe","code") AND Processes.process IN ("*tunnel*","*--tunnel*","*devtunnel*"))
  AND Processes.parent_process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","bash","sh")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS resolution of confirmed HelloDoor C2 domain (`female-disorder-beta-metropolitan.trycloudflare.com`) | 95 | Direct IOC match — confirmed Kimsuky HelloDoor infrastructure |
| DNS resolution of new httpMalice C2 domains (`pyrotech.co.kr`, `newjo-imd.com`, `yespp.co.kr`) | 95 | Direct IOC match — confirmed Kimsuky campaign C2 |
| `nos-setup.exe` or `astx-setup.exe` executing | 90 | Fake South Korean security software installer names; specific Kimsuky delivery artifacts |
| PowerShell command line referencing `mTSTCv8` | 90 | Intermediate downloader name is Kimsuky-specific |
| VS Code with `--tunnel` flag spawned from script interpreter parent | 80 | Kimsuky post-exploitation pattern; VS Code tunnel C2 evasion technique |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Kimsuky (Velvet Chollima, APT43, Thallium) | [MITRE ATT&CK — G0094 Kimsuky](https://attack.mitre.org/groups/G0094/) |
| Kimsuky — PebbleDash / HelloDoor cluster | [The Hacker News — Kimsuky Deploys HelloDoor (2026-05-29)](https://thehackernews.com/2026/05/kimsuky-deploys-httpspy-expands-arsenal.html) |
| Kimsuky — Enki research | [Enki White Hat — JSONPing, Webex Spoofing, HttpSpy Variant](https://www.enki.co.kr/en/media-center/blog/kimsuky-s-advanced-attack-techniques-jsonping-webex-spoofing-and-a-new-httpspy-variant) |

## References

- [The Hacker News — Kimsuky Deploys HTTPSpy, HelloDoor and VS Code Tunnels (2026-05-29)](https://thehackernews.com/2026/05/kimsuky-deploys-httpspy-expands-arsenal.html)
- [Enki White Hat — Kimsuky's Advanced Attack Techniques: JSONPing, Webex Spoofing, and a New HttpSpy Variant](https://www.enki.co.kr/en/media-center/blog/kimsuky-s-advanced-attack-techniques-jsonping-webex-spoofing-and-a-new-httpspy-variant)
- [Kaspersky Securelist — PebbleDash-based tools by Kimsuky (2026-05-15)](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/)
- [MITRE ATT&CK — T1219 Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK — T1102.001 Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK — G0094 Kimsuky](https://attack.mitre.org/groups/G0094/)
