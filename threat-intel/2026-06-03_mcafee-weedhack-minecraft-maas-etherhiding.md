---
scraped_at: 2026-06-05T05:30:00Z
source_url: https://www.mcafee.com/blogs/other-blogs/mcafee-labs/weedhack-minecraft-malware-as-a-service-campaign-research/
report_type: threat-intel
severity: medium
title: "WeedHack: Minecraft Malware-as-a-Service Campaign Uses EtherHiding Blockchain C2 to Infect 116,000+ Systems via SEO Poisoning and YouTube"
---

# WeedHack: Minecraft Malware-as-a-Service Campaign Uses EtherHiding Blockchain C2 to Infect 116,000+ Systems via SEO Poisoning and YouTube

McAfee Labs disclosed WeedHack on June 3, 2026 — a large-scale Malware-as-a-Service (MaaS) campaign targeting Minecraft players through SEO-poisoned fake mod download sites and YouTube-promoted malicious JAR files. Active since at least January 2026, the campaign has infected over 116,000 systems, averaging 2,000–3,000 new infections per day. WeedHack's most notable technical innovation is its use of the **EtherHiding** technique, which retrieves its current C2 domain from the Ethereum blockchain, making the C2 infrastructure highly resilient against takedown.

## 1. IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `telemetrydata[.]to` | C2 domain | Primary WeedHack C2 server; receives collected system information and serves second-stage payloads (Elevator.jar); used by approximately 116,000 infected systems as of June 3, 2026 |

### File Artifacts

| Indicator | Type | Context |
|-----------|------|---------|
| `DonutDupe.jar` | Malicious JAR | Starting point of the WeedHack infection chain; distributed as a fake Minecraft modification from SEO-poisoned download sites and YouTube-promoted links; executes on victim systems via `java -jar` |
| `Elevator.jar` | Second-stage JAR | Java payload fetched from the C2 server (`telemetrydata[.]to`); collects system information, configures Microsoft Defender exclusions, drops two additional JAR payloads, and establishes persistence |

### Distribution Infrastructure

- Over 240 distinct URLs used for distributing malicious JAR files
- Over 3,820 unique malicious JAR file variants (polymorphic)
- YouTube videos promoting "free Minecraft hacks/mods" as initial lure vector
- SEO poisoning of Minecraft mod download queries driving victims to malicious sites

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|----|-------------|
| Initial Access | Drive-by Compromise | T1189 | SEO poisoning of Minecraft mod search terms drives victims to attacker-controlled download sites; victims download and manually execute malicious JAR files promoted as game mods or hacks |
| Initial Access | Phishing: Spearphishing via Service | T1566.003 | YouTube videos embed links to malicious Minecraft mod downloads, presenting social proof via subscriber counts and view counts |
| Execution | User Execution: Malicious File | T1204.002 | Victim manually executes `DonutDupe.jar` believing it to be a legitimate Minecraft mod or hack; Java process launches without trusted signing |
| Execution | Command and Scripting Interpreter | T1059 | `DonutDupe.jar` launches a four-stage infection chain; `Elevator.jar` executes additional Java-based payload droppers |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | `Elevator.jar` configures Microsoft Defender exclusions to prevent detection of subsequently dropped payloads |
| Defense Evasion | Obfuscated Files or Information | T1027 | JAR file payload is obfuscated; custom class loader loads the second stage directly into memory (reflective loading) |
| Defense Evasion | Dynamic Resolution | T1568 | **EtherHiding**: First-stage malware queries the Ethereum blockchain to retrieve the current C2 domain; allows operators to update C2 addresses without modifying distributed malware, evading static domain blocklists |
| Command and Control | Dynamic Resolution: Dead Drop Resolver | T1568.001 | EtherHiding uses publicly readable Ethereum smart contract state or transaction data as a dead drop to publish current C2 domain strings |
| Persistence | Boot or Logon Autostart Execution | T1547 | WeedHack establishes persistence mechanisms during the third and fourth infection chain stages to survive system reboots |
| Collection | Screen Capture | T1113 | Remote access tool capabilities include webcam access and screen capture |
| Collection | Input Capture: Keylogging | T1056.001 | Keylogging capability deployed in final infection stage |
| Command and Control | Remote Access Software | T1219 | Reverse shell capability established; full remote access to compromised endpoint |

## 3. Malware & Tools

### WeedHack Infection Chain

```
Stage 1: DonutDupe.jar
  └─ Queries Ethereum blockchain (EtherHiding) to resolve C2 domain
  └─ Downloads second stage from resolved C2

Stage 2: Elevator.jar (fetched from telemetrydata[.]to)
  └─ Collects system information
  └─ Configures Microsoft Defender exclusions
  └─ Drops and executes two additional JAR payloads

Stage 3: Persistence installation
  └─ Establishes autostart mechanisms

Stage 4: Remote access tool
  └─ Webcam access
  └─ Keylogging
  └─ Reverse shell / RAT capability
```

**Distribution:** Sold as a MaaS subscription, enabling multiple threat actors to deploy WeedHack without developing the infrastructure themselves. The attacker's backend manages C2 updates via blockchain transactions, providing centralized infrastructure control across all MaaS customers.

**AV Detection:** McAfee detects WeedHack samples as:
- `Trojan:Win/Weedhack.AA`
- `Trojan:Win/Weedhack.AB`
- `Trojan:Win/Weedhack.AC`
- `Trojan:Win/Weedhack.AD`
- `Trojan:Win/Weedhack.AE`

## 4. Threat Actor / Campaign Attribution

| Actor | Confidence | Notes |
|-------|-----------|-------|
| Unknown (WeedHack MaaS Operator) | Low | Unattributed; financially motivated; operating a MaaS platform accessible to multiple downstream attackers; campaign active since January 2026; Minecraft targeting and EtherHiding C2 resilience suggest a technically capable developer-for-hire or underground service provider |

**EtherHiding Technique Precedent:** EtherHiding was first publicly documented in ClearFake campaigns in 2023–2024, where it was used to update fake browser update lure pages dynamically. WeedHack's use represents adoption of the technique by a different actor for C2 domain rotation, demonstrating ongoing spread of this blockchain-based evasion technique across threat actor communities.

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("java", "java.exe", "javaw", "javaw.exe")
  AND Processes.process_name IN ("powershell.exe", "powershell", "cmd.exe", "cmd",
    "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "curl", "wget",
    "certutil.exe", "bitsadmin.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("powershell.exe", "powershell"), 80,
    process_name IN ("mshta.exe", "regsvr32.exe"), 85,
    process_name IN ("cmd.exe", "cmd"), 70,
    process_name IN ("curl", "wget", "certutil.exe", "bitsadmin.exe"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path IN ("*\\Downloads\\*.jar", "*\\AppData\\*\\*.jar",
    "*/tmp/*.jar", "*/home/*/Downloads/*.jar")
  AND Filesystem.action="created"
by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search file_name IN ("DonutDupe.jar", "Elevator.jar") OR match(file_path, "(?i)(hack|cheat|mod|free|crack).*\.jar")
| eval risk_score=case(
    file_name IN ("DonutDupe.jar", "Elevator.jar"), 90,
    match(file_path, "(?i)(hack|cheat|free|crack).*\.jar"), 70,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user file_path file_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("telemetrydata.to")
   OR (DNS.query_type IN ("TXT") AND DNS.query IN ("*.eth", "*.eth.link", "*.eth.limo"))
by DNS.src DNS.query DNS.answer DNS.query_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    query="telemetrydata.to", 90,
    match(query, "\.eth$|\.eth\.link$|\.eth\.limo$") AND query_type="TXT", 65,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime src query answer query_type risk_score
```

## 6. Executive Summary

WeedHack is a Malware-as-a-Service (MaaS) campaign targeting Minecraft players, disclosed by McAfee Labs on June 3, 2026. Since January 2026, the campaign has infected over 116,000 systems by distributing malicious JAR files through SEO-poisoned Minecraft mod search results and YouTube promotional videos. The initial payload (`DonutDupe.jar`) uses the EtherHiding technique — querying the Ethereum blockchain to retrieve the current C2 domain — providing the operator with a highly resilient C2 infrastructure that is resistant to standard domain-based blocking. After resolving the C2, the malware downloads a second-stage payload (`Elevator.jar` from `telemetrydata[.]to`) that disables Microsoft Defender, collects system information, and ultimately installs a full remote access tool with keylogging, webcam capture, and reverse shell capabilities.

While WeedHack primarily targets consumer endpoints (Minecraft players), enterprise environments hosting developer workstations may be affected if employees run Minecraft on work machines or if the malicious JAR files reach corporate endpoints through personal downloads. The EtherHiding C2 technique is significant for enterprise defenders because standard domain blocklists are ineffective; detection must focus on suspicious Java process behavior and outbound Ethereum node queries.

## References

- [McAfee Labs — Game Over: WeedHack Rise of Minecraft MaaS Campaign](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/weedhack-minecraft-malware-as-a-service-campaign-research/)
- [BleepingComputer — Over 116,000 Minecraft Systems Infected in WeedHack Campaign](https://www.bleepingcomputer.com/news/security/over-116-000-minecraft-systems-infected-in-weedhack-malware-campaign/)
- [Help Net Security — WeedHack Minecraft Malware Campaign (June 3, 2026)](https://www.helpnetsecurity.com/2026/06/03/weedhack-minecraft-malware-campaign/)
- [The Hacker News — WeedHack Attacks Minecraft Users](https://thehackernews.com/2026/06/weedhack-attacks-minecraft-users.html)
- [MITRE ATT&CK — T1189: Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK — T1568: Dynamic Resolution](https://attack.mitre.org/techniques/T1568/)
- [MITRE ATT&CK — T1568.001: Dead Drop Resolver](https://attack.mitre.org/techniques/T1568/001/)
