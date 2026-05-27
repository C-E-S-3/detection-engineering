---
scraped_at: 2026-05-27T00:00:00Z
source_url: https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/
report_type: threat-intel
severity: high
title: "Nimbus Manticore: IRGC-Linked APT Deploys AI-Assisted MiniFast Backdoor and MiniJunk V2 via AppDomain Hijacking and SEO Poisoning"
---

# Nimbus Manticore: IRGC-Linked APT Deploys AI-Assisted MiniFast Backdoor and MiniJunk V2

## 1. IOCs

### Domains

| Indicator | Context |
|-----------|---------|
| getsqldeveloper[.]com | Nimbus Manticore SEO-poisoned fake SQL Developer download site; delivers weaponized installer dropping MiniFast backdoor; boosted by dozens of attacker-registered link-farm domains |

### Techniques / Artifacts (No Additional Public Hashes Confirmed at Time of Scrape)

| Artifact | Description |
|----------|-------------|
| `<appname>.config` (trojanized) | XML .config file placed alongside a legitimate .NET binary; specifies attacker-controlled `AppDomainManager` class pointing to malicious DLL — key AppDomain Hijacking artifact |
| MiniFast (aka MiniUpdate) | 64-bit Windows DLL backdoor; JSON-over-HTTP C2; mimics Chrome browser User-Agent; opcode-driven command set (shell exec, file transfer, process control, scheduled task persistence) |
| MiniJunk V2 | Updated variant of Nimbus Manticore's earlier MiniJunk implant; delivered alongside MiniFast in coordinated campaigns against U.S., Israel, UAE, and Middle East targets |
| Zoom installer (trojanized) | Legitimate Zoom installer's execution flow abused for time-sensitive DLL sideloading and malware staging |

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1566.001 | Spearphishing Attachment | Career-themed phishing lures impersonating aviation and software sector organizations |
| Initial Access | T1189 | Drive-by Compromise | SEO-poisoned `getsqldeveloper[.]com` delivers trojanized SQL Developer installer to searching victims |
| Initial Access | T1608.006 | Acquire Infrastructure: SEO Poisoning | Dozens of attacker-registered domains link to `getsqldeveloper[.]com` to inflate search-engine ranking |
| Defense Evasion / Execution | T1574.014 | Hijack Execution Flow: AppDomain Manager Injection | Trojanized `.config` file placed alongside a legitimate .NET binary; specifies attacker-controlled `AppDomainManager` to sideload malicious DLL at runtime without modifying the host binary |
| Defense Evasion | T1574.002 | DLL Side-Loading | Zoom installer execution flow abused to sideload MiniFast DLL |
| Persistence | T1053.005 | Scheduled Task/Job | MiniFast establishes persistence via Windows scheduled tasks |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | MiniFast communicates via JSON over HTTP, mimicking Chrome browser User-Agent |
| Resource Development | T1587.001 | Develop Capabilities: Malware | AI-assisted malware development evidenced by excessive error handling, verbose debug strings, modular code patterns |

## 3. Malware & Tools

- **MiniFast (aka MiniUpdate)** — 64-bit Windows DLL; full-featured backdoor with opcode-driven C2 protocol over JSON/HTTP; capabilities include remote shell execution, file upload/download, directory and process enumeration, dynamic C2 interval configuration, and scheduled task persistence. AI-assisted development is strongly indicated by excessive defensive programming, verbose function names, and detailed debug strings.
- **MiniJunk V2** — Updated variant of the earlier MiniJunk implant; used in coordinated campaigns targeting U.S., Israel, UAE, and broader Middle East. Reported alongside MiniFast by Unit 42.
- **Trojanized Zoom Installer** — Legitimate Zoom installer co-opted to stage a time-sensitive DLL sideloading chain, blending into normal software installation activity.

## 4. Threat Actor / Campaign Attribution

- **Actor**: Nimbus Manticore
- **Nexus**: Iran / IRGC (Islamic Revolutionary Guard Corps) affiliated
- **History**: Known for targeting defense, aerospace, and telecom sectors via career-themed phishing lures
- **Campaign context**: Activity surged after **Operation Epic Fury** (U.S. military strikes against Iran, February 28, 2026). Actor demonstrated accelerated tooling development and adoption of new delivery techniques during the conflict period.
- **Timeline**:
  - February 2026: AppDomain Hijacking first observed delivering MiniJunk
  - March 2026: MiniFast backdoor introduced into campaign rotation
  - April 2026: SEO poisoning added as delivery vector via `getsqldeveloper[.]com`
  - May 2026: Check Point Research public disclosure

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name="*.config"
    Filesystem.file_path IN ("*\\Program Files\\*","*\\Program Files (x86)\\*","*\\Windows\\*")
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"(?i)\\\\Windows\\\\"), 85,
    match(file_path,"(?i)\\\\Program Files"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("zoom.exe","ZoomInstaller.exe","ZoomSetup.exe")
    Processes.process IN ("*cmd.exe*","*powershell*","*rundll32*","*mshta*","*wscript*","*cscript*","*regsvr32*")
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
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("getsqldeveloper.com","getsqldeveloper[.]com")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

## 6. Executive Summary

Nimbus Manticore, an IRGC-affiliated Iranian APT, significantly escalated operations following Operation Epic Fury in February 2026. Check Point Research published analysis of a multi-wave campaign deploying two new implants: **MiniFast** (a 64-bit Windows DLL backdoor with AI-assisted development indicators) and **MiniJunk V2** (an updated variant reported concurrently by Unit 42).

The campaign introduced two notable new TTPs: **AppDomain Manager Injection** (T1574.014) — placing a trojanized `.config` file alongside a legitimate .NET application to force-load a malicious DLL at runtime — and **SEO poisoning** via `getsqldeveloper[.]com`, a fake Oracle SQL Developer site boosted by dozens of link-farm domains. A trojanized Zoom installer was also used to stage DLL sideloading, blending into normal software update activity.

Targeted sectors include defense, aviation, software development, telecom, and energy in the U.S., Europe, Israel, UAE, and the Middle East. Defenders should monitor for unexpected `.config` file creation in program directories, Zoom installer spawning shell utilities, and DNS queries for `getsqldeveloper[.]com`.
