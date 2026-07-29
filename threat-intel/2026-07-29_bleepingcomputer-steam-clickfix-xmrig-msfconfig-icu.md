---
scraped_at: "2026-07-29T08:00:00Z"
source_url: https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-campaign-delivers-xmrig-cryptominer-via-fake-config-tool/
report_type: threat-intel
severity: medium
title: "Steam Forum ClickFix Campaign — Fake Config Tool Lure Delivers XMRig Cryptominer via msfconfig[.]icu"
---

# Steam Forum ClickFix Campaign — Fake Config Tool Lure Delivers XMRig Cryptominer via msfconfig[.]icu

BleepingComputer reported (active window July 25–28, 2026) on a **ClickFix** campaign abusing Steam community forums and gaming-adjacent channels to deliver **XMRig** cryptominer. Threat actors posted fake "performance config tool" and "FPS optimizer" content on Steam Discussion boards instructing victims to run PowerShell commands. Copying and pasting the ClickFix payload triggers a download from `msfconfig[.]icu` — a domain deliberately registered to appear as Microsoft's `msconfig` system utility — which drops and persistently installs an XMRig Monero (XMR) miner.

## 1. IOCs

### Domains (1)

| Indicator | Notes |
|-----------|-------|
| msfconfig[.]icu | ClickFix download domain; delivers XMRig payload; impersonates Microsoft msconfig utility; Steam gaming forum lure campaign, July 2026 |

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1566.003 | Phishing: Spearphishing via Service | Malicious ClickFix instructions posted in Steam community forums |
| Execution | T1059.001 | PowerShell | Victim executes attacker-controlled PowerShell from clipboard (ClickFix social engineering) |
| Execution | T1204.002 | User Execution: Malicious File | Victim runs the downloaded XMRig binary |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Domain `msfconfig[.]icu` impersonates Windows msconfig.exe system tool |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | XMRig persists via scheduled task or startup entry |
| Impact | T1496 | Resource Hijacking | XMRig mines Monero (XMR) using victim CPU/GPU, degrading system performance |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | XMRig beacon to Monero mining pool over HTTP/HTTPS |

## 3. Malware & Tools

**XMRig (Monero CPU/GPU Miner)**

An open-source Monero cryptocurrency miner that is routinely weaponized by threat actors for unauthorized mining (cryptojacking). In this campaign, it is delivered via a ClickFix lure chain targeting the Steam gaming community:

1. Attacker posts "FPS optimizer" or "game config tool" on Steam community forums / Discord channels
2. Post contains a ClickFix instruction: "Press Win+R, paste this command..." (or Ctrl+V into a Run dialog)
3. PowerShell command downloads XMRig from `msfconfig[.]icu`
4. XMRig installed, scheduled task created for persistence
5. Miner connects to Monero pool — victim's CPU/GPU resources drained

**ClickFix social engineering** specifically targets tech-literate gamers who may be more comfortable running PowerShell commands than typical enterprise users, expecting them to see "config" in the domain name and trust the pseudo-official appearance.

## 4. Threat Actor / Campaign Attribution

| Actor | Assessment | Notes |
|-------|-----------|-------|
| Unknown financially motivated actor | Medium confidence — BleepingComputer campaign analysis | No APT attribution; financially motivated cryptomining via gaming community targeting; domain registration pattern (`msfconfig`) indicates deliberate Microsoft impersonation |

## 5. Splunk Detection Searches

```spl
`-- DNS: Lookup for ClickFix XMRig delivery domain`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("msfconfig.icu","www.msfconfig.icu")
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query record_type risk_score
```

```spl
`-- Endpoint: ClickFix execution pattern — PowerShell spawned from Run dialog (explorer.exe)`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("explorer.exe","cmd.exe")
  AND Processes.process_name IN ("powershell.exe","pwsh.exe")
  AND Processes.process IN ("*msfconfig*","*icu*","*xmrig*","*-encodedcommand*","*FromBase64String*","*DownloadString*","*IEX*","*Invoke-Expression*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

```spl
`-- Endpoint: XMRig process execution or known miner binary patterns`
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("xmrig.exe","xmrig","xmrig-cuda","xmrig-amd")
   OR Processes.process IN ("*--donate-level*","*--pool*","*xmr*","*monero*","*stratum+tcp*","*stratum+ssl*")
by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user process_name process process_id risk_score
```

## 6. Executive Summary

A **ClickFix** campaign active in Steam gaming forums between July 25–28, 2026 uses fake "performance optimizer" and "FPS config tool" posts to trick gamers into executing PowerShell commands. The command downloads from `msfconfig[.]icu` — a domain impersonating Windows `msconfig` — and installs **XMRig** Monero miner with scheduled task persistence. The attack is straightforward but effective in gaming communities where users routinely run config scripts and may not scrutinize domain names carefully. No credential theft or lateral movement has been confirmed; the campaign is financially motivated cryptomining. Block `msfconfig[.]icu` at DNS/proxy. Hunt for XMRig process execution and for PowerShell spawned by explorer.exe referencing `msfconfig` or download-string patterns.

## References

- https://www.bleepingcomputer.com/news/security/steam-forum-clickfix-campaign-delivers-xmrig-cryptominer-via-fake-config-tool/ — BleepingComputer, 2026-07-28
- https://attack.mitre.org/techniques/T1566/003/ — T1566.003 Phishing via Service
- https://attack.mitre.org/techniques/T1496/ — T1496 Resource Hijacking
- https://github.com/xmrig/xmrig — XMRig open source project
