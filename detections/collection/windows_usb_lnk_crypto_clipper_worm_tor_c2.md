# Windows USB LNK Crypto Clipper Worm with Tor-Based C2

## Description

Detects the Windows cryptocurrency clipboard hijacking worm disclosed by Microsoft on June 17, 2026. The malware distributes via malicious `.lnk` (Windows Shortcut) files placed on USB drives. When a victim browses the USB in Explorer, Windows Script Host (wscript.exe) processes the shortcut and executes the embedded payload. The malware deploys a **bundled portable Tor client** for C2, polls the clipboard every 500ms to replace cryptocurrency wallet addresses (BTC, ETH) and BIP39 seed phrases with attacker-controlled equivalents, and propagates by copying .lnk files to any connected USB storage.

The Tor-based C2 eliminates traditional network-layer IOCs (no public C2 IPs or domains), making perimeter-based blocking ineffective. Detection must focus on process behavior (wscript from Explorer, Tor spawned outside browser), filesystem artifacts, and endpoint telemetry.

False positives: wscript.exe invoked by legitimate installer .lnk shortcuts; tune by excluding known software installation events. Tor.exe from legitimate Tor Browser installations is expected — filter by parent process and executable path.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Clipboard Data |
| Technique ID | T1115 |

Secondary Techniques:
- T1091 — Replication Through Removable Media (USB .lnk worm propagation; initial access)
- T1059.005 — Command and Scripting Interpreter: Visual Basic (wscript.exe VBS execution)
- T1090.003 — Proxy: Multi-hop Proxy (bundled Tor client for C2 anonymization)
- T1053.005 — Scheduled Task/Job: Scheduled Task (persistence mechanism)
- T1552.001 — Unsecured Credentials: Credentials In Files (BIP39 seed phrase harvesting)
- T1027 — Obfuscated Files or Information (payload obfuscation)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |
| Command & Control |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="explorer.exe"
    AND Processes.process_name IN ("wscript.exe","cscript.exe","mshta.exe","powershell.exe","cmd.exe")
    AND (Processes.process LIKE "%.lnk%" OR Processes.process LIKE "%\\\\[EFG-Z]:\\\\%"
         OR Processes.process LIKE "%Removable%")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "\.lnk") AND process_name IN ("wscript.exe","mshta.exe"), 90,
    match(process, "[EFG-Z]:\\\\") AND process_name="wscript.exe", 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="tor.exe"
    AND NOT Processes.parent_process_name IN ("firefox.exe","tor-browser.exe",
                                               "start-tor-browser.exe","vidalia.exe")
    AND NOT Processes.process_path LIKE "%Tor Browser%"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("wscript.exe","cscript.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval spawned_tor_candidate=if(
    match(process, "tor|socks|proxy"), 1, 0)
| eval risk_score=case(spawned_tor_candidate=1, 88, parent_process_name="explorer.exe", 75, 1=1, 50)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name LIKE "*.lnk"
    AND Filesystem.action="created"
    AND NOT Filesystem.file_path LIKE "%\\Programs\\%"
    AND NOT Filesystem.file_path LIKE "%\\Desktop\\%"
    AND NOT Filesystem.file_path LIKE "%\\Taskbar\\%"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "[EFG-Z]:\\\\"), 85,
    match(file_path, "AppData\\\\Roaming"), 80,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user file_path file_name risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| tor.exe spawned from non-browser parent outside Tor Browser path | 95 | Near-certain malware embedding bundled Tor for C2 |
| Explorer spawning wscript.exe processing .lnk file | 90 | Classic USB .lnk worm execution chain |
| wscript.exe/cscript.exe child of explorer.exe with removable drive path | 85 | USB autorun-style execution |
| .lnk file created outside normal shortcut locations (Desktop/Programs/Taskbar) | 85 | Worm copying .lnk to propagate to USB |
| wscript.exe with Tor/SOCKS/proxy indicators in command line | 88 | Malware deploying Tor proxy for C2 |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed (likely Russian-speaking financially motivated actor) | [Microsoft Security Blog (2026-06-17)](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/) |

## References

- [Microsoft Security Blog — Crypto Clipper uses Tor and worm-like propagation (2026-06-17)](https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/)
- [BleepingComputer — USB worm spreads crypto-stealing malware via Windows shortcut files (2026-06-18)](https://www.bleepingcomputer.com/news/security/usb-worm-spreads-crypto-stealing-malware-via-windows-shortcut-files/)
- [MITRE ATT&CK — T1115 Clipboard Data](https://attack.mitre.org/techniques/T1115/)
- [MITRE ATT&CK — T1091 Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK — T1090.003 Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)
