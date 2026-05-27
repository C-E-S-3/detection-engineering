---
scraped_at: 2026-05-27T00:00:00Z
source_url: https://www.security.com/threat-intelligence/iran-seedworm-electronics
report_type: threat-intel
severity: high
title: "Seedworm (MuddyWater) Q1 2026 Espionage Campaign: DLL Sideloading via Signed Fortemedia and SentinelOne Binaries Targets 9 Countries"
---

# Seedworm (MuddyWater) Q1 2026 Espionage Campaign: DLL Sideloading via Signed AV Binaries

## 1. IOCs

### IP Addresses

| Indicator | Context |
|-----------|---------|
| 157.20.182[.]49 | Attacker-controlled C2 IP embedded in malicious DLL code; used for outbound callback from ChromElevator-embedded credential-harvesting DLL |

### File Hashes

| Hash | Type | Description |
|------|------|-------------|
| d587959841a763669279ad831b8f0379f6a7b037dffc19deab5d41f37f8b5ffc | SHA256 | Malicious DLL sideloaded by Seedworm via signed Fortemedia/SentinelOne binary; contains ChromElevator for Chromium App-Bound Encryption bypass and credential theft; documented by Group-IB (February 2026) and Symantec (May 2026) |

### Additional Artifacts

| Artifact | Description |
|----------|-------------|
| fmapp.dll | Malicious DLL sideloaded by `fmapp.exe` (legitimate signed Fortemedia audio driver utility) |
| sentinelagentcore.dll | Malicious DLL sideloaded by `sentinelmemoryscanner.exe` (legitimate signed SentinelOne binary) |
| ChromElevator | Open-source Chromium App-Bound Encryption bypass tool embedded in both DLLs; harvests passwords, cookies, and payment card data |
| sendit.sh | Public file-sharing service abused for data exfiltration |

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Defense Evasion | T1574.002 | Hijack Execution Flow: DLL Side-Loading | `fmapp.exe` (Fortemedia) sideloads `fmapp.dll`; `sentinelmemoryscanner.exe` (SentinelOne) sideloads `sentinelagentcore.dll`; signed parent binary provides cover |
| Credential Access | T1555.003 | Credentials from Web Browsers | ChromElevator bypasses Chromium App-Bound Encryption (ABE) to extract passwords, cookies, and payment card data from all Chromium-based browsers |
| Exfiltration | T1567.002 | Exfiltration to Code Repository | Data exfiltrated via sendit.sh (public file-sharing service) to avoid triggering firewall rules against known exfil destinations |
| Discovery | T1057 | Process Discovery | DLL enumerates running processes for targeting and C2 callback |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Malicious DLL connects to attacker-controlled 157.20.182[.]49 for tasking |

## 3. Malware & Tools

- **fmapp.dll** — Malicious DLL placed in the same directory as the legitimate Fortemedia audio utility `fmapp.exe`; contains ChromElevator and C2 callback to 157.20.182[.]49. Previously used in a MuddyWater campaign codenamed **Operation Olalampo** (documented by Group-IB).
- **sentinelagentcore.dll** — Malicious DLL placed alongside the legitimate SentinelOne binary `sentinelmemoryscanner.exe` to exploit DLL search order; same ChromElevator payload.
- **ChromElevator** — Open-source tool that defeats Chromium App-Bound Encryption introduced in Chrome v127+; enables credential harvesting even on up-to-date browsers.

## 4. Threat Actor / Campaign Attribution

- **Actor**: Seedworm, also known as MuddyWater, Temp Zagros, Static Kitten, Earth Vetala (G0069)
- **Nexus**: Iran / Ministry of Intelligence and Security (MOIS)
- **Campaign period**: Q1 2026 (confirmed activity February 2026 onward)
- **Victims**: At least 9 organizations across 9 countries on 4 continents, including:
  - Major South Korean electronics manufacturer (week-long breach, February 2026)
  - International airport in the Middle East
  - Southeast Asian industrial manufacturers
  - Latin American financial-services provider
- **Sectors targeted**: Industrial and electronics manufacturing, education, public sector, financial services, professional services

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("fmapp.exe","sentinelmemoryscanner.exe")
    Processes.process_name IN ("cmd.exe","powershell.exe","mshta.exe","wscript.exe",
                               "cscript.exe","rundll32.exe","regsvr32.exe","schtasks.exe",
                               "net.exe","whoami.exe","ipconfig.exe","nltest.exe")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="157.20.182.49"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port action risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("fmapp.exe","sentinelmemoryscanner.exe")
    Processes.process_path!="*\\Fortemedia\\*"
    Processes.process_path!="*\\SentinelOne\\*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process_path Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="fmapp.exe", 85,
    process_name="sentinelmemoryscanner.exe", 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process_path risk_score
```

## 6. Executive Summary

Symantec (security.com) documented a Q1 2026 espionage campaign by **Seedworm** (MuddyWater), an Iranian APT operating on behalf of MOIS, that compromised at least 9 organizations across 9 countries in four continents. The campaign's distinguishing technical feature is DLL sideloading via **legitimately signed security and audio software binaries**: the Fortemedia audio utility `fmapp.exe` sideloads `fmapp.dll`, and the SentinelOne scanner `sentinelmemoryscanner.exe` sideloads `sentinelagentcore.dll`. Both malicious DLLs embed **ChromElevator**, an open-source tool that bypasses Chromium App-Bound Encryption to steal passwords, cookies, and payment card data from all Chromium-based browsers.

The malicious DLL connects to attacker-controlled IP `157.20.182[.]49` for C2, and exfiltrates harvested data via the public file-sharing service `sendit.sh`. The use of signed vendor binaries from SentinelOne — a security product — as a sideloading carrier is particularly notable and underscores that digitally signed files must not be blindly trusted.

Defenders should alert on `fmapp.exe` or `sentinelmemoryscanner.exe` executing from non-standard installation paths, spawning unexpected child processes, or connecting to non-vendor IP addresses.
