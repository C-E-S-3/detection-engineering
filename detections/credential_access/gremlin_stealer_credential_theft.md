# Gremlin Stealer — Browser Credential and Crypto Wallet Theft

## Description

Detects the Gremlin Stealer, a C#-based Windows infostealer sold as Malware-as-a-Service (MaaS) via Telegram. Gremlin Stealer harvests browser credentials (Chromium and Gecko stores, including Chrome Cookie V20 bypass), Telegram session files, Steam data, FTP credentials, VPN configs, and cryptocurrency wallet addresses (via clipboard clipping), then exfiltrates all data to an attacker-controlled portal via hard-coded Telegram Bot API key. The May 2026 variant obfuscates critical functions within the .NET resource section using single-byte XOR, decrypting each into memory only at call time. Detection focuses on: non-browser process access to browser credential store files, outbound connections to confirmed C2 IP `207.244.199[.]46`, non-browser processes using the Telegram Bot API for sendDocument/sendMessage, and known file hashes. False positives: enterprise password managers that access browser profile directories; credential backup or sync utilities; Telegram Desktop itself making API calls.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Steal Web Session Cookie |
| Technique ID | T1539 |

Secondary techniques: T1555.003 (Credentials from Web Browsers — Chromium/Gecko credential stores), T1528 (Steal Application Access Token — Telegram session data), T1552.001 (Unsecured Credentials: Credentials in Files — VPN/FTP configs), T1115 (Clipboard Data — crypto clipping), T1567 (Exfiltration Over Web Service — Telegram Bot API), T1027.009 (Obfuscated Files or Information: Embedded Payloads — XOR-encrypted .NET resource section)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_path="*\\AppData\\Local\\*\\User Data\\Default\\Login Data*"
      OR Filesystem.file_path="*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json*"
      OR Filesystem.file_path="*\\AppData\\Roaming\\Telegram Desktop\\tdata\\*"
      OR Filesystem.file_path="*\\AppData\\Local\\Steam\\config\\loginusers.vdf*"
      OR Filesystem.file_path="*\\AppData\\Roaming\\*\\profiles.ini*")
    AND Filesystem.action="read"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_id Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"(?i)Login Data") AND NOT match(process_name,"(?i)chrome|msedge|brave|opera|vivaldi"), 90,
    match(file_path,"(?i)logins\.json") AND NOT match(process_name,"(?i)firefox"), 90,
    match(file_path,"(?i)Telegram.*tdata") AND NOT match(process_name,"(?i)telegram"), 85,
    match(file_path,"(?i)loginusers\.vdf") AND NOT match(process_name,"(?i)steam"), 80,
    1=1, 70)
| where risk_score >= 80
| table firstTime lastTime dest user process_name process_id file_path risk_score
```

**Supplemental: Gremlin Stealer C2 connection to 207.244.199.46**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip="207.244.199.46"
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port app risk_score
```

**Supplemental: Non-browser process using Telegram Bot API for data upload**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_domain="api.telegram.org"
    AND NOT All_Traffic.process_name IN ("Telegram.exe","telegram","chrome.exe","firefox.exe","msedge.exe",
                                          "slack.exe","mattermost.exe","teams.exe")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_domain All_Traffic.bytes_out
     All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    bytes_out > 1048576, 90,
    bytes_out > 102400, 80,
    1=1, 70)
| where risk_score >= 80
| table firstTime lastTime src_ip dest_domain process_name bytes_out risk_score
```

**Supplemental: Gremlin Stealer file hash match**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_hash IN (
    "d1ea7576611623c6a4ad1990ffed562e8981a3aa209717065eddc5be37a76132",
    "2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_path file_name file_hash risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Known Gremlin Stealer hash on disk | 95 | Direct IOC match; confirmed malicious sample |
| Connection to `207.244.199[.]46` | 95 | Confirmed Gremlin Stealer exfiltration endpoint; no legitimate use |
| Browser credential store read by non-browser process | 90 | Infostealer hallmark; legitimate access is exclusively from the owning browser |
| Telegram session data read by non-Telegram process | 85 | Session hijacking attempt; no legitimate non-Telegram process should read tdata |
| Non-browser process sending > 1 MB to Telegram Bot API | 90 | Bulk data exfiltration via Telegram; Gremlin Stealer exfiltration pattern |
| Non-browser process sending > 100 KB to Telegram Bot API | 80 | Smaller exfiltration; review alongside other indicators |
| Steam loginusers.vdf read by non-Steam process | 80 | Gaming credential theft; Gremlin Stealer targets Steam session tokens |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gremlin Stealer (MaaS — multiple buyers) | [Unit 42 — Gremlin Stealer Evolution (2026-05-15)](https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/), [Unit 42 — Original Gremlin Stealer (2025)](https://unit42.paloaltonetworks.com/new-malware-gremlin-stealer-for-sale-on-telegram/) |

## References

- [Unit 42 — Gremlin Stealer's Evolved Tactics: Hiding in Plain Sight With Resource Files (2026-05-15)](https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/)
- [Unit 42 — Gremlin Stealer: New Stealer on Sale in Underground Forum](https://unit42.paloaltonetworks.com/new-malware-gremlin-stealer-for-sale-on-telegram/)
- [MITRE ATT&CK — T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK — T1555.003 Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK — T1115 Clipboard Data](https://attack.mitre.org/techniques/T1115/)
