---
scraped_at: 2026-08-21T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia
report_type: threat-intel
severity: high
title: "Going with the Flow(s): Distinct Clusters Target Individuals of Interest to Russia"
---

# Going with the Flow(s): Distinct Clusters Target Individuals of Interest to Russia

**Source:** Google Threat Intelligence Group (GTIG) / Mandiant  
**Published:** 2026-08-20  
**Severity:** High  
**Threat Actor:** APT29 sub-clusters (UNC6293, UNC7005/STORM-2945, UNC5976)

---

## 1. IOCs

### IP Addresses

| IP | Context |
|----|---------|
| 107.189.18.7 | APT29 cluster phishing infrastructure |
| 196.251.107.171 | APT29 cluster phishing infrastructure |

> **Previously tracked (not re-added):** 31.57.243.154, 38.146.28.75, 104.194.159.150 — already in ip.csv under APT29 CaptiveCrunch 2026-08-02.

### Domains

| Domain | Context |
|--------|---------|
| dosportal.app | OAuth phishing / credential harvesting portal |
| foreignrelations.us | Diplomatic impersonation lure domain |
| fewfwfwfwfwf.info | Phishing infrastructure |
| miov2iaiaoubqosiqoiajwowiwjso.online | Phishing infrastructure (randomized subdomain pattern) |
| mioisiskwowiwjowuwjwolab.club | Phishing infrastructure |
| chamber-ua.org | Ukraine chamber lure / diplomatic impersonation |
| wa-connect.eu | WhatsApp device linking phishing |
| wa-connect.net | WhatsApp device linking phishing |
| wa-invite.com | WhatsApp device linking phishing |
| wa-device.com | WhatsApp device linking phishing |
| wa-meeting.com | WhatsApp device linking phishing |
| shopinvite.org | WhatsApp/OAuth invite phishing |
| my-invite.org | WhatsApp/OAuth invite phishing |
| globsec.net | GLOBSEC conference impersonation |
| statistic-ms.live | Microsoft statistics lure / credential harvesting |
| owa-ms365.com | Fake Microsoft OWA / M365 login page |
| m365-owa.com | Fake Microsoft OWA / M365 login page |
| ms365-device.com | Microsoft device code phishing |
| ms365-live.com | Fake Microsoft Live login page |
| finishoperations.com | Finnish Operations Center impersonation |
| finishoperations.org | Finnish Operations Center impersonation |
| foc-share.com | FOC (Finnish Operations Center) file share lure |
| share-foc.com | FOC file share lure |
| internal-share.com | Internal share lure / credential harvesting |
| foc-share.org | FOC file share lure |
| drive.google.verify-drive.com | Google Drive impersonation / OAuth phishing |
| mail.kiis.co.uk | Kyiv International Institute of Sociology lure |

### File Hashes (SHA256)

> **Previously tracked (not re-added):** be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c — already tracked as ChocoShell/CHERRYPIE in APT29 CaptiveCrunch.

| Hash | Malware Family | Context |
|------|---------------|---------|
| 5b8d50c2e8cc3038b7c6e6dbf1219f6e814930a1e3c0053143a1191ae67f8ffc | CHERRYPIE/ChocoShell | LLM-generated PowerShell infostealer |
| a06a8fd1b6fa1924199a4540cf16d089217ce8f78c617739946f145fd1fc88c1 | CHERRYPIE/ChocoShell | LLM-generated PowerShell infostealer |
| 1d9299799a7b8da67c44ebec064d64542c27645f8e84de4a22ca3f6cbc843e3c | CHERRYPIE/ChocoShell | LLM-generated PowerShell infostealer |
| c5826032207d623a7f6caec8465af7364eccc355f9a48897da2a54f3e4420265 | ENGINELIGHT | Go-based malware |
| 125752ad7c20d715920a3b2fb0fdde660f07b3f2b053665cf38c2d6d9de86e1e | ENGINELIGHT | Go-based malware |
| 403b624e35777cbc07dbe66398b21bba70396a20b859c880732338ce1dd1f41f | HEADRUSH | Malicious Excel plugin HTA downloader |
| 28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3 | HEADRUSH | Malicious Excel plugin HTA downloader |
| 1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916 | VIDAR | MaaS infostealer |
| 6f7090895c1c3dee30de6b3f098ca3a788dc198646e5293a8b1210430b0add97 | VIDAR | MaaS infostealer |
| 20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38 | ATOMIC | macOS MaaS infostealer (AtomicStealer) |
| ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25 | ATOMIC | macOS MaaS infostealer (AtomicStealer) |
| 2c7f4165967d6f7737b3fef87959846920b57a5368b531ad1427c7214d4c41a2 | ATOMIC | macOS MaaS infostealer (AtomicStealer) |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Initial Access | Phishing: Spearphishing Link | T1566.002 | Targeted spearphishing lures impersonating diplomatic events, GLOBSEC, Finnish Operations Center, WhatsApp |
| Credential Access | Steal Application Access Token | T1528 | OAuth device code phishing to steal access tokens for M365, Google accounts |
| Credential Access | Forge Web Credentials: Web Cookies | T1606.001 | Infostealer browser cookie theft (CHERRYPIE, VIDAR, ATOMIC) |
| Credential Access | Input Capture: Keylogging | T1056.001 | CHERRYPIE/VIDAR keylogging capability |
| Defense Evasion | Use Alternate Authentication Material | T1550.001 | App-Specific Password (ASP) abuse to bypass MFA |
| Defense Evasion | Hide Artifacts: Browser Fingerprinting | T1564 | Browser fingerprinting to evade detection/analysis |
| Execution | User Execution: Malicious File | T1204.002 | Victim opens malicious Excel plugin (HEADRUSH) triggering HTA download |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | CHERRYPIE LLM-generated PowerShell infostealer execution |
| Collection | Browser Session Hijacking | T1185 | Browser credential, cookie, and payment data theft |
| Collection | Email Collection | T1114 | Credential theft enabling email access |
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | Adversary-registered phishing domains impersonating legitimate services |
| Resource Development | Compromise Infrastructure: DNS Server | T1584.002 | Captive portal DNS poisoning in hospitality networks |
| Command and Control | Web Service: Bidirectional Communication | T1102.002 | CHERRYPIE C2 via web services |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Stolen credentials/cookies exfiltrated via malware C2 |

---

## 3. Malware & Tools

### CHERRYPIE (also tracked as ChocoShell)
- **Type:** PowerShell infostealer
- **Notable:** Generated with LLM assistance — represents novel AI-assisted malware development by a nation-state actor
- **Capabilities:** Browser credential theft, cookie theft, stored payment data, audio/video recording via WebRTC, authentication token theft
- **Platform:** Windows (PowerShell)

### ENGINELIGHT
- **Type:** Go-based malware
- **Capabilities:** File transfer, encrypted messaging application targeting, post-compromise access

### HEADRUSH
- **Type:** Malicious Excel plugin (.xlam) / HTA downloader
- **Delivery:** Victims open a weaponized Excel plugin that downloads and executes an HTA payload
- **Platform:** Windows

### VIDAR
- **Type:** Malware-as-a-Service (MaaS) infostealer
- **Capabilities:** Browser credential/cookie/payment theft, keylogging
- **Availability:** Purchased by APT29 sub-clusters via MaaS marketplace

### ATOMIC (AtomicStealer)
- **Type:** macOS MaaS infostealer
- **Capabilities:** macOS browser credential theft, keychain access, cryptocurrency wallet theft
- **Notable:** APT29 cluster purchasing macOS-targeting MaaS to broaden platform coverage

---

## 4. Threat Actor / Campaign Attribution

### Overview
Google GTIG tracks three distinct APT29 sub-clusters (Ice Relic) conducting coordinated espionage against individuals of strategic interest to Russia:

| Cluster | Also Known As | Primary Targeting |
|---------|--------------|-------------------|
| UNC6293 | — | Diplomats, academics, think tanks in EU/NATO countries |
| UNC7005 | STORM-2945 | Defense personnel, military attaches |
| UNC5976 | — | Diplomatic community, NGO workers |

### Campaign Techniques
- **App-Specific Password (ASP) phishing:** Targets Gmail/Google accounts where 2FA is enabled; tricks victims into generating an ASP that bypasses MFA entirely
- **OAuth device code phishing:** Sends device code flow URLs via email/messaging; victim enters code at `microsoft.com/devicelogin` granting attacker persistent access
- **WhatsApp device linking:** Tricks victims into scanning a QR code that links attacker-controlled device to victim's WhatsApp account
- **Captive portal DNS poisoning:** In hospitality/conference settings, poisons DNS to redirect users to actor-controlled credential harvesting pages when joining WiFi
- **GLOBSEC/diplomatic conference impersonation:** Uses event-themed lures targeting attendees of real EU/NATO-aligned security conferences

### Targets
- Diplomats and embassy staff in European capitals
- Think tank and academic researchers focused on Russia/Eastern Europe
- Defense attachés and military personnel
- Journalists covering Russia and Ukraine

---

## 5. Splunk Detection Searches

### 5a. Microsoft OAuth Device Code Phishing — Authentication Detection

Detects successful OAuth device code flow authentications that may indicate phishing compromise. Device code flow is rarely used legitimately in enterprise environments.

```spl
index=o365 OR index=azure_ad sourcetype="azure:aad:signin"
AuthenticationProtocol="deviceCode" ResultType=0
| stats count min(_time) as firstTime max(_time) as lastTime
    values(UserPrincipalName) as users
    values(IPAddress) as src_ips
    values(AppDisplayName) as apps
    values(DeviceDetail.operatingSystem) as os
    by ConditionalAccessStatus ResourceDisplayName
| where count > 0
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime users src_ips apps os ConditionalAccessStatus ResourceDisplayName count
```

### 5b. CHERRYPIE — LLM-Generated PowerShell Infostealer Behavioral Detection

Detects PowerShell processes accessing browser credential stores or certificate stores — indicative of CHERRYPIE/ChocoShell and similar PowerShell infostealers.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe"
    (Processes.process="*AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data*"
    OR Processes.process="*AppData\\Roaming\\Mozilla\\Firefox\\Profiles*"
    OR Processes.process="*Cookies*" OR Processes.process="*Login Data*"
    OR Processes.process="*Web Data*" OR Processes.process="*credential*")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process process_id
```

### 5c. APT29 — Known Phishing Domain Lookup (Network)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Resolution.DNS
    where DNS.query IN (
        "dosportal.app","foreignrelations.us","chamber-ua.org",
        "wa-connect.eu","wa-connect.net","wa-invite.com","wa-device.com","wa-meeting.com",
        "shopinvite.org","my-invite.org","globsec.net","statistic-ms.live",
        "owa-ms365.com","m365-owa.com","ms365-device.com","ms365-live.com",
        "finishoperations.com","finishoperations.org","foc-share.com","share-foc.com",
        "internal-share.com","foc-share.org","drive.google.verify-drive.com","mail.kiis.co.uk",
        "fewfwfwfwfwf.info","miov2iaiaoubqosiqoiajwowiwjso.online","mioisiskwowiwjowuwjwolab.club"
    )
    by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src query answer count
```

### 5d. HEADRUSH — Excel Plugin HTA Downloader Detection

Detects Excel spawning HTA-related processes, indicating the HEADRUSH Excel plugin technique.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name="excel.exe"
    (Processes.process_name="mshta.exe" OR Processes.process_name="wscript.exe"
    OR Processes.process_name="cscript.exe" OR Processes.process_name="cmd.exe"
    OR Processes.process_name="powershell.exe")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process process_id
```

---

## 6. Executive Summary

Google Threat Intelligence Group published research on August 20, 2026 identifying three distinct APT29 sub-clusters (UNC6293, UNC7005/STORM-2945, UNC5976) conducting coordinated credential theft and espionage operations against individuals of strategic interest to Russia: diplomats, academic researchers, defense personnel, and think tank employees primarily in EU and NATO-aligned countries.

The clusters employ a sophisticated, multi-vector approach to credential compromise: App-Specific Password (ASP) phishing to bypass MFA on Google accounts; OAuth device code phishing for persistent Microsoft 365 access; WhatsApp device-linking attacks to monitor encrypted communications; and captive portal DNS poisoning at hotels and conference venues. Lure themes impersonate real diplomatic events including GLOBSEC, Finnish Operations Center communications, and Ukraine-related organizations.

**Key development:** APT29 is now deploying **CHERRYPIE** (also tracked as ChocoShell), a PowerShell infostealer with artifacts generated using large language models — representing a documented case of a Tier 1 nation-state actor using AI to accelerate malware development. The actor has also begun purchasing macOS-targeting MaaS (ATOMIC/AtomicStealer) alongside Windows infostealers (VIDAR), broadening platform coverage against high-value targets.

**Defensive priorities:** Disable OAuth device code flow in Conditional Access policies where not operationally required; enforce phishing-resistant MFA (FIDO2/hardware keys) for high-risk users; block identified IOC domains at DNS and proxy; monitor PowerShell processes accessing browser credential stores.
