---
scraped_at: "2026-11-27T00:00:00Z"
source_url: "https://www.bitdefender.com/en-us/blog/labs/sys010-reloaded-malvertising-campaign-targeting-meta-business-accounts"
report_type: threat-intel
severity: high
title: "SYS010: Malvertising Campaign Abuses Chrome/Edge/Firefox Enterprise Policy to Force-Install Credential-Stealing Extensions"
---

## 1. IOCs

### Domains (Defanged)
| Domain | Role |
|--------|------|
| lelebag[.]com | Chrome extension C2 (command server) |
| esora[.]top | Chrome extension C2 (command server) |

### File Hashes
| File | Hash Type | Hash | Description |
|------|-----------|------|-------------|
| docs-helper-1.0.25.crx | SHA-256 | 92686bac718b5853bc26abeafe3bd0d5a542060c94a8715e76dc1a62834f6691 | Malicious Chrome extension package (Docs Helper 1.0.25) |

### Browser Extension / Add-On Identifiers
| Browser | Extension Name | ID |
|---------|---------------|-----|
| Chrome | Docs Helper 1.0.25 | ikpkhjechdnnfjedponpfmigmgcjgabi |
| Chrome | (secondary identifier) | pmhmgkohdaacioooendcjcibkefifjja |
| Firefox | Document Hub 2.1.20 | {8819e3bb-599d-4c03-a958-402237346b01} |

### PHP Loader Components (Filenames)
| Filename | Role |
|----------|------|
| eclient.php | Browser policy manipulation — enrolls Chrome in attacker Google Admin console |
| bootstrap.php | Malware bootstrapper |
| base.php | Base loader module |
| updater.php | Extension/payload update handler |
| u.php | General-purpose loader module |
| esync.php | Extension synchronization handler |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Tactic ID | Technique | Technique ID | Usage |
|--------|-----------|-----------|--------------|-------|
| Initial Access | TA0001 | Phishing via Service | T1566.003 | Fake animated-wallpaper apps distributed via Meta (Facebook/Instagram) ads |
| Execution | TA0002 | User Execution: Malicious File | T1204.002 | Victim runs trojanized wallpaper app installer |
| Persistence | TA0003 | Browser Extensions | T1176 | Malicious Chrome/Firefox extension force-installed via browser management policy manipulation |
| Defense Evasion | TA0005 | Modify Registry | T1112 | Windows registry keys written to enforce Chrome Enterprise policy (`SOFTWARE\Policies\Google\Chrome`) |
| Defense Evasion | TA0005 | Impair Defenses: Disable or Modify Tools | T1562.001 | Firefox policies disable Developer Tools and abuse reporting |
| Credential Access | TA0006 | Steal Web Session Cookie | T1539 | Extension harvests session cookies for all sites on demand |
| Collection | TA0009 | Email Collection: Remote Email Collection | T1114.002 | Extension reads/deletes Gmail and Outlook messages (up to 50 per request including Spam) |
| Collection | TA0009 | Data from Local System | T1005 | Meta Business account data exfiltrated |
| Command and Control | TA0011 | Application Layer Protocol: Web Protocols | T1071.001 | Extension polls C2 every 5 minutes via HTTPS; C2 endpoints delivered via Telegram and Cloudflare R2 |
| Command and Control | TA0011 | Dead Drop Resolver | T1102.001 | C2 endpoints dynamically retrieved from Telegram channel and Cloudflare R2 storage |

---

## 3. Malware & Tools

| Name | Type | Description |
|------|------|-------------|
| SYS010 | Infostealer / credential thief | Rebuilt version of SYS01 infostealer; targets Meta Business accounts, Gmail, Outlook; includes browser policy manipulation component |
| Docs Helper 1.0.25 (Chrome) | Malicious browser extension | Reads/deletes Gmail and Outlook messages; harvests session cookies; polls C2 every 5 minutes |
| Document Hub 2.1.20 (Firefox) | Malicious browser add-on | Firefox counterpart; signed by Mozilla add-on signing service (October 16, 2026); force-installed via ExtensionSettings policy |
| eclient.php | PHP loader | Modifies browser management policies: Chrome enrollment in attacker Google Admin console, Edge MDM enrollment, Firefox ExtensionSettings injection |

---

## 4. Threat Actor / Campaign Attribution

| Field | Detail |
|-------|--------|
| Attribution | Unknown financially motivated threat actor; campaign consistent with SYS01 operator behavior |
| Campaign Start | October 16, 2026 (first malicious Meta ad identified) |
| Campaign Status | Active as of November 26, 2026 (hundreds of ads created) |
| Primary Source | Bitdefender Labs — "SYS010 Reloaded: Malvertising Campaign Targeting Meta Business Accounts" |
| Delivery Vector | Meta (Facebook/Instagram) paid ads distributing fake free animated wallpaper applications |
| Targets | Meta Business account holders, Gmail and Outlook users, Windows users |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist*"
     OR Registry.registry_path="*\\SOFTWARE\\Policies\\Google\\Chrome\\CloudManagementEnrollmentToken*"
     OR Registry.registry_path="*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\Extensions\\Install*"
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime dest user registry_path registry_value_data risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="lelebag.com" OR DNS.query="esora.top"
  by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95, threat="SYS010 C2"
| table firstTime lastTime src query threat risk_score
```

```spl
`sysmon`
  source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=13
  TargetObject IN ("*\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist*",
                   "*\\SOFTWARE\\Policies\\Google\\Chrome\\CloudManagementEnrollmentToken*",
                   "*\\SOFTWARE\\Policies\\Mozilla\\Firefox\\Extensions\\Install*")
| eval process=Image
| stats count min(_time) as firstTime max(_time) as lastTime
        values(TargetObject) as registry_keys_modified
        values(Details) as registry_values
  by ComputerName User process
| where process!="C:\\Windows\\regedit.exe" AND process!="C:\\Windows\\system32\\msiexec.exe"
| eval risk_score=85
| table firstTime lastTime ComputerName User process registry_keys_modified registry_values risk_score
```

---

## 6. Executive Summary

Bitdefender Labs disclosed the SYS010 campaign on November 26, 2026. SYS010 is an evolution of the SYS01 infostealer that weaponizes legitimate enterprise browser management features to force-install credential-stealing extensions without user consent or Chrome Web Store vetting.

**Attack Chain:** Victims encounter fake animated-wallpaper app advertisements on Meta platforms (Facebook/Instagram). Running the app triggers a PHP-based loader (eclient.php) that modifies browser management policies: in Chrome, the browser is enrolled in an attacker-controlled Google Workspace Admin console and the malicious "Docs Helper" extension (ID: ikpkhjechdnnfjedponpfmigmgcjgabi) is force-installed; in Firefox, the ExtensionSettings policy injects the "Document Hub" add-on and disables Developer Tools; in Edge, an MDM enrollment is performed.

**Capabilities:** The malicious extension polls its C2 server every five minutes. On command, it reads and permanently deletes up to 50 Gmail and Outlook messages per request (including from Spam), harvests session cookies across all websites (enabling MFA bypass), and exfiltrates Meta Business account data. C2 endpoints are updated dynamically via Telegram and Cloudflare R2, making static domain blocking insufficient.

**Risk:** SYS010 is notable because it abuses legitimate OS and browser management channels — the same mechanisms used by enterprise IT departments — meaning extensions installed this way bypass Google's Chrome Web Store review, do not trigger standard browser security alerts, and persist across browser restarts and updates. Organizations should monitor for unexpected browser policy registry writes and block the IOC domains/hashes at endpoint and DNS controls.
