---
scraped_at: 2026-06-01T00:00:00Z
source_url: https://www.bleepingcomputer.com/news/security/chatgpt-share-links-abused-to-host-fake-outage-pages-to-deliver-malware/
report_type: threat-intel
severity: high
title: "LLMShare: Threat Actors Abuse ChatGPT Share Links and Google Ads to Deliver Credential-Stealing Malware (Odyssey Stealer)"
---

## 1. IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| Domain | `openew[.]app` | Malicious site impersonating OpenAI ChatGPT desktop download portal; delivers Windows credential-stealing loader and macOS Odyssey Stealer |

No file hashes for the Windows or macOS payloads have been publicly confirmed in available sources at the time of this report.

**Behavioral IOCs:**
- DNS queries to `openew.app` from end-user workstations
- Download of `.msi`, `.exe`, or `.dmg` files from `openew.app`
- Browser process spawning an installer subprocess shortly after a download from `openew.app`

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1189 | Drive-by Compromise | Malicious Google Ads targeting users searching for "ChatGPT download" redirect to fake outage page hosted on the legitimate chatgpt.com domain via the ChatGPT share-link feature |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Malvertising link leads to a chatgpt.com shared page rendered with custom HTML/CSS that simulates an OpenAI outage notice and presents a download link |
| Execution | T1204.002 | User Execution: Malicious File | Users are socially engineered into downloading and running the fake installer (Windows EXE/MSI) or disk image (macOS DMG) |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Payload site `openew.app` impersonates `openai.com`; `.app` TLD (Google-operated, HTTPS-required) displays a padlock icon, reducing user suspicion |
| Defense Evasion | T1564 | Hide Artifacts | Site employs server-side cloaking: security scanners and URL checkers receive a benign AR/VR company page; only real user-agents receive the malicious download |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Windows payload steals browser-stored credentials; macOS Odyssey Stealer harvests browser passwords, cookies, and Telegram session data |
| Credential Access | T1539 | Steal Web Session Cookie | Odyssey Stealer exfiltrates session cookies from browsers |
| Collection | T1083 | File and Directory Discovery | Odyssey Stealer searches for and steals cryptocurrency wallet files and seeds |

**Attack Chain:**
1. Attacker creates a ChatGPT shared conversation that renders a custom HTML/CSS fake outage notice (using the ChatGPT share/remix-with-ChatGPT feature on chatgpt.com).
2. A sponsored Google Ad targeting keywords like "ChatGPT desktop app" or "ChatGPT download" redirects users to the attacker-controlled `chatgpt.com/share/<id>` URL.
3. The victim sees a fake outage page on the legitimate chatgpt.com domain, presenting download buttons for macOS and Windows.
4. Clicking a download button redirects the user to `openew.app`, which impersonates the OpenAI desktop application download page.
5. The site delivers platform-appropriate malware: a credential-stealing loader on Windows, or Odyssey Stealer (AMOS fork) on macOS.
6. Stolen credentials, cookies, and cryptocurrency wallet data are exfiltrated to attacker-controlled infrastructure.

## 3. Malware & Tools

| Malware | Platform | Description |
|---------|----------|-------------|
| Credential-stealing loader (unnamed) | Windows | Fake installer that establishes a back channel to an attacker-controlled server and steals credentials, browser data, and validates the host is a real machine (VM detection) |
| Odyssey Stealer | macOS | AMOS (Atomic macOS Stealer) fork sold as Malware-as-a-Service by threat actor alias "Rodrigo" (Rodrigo4); steals browser passwords, cookies, Telegram session data, cryptocurrency wallets and extensions, Epic Games credentials; delivered as a DMG; communicates via C2 panel accessible to attackers |

**Odyssey Stealer delivery method:**
- Delivered as a macOS DMG masquerading as the ChatGPT desktop application
- Uses obfuscated AppleScript for persistence via LaunchDaemon
- Targets cryptocurrency extensions in Chrome/Firefox/Brave
- MaaS offering — multiple threat actors may operate this payload independently

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Campaign Name | LLMShare (named by Push Security) |
| Motivation | Financial — credential theft and cryptocurrency theft |
| Attribution | Unknown; MaaS model suggests multiple affiliates using Odyssey Stealer |
| Novel Technique | Abuse of ChatGPT share-link feature (chatgpt.com domain) to host malicious HTML renders; extends known malvertising patterns into LLM platforms |

The "LLMShare" technique generalizes across any LLM platform that supports public share links with custom rendering (ChatGPT, Claude, Gemini, etc.). Defenders should expect this technique to be replicated across platforms.

## 5. Splunk Detection Searches

```spl
| comment "Search 1: DNS queries to openew.app — direct IOC hit for LLMShare campaign"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query="openew.app" OR DNS.query="*.openew.app"
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

```spl
| comment "Search 2: Browser spawning installer from unusual download — fake ChatGPT installer execution pattern"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("chrome.exe", "msedge.exe", "firefox.exe", "safari", "brave.exe")
    AND Processes.process_name IN ("msiexec.exe", "setup.exe", "install.exe")
    AND (Processes.process="*chatgpt*" OR Processes.process="*openai*" OR Processes.process="*openew*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "Search 3: macOS LaunchDaemon created by non-system process — Odyssey Stealer persistence"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN ("/Library/LaunchDaemons/*", "/Library/LaunchAgents/*", "~/Library/LaunchAgents/*")
    AND Filesystem.action=created
    AND NOT Filesystem.process_name IN ("com.apple.installer", "system_installer", "launchd")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

**Tuning notes:**
- Search 1 is highest confidence: `openew.app` has no legitimate use; any internal DNS resolution to this domain should be investigated immediately.
- Search 2 may generate false positives for legitimate software installers downloaded via browser; filter known-good hashes via a lookup table.
- Search 3 targets macOS LaunchDaemon/LaunchAgent persistence, which is a common technique for macOS infostealers including Odyssey Stealer and AMOS. Tune by excluding known installer paths from your software management tooling.

## 6. Executive Summary

Push Security disclosed the "LLMShare" technique on May 29, 2026, describing an active campaign where threat actors abuse ChatGPT's share-link feature to host convincing fake OpenAI outage pages on the legitimate `chatgpt.com` domain. The attack is initiated via sponsored Google Ads targeting search terms like "ChatGPT download," funneling users to a ChatGPT shared conversation that renders custom HTML simulating a service outage.

When users click the download button, they are taken to `openew[.]app` — a convincing impersonation of the OpenAI ChatGPT desktop download portal. The site employs cloaking to show benign content to security scanners. Windows users receive a credential-stealing malware loader; macOS users receive Odyssey Stealer, a fork of Atomic macOS Stealer (AMOS) sold as MaaS.

The LLMShare technique is notable because it leverages a legitimately-hosted page (chatgpt.com, with valid HTTPS), making it difficult for security products to detect using domain reputation alone. The technique is platform-agnostic and expected to be replicated across other LLM platforms supporting public share links.

**Immediate actions:**
1. Block `openew.app` in DNS filters and web proxies.
2. Monitor for DNS queries or web connections to `openew.app` across the environment.
3. Hunt for browser-spawned installer executions with "openai," "chatgpt," or "openew" in the process command line.
4. Educate users: ChatGPT, Claude, and similar AI tools do not require separate desktop application installers downloaded from third-party domains.

## References

- [BleepingComputer — ChatGPT share links abused to host fake outage pages (2026-05-29)](https://www.bleepingcomputer.com/news/security/chatgpt-share-links-abused-to-host-fake-outage-pages-to-deliver-malware/)
- [Push Security — LLMShare: using shared chatbot pages to distribute malware](https://pushsecurity.com/blog/llmshare-malvertising-campaign)
- [Malwarebytes — Fake ChatGPT download site infects Windows and Mac users (2026-05)](https://www.malwarebytes.com/blog/threat-intel/2026/05/fake-chatgpt-download-site-infects-windows-and-mac-users-with-malware)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1555.003 — Credentials from Password Stores: Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
