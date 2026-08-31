---
scraped_at: 2026-08-31T00:00:00Z
source_url: https://thehackernews.com/2026/08/wordlistloader-delivers-amatera-via.html
report_type: threat-intel
severity: high
title: "WordlistLoader + SynkLoader Deliver Amatera 4.3.3-alpha1 Stealer via ClearFake/ClickFix"
---

# WordlistLoader + SynkLoader Deliver Amatera 4.3.3-alpha1 Stealer via ClearFake/ClickFix

**Date Reported:** August 24, 2026  
**Sources:** Gen Threat Labs; The Hacker News  
**Severity:** High  

## 1. IOCs

No specific C2 IP addresses or domains were publicly confirmed at time of report. Infrastructure is distributed via compromised websites and Cloudflare-fronted delivery, making static IOCs ephemeral.

### File Artifacts
| Type | Description |
|------|-------------|
| MSI installer | SynkLoader delivery via WebDAV-hosted DLL dropped by fake CAPTCHA ClickFix |
| Python loader | SynkLoader runtime component (Python-based, beacons every 90–120 seconds) |
| Shellcode-encoded binary | WordlistLoader payload — each byte represented as plain English word |
| Amatera 4.3.3-alpha1 | Infostealer final payload |

## 2. TTPs

| Tactic | Technique | Details |
|--------|-----------|---------|
| Initial Access | T1189 — Drive-by Compromise | Compromised websites running fake CAPTCHA and ClearFake JS injection |
| Initial Access | T1204.001 — User Execution: Malicious Link | ClickFix pastejacking: victim pastes a PowerShell/mshta command from clipboard |
| Execution | T1059.001 — PowerShell | ClickFix-injected clipboard command spawns PS or mshta to fetch stage 1 |
| Execution | T1059.006 — Python | SynkLoader runs as Python-based stage 2; beacons to C2 every 90–120s |
| Defense Evasion | T1027 — Obfuscated Files or Information | WordlistLoader encodes each shellcode byte as a plain English word, bypassing binary pattern detection |
| Defense Evasion | T1218.007 — Msiexec | SynkLoader delivered as MSI installer |
| Execution (Delivery) | T1105 — Ingress Tool Transfer | Payloads hosted on WebDAV shares; DLL side-loading |
| Credential Access | T1555.003 — Credentials from Web Browsers | Amatera 4.3.3-alpha1 steals credentials from 20+ browsers |
| Collection | T1560 — Archive Collected Data | Amatera packages wallet files, browser credentials, message history for exfil |
| Collection | T1005 — Data from Local System | Crypto wallet files, session cookies, autofill data |

**MITRE Tactics:** TA0001, TA0002, TA0005, TA0006, TA0009  
**Kill Chain Phases:** Delivery, Exploitation, Actions on Objectives

## 3. Malware & Tools

### WordlistLoader
A novel loader that encodes its shellcode payload by mapping each byte to a plain English word from a dictionary. This encoding scheme evades binary signature detections and most ML-based classifiers trained on numeric shellcode patterns. Delivers Amatera as final payload. Observed delivery via ClearFake fake browser update overlays.

### SynkLoader
MSI-packaged, Python-based loader that acts as an access broker. Key characteristics:
- Beacons to C2 every 90–120 seconds for tasking
- Sells victim access to ransomware affiliate groups
- Capable of deploying any second-stage payload on instruction

### Amatera 4.3.3-alpha1 (Infostealer)
An actively developed infostealer, now at version 4.3.3-alpha1, with capabilities including:
- **Browser credential theft:** 20+ browsers (Chromium-based, Firefox family, niche browsers)
- **Cryptocurrency wallet theft:** Targets browser extension wallets and standalone wallet software
- **Message history exfiltration:** Messaging apps on the victim system
- **Session cookie theft:** Enables session hijacking for SaaS applications

## 4. Threat Actor

Attribution is not publicly confirmed. The combination of ClearFake infrastructure, SynkLoader's access-broker model, and Amatera's active development suggests a financially motivated threat actor operating a Malware-as-a-Service (MaaS) model. SynkLoader specifically sells access to ransomware groups, suggesting the initial access phase is run as a separate criminal enterprise.

| Attribute | Value |
|-----------|-------|
| Motivation | Financial — credential theft, crypto theft, ransomware access brokering |
| Targeting | Broad / opportunistic (compromised websites) |
| MaaS model | SynkLoader sells access; Amatera may be purchased separately |

## 5. Splunk Detection Searches

### Detect ClickFix pastejacking via clipboard-spawned suspicious processes
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "iexplore.exe")
    AND Processes.process_name IN ("powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe", "cmd.exe")
    AND (Processes.process="*-enc*" OR Processes.process="*WebDAV*" OR Processes.process="*msiexec*" OR Processes.process="*IEX*" OR Processes.process="*DownloadString*")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect Python loader beaconing (SynkLoader pattern)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("python.exe", "python3", "pythonw.exe")
    AND Processes.parent_process_name IN ("msiexec.exe", "cmd.exe", "powershell.exe", "wscript.exe")
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect MSI installation from WebDAV share (SynkLoader delivery)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name="msiexec.exe"
    AND (Processes.process="*\\\\*" OR Processes.process="*http*" OR Processes.process="*dav*")
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Detect browser credential file access by non-browser processes (Amatera)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path IN (
    "*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Login Data",
    "*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*\\Login Data",
    "*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json",
    "*\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\*\\Login Data")
    AND Filesystem.process_name NOT IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "SearchApp.exe")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user process_name file_path risk_score
```

**Risk Scores:** 70–85 (High); 80 for ClickFix spawn chain, 85 for credential file access by non-browser process

## 6. Executive Summary

Gen Threat Labs (published via The Hacker News on August 24, 2026) disclosed a multi-stage infostealer campaign using two novel loaders, **WordlistLoader** and **SynkLoader**, delivering **Amatera 4.3.3-alpha1**.

The campaign's most technically notable element is WordlistLoader's shellcode encoding scheme: each byte of the malicious payload is represented as a plain English dictionary word. This entirely bypasses binary-pattern based detection and is novel enough that most deployed signatures will not match it.

Delivery is via the now-common **ClearFake / ClickFix** pastejacking flow — compromised websites inject JavaScript that displays a fake CAPTCHA or browser update overlay, instructing victims to paste a PowerShell or mshta command from their clipboard into a Run dialog. The second-stage **SynkLoader** operates as an access broker, selling persistent access to ransomware affiliates while also deploying **Amatera 4.3.3-alpha1** to steal browser credentials, cryptocurrency wallets, and session cookies from 20+ browsers.

**Recommended actions:**
1. Alert on browser processes spawning PowerShell, mshta, or wscript — a strong indicator of ClickFix execution.
2. Alert on msiexec loading from UNC (WebDAV) paths.
3. Alert on non-browser processes accessing browser credential files (Login Data, logins.json).
4. Consider blocking WebDAV from untrusted sources at the proxy layer.

## References

- https://thehackernews.com/2026/08/wordlistloader-delivers-amatera-via.html
- https://www.gendigital.com/blog/insights/research/wordlistloader-synkloader-amatera/
- https://attack.mitre.org/techniques/T1189/
- https://attack.mitre.org/techniques/T1204/001/
- https://attack.mitre.org/techniques/T1027/
