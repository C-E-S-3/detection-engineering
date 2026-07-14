---
scraped_at: 2026-07-14T00:00:00Z
source_url: https://www.jamf.com/blog/crashstealer-macos-infostealer/
report_type: threat-intel
severity: high
title: "CrashStealer: Native C++ macOS Infostealer Impersonating Apple CrashReporter"
---

## 1. IOCs

### Domains

| Domain | Description |
|--------|-------------|
| `werkbit[.]io` | Delivery site — "Werkbit Setup" disk image download; domain registered late June 2026 |
| `endpoint-api-v1[.]com` | C2 exfiltration endpoint; receives AES-GCM encrypted POST data via libcurl |

### Code Signing / Identity

| Identifier | Description |
|-----------|-------------|
| `Emil Grigorov (WWB7JA7AQV)` | Apple Developer ID used to sign and notarize the dropper |
| `dev.golove.velto` | Dropper application bundle ID |
| `mgothiclove/pkeys` | Public GitHub repository fetched by dropper for RSA public key material |

### File Characteristics

- Delivery disk image: `Werkbit Setup.dmg` — PIN-gated installer (PIN required to mount/run)
- Persistence mechanism: LaunchAgent plist installed under `~/Library/LaunchAgents/`
- Masquerade path: copies itself into a directory named to resemble Apple's CrashReporter framework
- Self-re-signs after copy using `codesign`

## 2. TTPs

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Credential Access | T1555.001 | Credentials from Password Stores: Keychain | Primary objective: enumerates and dumps macOS Keychain entries including passwords, certificates, and private keys |
| Collection | T1005 | Data from Local System | Collects browser credentials, saved passwords, and system data beyond Keychain |
| Persistence | T1547.011 | Boot or Logon Autostart Execution: Plist Modification | LaunchAgent plist installed in `~/Library/LaunchAgents/` for user-context persistence |
| Defense Evasion | T1553.002 | Subvert Trust Controls: Code Signing | Dropper is notarized by Apple with a valid Developer ID (Emil Grigorov / WWB7JA7AQV); passes Gatekeeper |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Copies itself into a path mimicking Apple's CrashReporter framework; calls `codesign` to re-sign after move |
| Command and Control | T1041 | Exfiltration Over C2 Channel | AES-GCM encrypted data exfiltrated via HTTP POST using libcurl to `endpoint-api-v1[.]com` |
| Resource Development | T1588.003 | Obtain Capabilities: Code Signing Certificates | Attacker obtained a valid Apple Developer certificate (possibly fraudulently) to notarize the dropper |

## 3. Malware & Tools

**CrashStealer** is a native C++ macOS infostealer first documented by Jamf Threat Labs in July 2026. It is notable for several characteristics that distinguish it from typical macOS commodity stealers written in Python or shell:

**Delivery and initial access:**
- Distributed as a disk image (`Werkbit Setup.dmg`) hosted on `werkbit[.]io`; the disk image is PIN-gated — a PIN is required before the payload will execute, indicating targeted delivery (victims likely received the PIN via social engineering, email, or chat)
- The dropper is notarized with a real Apple Developer ID (`Emil Grigorov / WWB7JA7AQV`, team ID `WWB7JA7AQV`), so it clears Gatekeeper without a security warning

**Execution and persistence:**
- Bundle ID `dev.golove.velto`; the dropper fetches RSA public key material from the attacker-controlled GitHub repository `mgothiclove/pkeys` at runtime
- After first execution, the malware copies itself to a directory path constructed to resemble Apple's CrashReporter framework (e.g., `/Library/Application Support/CrashReporter/` or a user-equivalent path), then re-signs the copy using `/usr/bin/codesign`
- A LaunchAgent plist is written to `~/Library/LaunchAgents/` pointing to the re-signed copy, achieving user-level persistence that survives reboots

**Credential theft:**
- Primary target is the macOS Keychain — the malware calls Security framework APIs (`SecItemCopyMatching`, `SecKeychainItemCopyAttributesAndData`) to enumerate and extract Keychain items including internet passwords, certificates, and private keys
- Additionally collects browser-stored credentials and local application data

**Exfiltration:**
- Stolen data is encrypted with AES-GCM before transmission
- Upload performed via libcurl HTTP POST to `endpoint-api-v1[.]com`
- The RSA public key fetched from GitHub is used for key encapsulation of the AES session key, ensuring only the attacker can decrypt the stolen data

The combination of native C++ (harder to reverse than scripted stealers), Apple notarization, PIN-gated delivery, and CrashReporter masquerade makes CrashStealer significantly harder to detect with traditional macOS endpoint controls.

## 4. Threat Actor / Campaign Attribution

The threat actor behind CrashStealer is unknown. No group attribution has been made by Jamf or any secondary source as of July 2026. Key observations:

- The PIN-gated delivery mechanism is characteristic of targeted campaigns rather than mass-distribution malware, suggesting a specific victim set
- Victimology is not publicly reported; no industries or geographies identified
- Use of a validly notarized Developer ID (Emil Grigorov / WWB7JA7AQV) suggests either a fraudulently obtained Apple certificate or a developer account compromised by the attacker
- The GitHub-hosted key retrieval (`mgothiclove/pkeys`) is a low-operational-security choice that may allow attribution if the account is linked to other activity

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("werkbit.io","endpoint-api-v1.com")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

```spl
index=* (dest="werkbit.io" OR dest="endpoint-api-v1.com" OR dest="werkbit[.]io" OR dest="endpoint-api-v1[.]com")
| stats count min(_time) as firstTime max(_time) as lastTime by src dest dest_port
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="codesign"
  AND (Processes.process="*CrashReporter*" OR Processes.process="*LaunchAgents*")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_path="*/Library/LaunchAgents/*"
  AND (Filesystem.process_name!="launchctl" AND Filesystem.process_name!="installer"
       AND Filesystem.process_name!="softwareupdate" AND Filesystem.process_name!="mdmclient")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path,"CrashReporter"), 90,
    1=1, 50
  )
| where risk_score >= 50
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

## 6. Executive Summary

Jamf Threat Labs disclosed CrashStealer on July 13, 2026 — a native C++ macOS infostealer distinguished from commodity stealers by its Apple Developer notarization (Emil Grigorov / WWB7JA7AQV), PIN-gated delivery (indicating targeted distribution), and persistent masquerade as Apple's CrashReporter framework. The malware targets the macOS Keychain (Security framework API calls) along with browser credentials and application data, encrypts stolen content with AES-GCM (key encapsulated with an RSA public key fetched from GitHub at runtime), and exfiltrates via libcurl HTTP POST to `endpoint-api-v1[.]com`. Persistence is via a LaunchAgent plist; the malware re-signs itself after copying to the CrashReporter-mimicking path. The delivery domain is `werkbit[.]io` (registered late June 2026). No threat actor attribution has been made. The notarized certificate and PIN-gated delivery model suggest either a targeted espionage campaign or a novel sophisticated criminal operation. Organizations with macOS endpoints should immediately alert on any DNS resolution or network connections to `werkbit[.]io` or `endpoint-api-v1[.]com`, and monitor for LaunchAgent creation by non-system processes in CrashReporter-adjacent paths.

## References

- [Jamf Threat Labs — CrashStealer macOS Infostealer (2026-07-13)](https://www.jamf.com/blog/crashstealer-macos-infostealer/)
- [BleepingComputer — CrashStealer coverage (2026-07-13)](https://www.bleepingcomputer.com/news/security/new-crashstealer-macos-malware-steals-passwords-using-fake-crashreporter/)
- [The Hacker News — CrashStealer (2026-07-13)](https://thehackernews.com/2026/07/crashstealer-macos-malware-impersonates.html)
- [MITRE ATT&CK T1555.001 — Credentials from Password Stores: Keychain](https://attack.mitre.org/techniques/T1555/001/)
- [MITRE ATT&CK T1547.011 — Boot or Logon Autostart Execution: Plist Modification](https://attack.mitre.org/techniques/T1547/011/)
- [MITRE ATT&CK T1036.005 — Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
