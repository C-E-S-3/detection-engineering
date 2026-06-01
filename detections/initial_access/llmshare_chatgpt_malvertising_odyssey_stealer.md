# LLMShare ChatGPT Malvertising — Odyssey Stealer and Credential-Stealing Loader Delivery

## Description

Detects activity associated with the "LLMShare" malvertising campaign (disclosed May 2026) where threat actors abuse ChatGPT's share-link feature to host fake OpenAI outage pages on the legitimate `chatgpt.com` domain. Victims are directed via sponsored Google Ads and download malware from `openew[.]app`, receiving either a Windows credential-stealing loader or macOS Odyssey Stealer (an AMOS fork targeting browser credentials, cookies, and cryptocurrency wallets).

Key signals: DNS resolution of `openew.app`, browser processes spawning installer subprocesses with OpenAI-themed names, and LaunchDaemon/LaunchAgent creation by non-system processes on macOS.

**False positive sources:** Legitimate software with names matching "openai" or "chatgpt" (e.g., official ChatGPT desktop app installed from openai.com); adjust the domain blocklist query to exclude confirmed-safe download paths. The macOS LaunchDaemon detection may fire on legitimate app installations.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Drive-by Compromise |
| Technique ID | T1189 |
| Secondary Technique | User Execution: Malicious File |
| Secondary Technique ID | T1204.002 |
| Secondary Technique | Credentials from Password Stores: Web Browsers |
| Secondary Technique ID | T1555.003 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |

## Splunk Detection Query

```spl
| comment "Query 1: DNS query for openew.app — direct IOC for LLMShare delivery infrastructure"
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
| comment "Query 2: Browser spawning fake ChatGPT installer — LLMShare execution chain"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
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

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query to `openew.app` | 90 | No legitimate use; confirmed malware distribution domain for LLMShare campaign |
| Browser spawning installer with openai/chatgpt/openew in cmdline | 80 | Fake installer execution from a browser download; high confidence for this campaign |
| macOS LaunchDaemon created by non-system process | 75 | Odyssey Stealer persistence mechanism; broad coverage of macOS infostealer behavior |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (LLMShare operator) | [BleepingComputer — LLMShare campaign (2026-05-29)](https://www.bleepingcomputer.com/news/security/chatgpt-share-links-abused-to-host-fake-outage-pages-to-deliver-malware/) |
| Odyssey Stealer operators (MaaS affiliates, alias "Rodrigo4") | [Push Security — LLMShare research](https://pushsecurity.com/blog/llmshare-malvertising-campaign), [Malwarebytes (2026-05)](https://www.malwarebytes.com/blog/threat-intel/2026/05/fake-chatgpt-download-site-infects-windows-and-mac-users-with-malware) |

## References

- [BleepingComputer — ChatGPT share links abused to host fake outage pages (2026-05-29)](https://www.bleepingcomputer.com/news/security/chatgpt-share-links-abused-to-host-fake-outage-pages-to-deliver-malware/)
- [Push Security — LLMShare: using shared chatbot pages to distribute malware](https://pushsecurity.com/blog/llmshare-malvertising-campaign)
- [MITRE ATT&CK T1189 — Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK T1204.002 — User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1555.003 — Credentials from Password Stores: Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
