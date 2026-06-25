---
scraped_at: 2026-06-25T00:00:00Z
source_url: https://www.zscaler.com/blogs/security-research/payouts-king-ransomware-initial-access-broker-deploys-new-edgecution
report_type: threat-intel
severity: high
title: "Zscaler ThreatLabz: Edgecution — Payouts King IAB Deploys Malicious Edge Extension Backdoor via Chrome Native Messaging"
---

## 1. IOCs

### Domains / C2 Endpoints (CloudFront WebSocket)

| Indicator | Description |
|---|---|
| `d3nh8sl98s2554.cloudfront[.]net` | Edgecution C2 via WebSocket (wss://d3nh8sl98s2554.cloudfront[.]net/ws); attacker-controlled CloudFront distribution |
| `d2g6dl71gua1qa.cloudfront[.]net` | Edgecution C2 via WebSocket (wss://d2g6dl71gua1qa.cloudfront[.]net/ws) |
| `d1jp293q9tvi92.cloudfront[.]net` | Edgecution C2 via WebSocket (wss://d1jp293q9tvi92.cloudfront[.]net/ws) |
| `d23l50n6ubud7p.cloudfront[.]net` | Edgecution C2 via WebSocket (wss://d23l50n6ubud7p.cloudfront[.]net/ws) |

### File Hashes

| SHA256 | Type | Description |
|---|---|---|
| `a08d8e63b0cd3638fb40b8e6da546e26da69439597565827f9cec87915f78568` | SHA256 | Edgecution browser extension background script (`background.js`); beacons to CloudFront WebSocket C2 and relays commands to the Python native host via Chrome Native Messaging protocol |
| `3d1158884fb339b3328bd330fcc27598e1f1c94bcac39e75d1a272afa4deee1a` | SHA256 | Edgecution Python backdoor; registered as Chrome Native Messaging host; receives commands from extension and executes on host OS; capabilities include system info collection, filesystem access, arbitrary code execution |

---

## 2. TTPs

| MITRE Tactic | Technique ID | Technique Name | Usage |
|---|---|---|---|
| Initial Access | T1566 | Phishing | Attacker impersonates IT support on Microsoft Teams and directs victim to a fraudulent portal ("spam filter update" or "Outlook update") |
| Initial Access | T1204.002 | User Execution: Malicious File | Victim is directed to install a malicious Microsoft Edge extension from the attacker-controlled portal |
| Persistence | T1176 | Browser Extensions | Malicious Edge extension (`Edgecution`) persists in the browser; registers a Chrome Native Messaging host; beacons to C2 on browser start |
| Execution | T1559 | Inter-Process Communication | Chrome Native Messaging protocol bridges the browser extension (sandboxed) to the Python backdoor process (host OS); extension sends JSON commands over stdin/stdout pipe to native host |
| Discovery | T1082 | System Information Discovery | Python backdoor collects system information (OS version, hostname, user context) and reports to C2 |
| Discovery | T1083 | File and Directory Discovery | Backdoor provides filesystem enumeration capability |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | C2 communication over WebSocket (wss://) to attacker-controlled CloudFront distributions on port 443 |
| Command and Control | T1102 | Web Service | CloudFront CDN used as a C2 relay to blend in with legitimate AWS traffic |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | Backdoor is implemented as a Python script registered as a Chrome Native Messaging host binary |

---

## 3. Malware & Tools

### Edgecution Browser Extension
- Implemented as a Microsoft Edge browser extension
- Contains a `background.js` service worker that establishes a persistent WebSocket connection to attacker-controlled CloudFront distributions
- Uses the `chrome.runtime.connectNative()` API to open a Chrome Native Messaging pipe to the Python backdoor process on the host OS
- Commands from C2 are forwarded through this pipe to bypass the browser sandbox

### Edgecution Python Backdoor
- Registered as a Chrome Native Messaging host (`com.edgecution.host` or similar manifest name)
- Receives JSON-formatted command messages over stdin from the browser extension
- Executes commands on the host OS with the privileges of the user running the browser
- Capabilities:
  - System information enumeration
  - File and directory access
  - Arbitrary OS command execution
  - Output returned to extension → C2

### Infrastructure
- C2 uses Amazon CloudFront WebSocket endpoints, making network-layer blocking difficult without disrupting legitimate CloudFront traffic
- Unique subdomain identifiers (d3nh8sl98s2554, d2g6dl71gua1qa, d1jp293q9tvi92, d23l50n6ubud7p) distinguish attacker distributions from legitimate use

---

## 4. Threat Actor / Campaign Attribution

| Attribute | Value |
|---|---|
| Actor | Payouts Kings (Initial Access Broker) |
| Type | Ransomware initial access broker (IAB) |
| Confidence | High (Zscaler ThreatLabz) |
| Distribution method | Microsoft Teams social engineering → fake IT support portal → Edge extension install |
| Downstream impact | Payouts Kings sells access to ransomware operators; Edgecution represents a pre-ransomware foothold |
| Target sectors | Enterprises with Microsoft 365 deployments (Teams-based vishing targets corporate help-desk social engineering awareness gaps) |

### Attack Chain
1. **Reconnaissance/Social Engineering**: Attacker contacts victim via Microsoft Teams, impersonating IT helpdesk; claims victim must install a "spam filter" or "Outlook update" to remain compliant
2. **Delivery**: Victim directed to attacker-controlled portal; instructed to install a malicious Microsoft Edge extension
3. **Installation**: Extension installed; registers Chrome Native Messaging host (Python script) on the host OS; C2 beacon established via WebSocket to CloudFront
4. **C2 Establishment**: Persistent C2 via CloudFront WebSocket; commands relayed through browser extension to host-level Python backdoor
5. **Access Sold**: IAB (Payouts Kings) maintains access and sells to ransomware operators for follow-on intrusion

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="msedge.exe"
    AND Processes.process_name IN ("python.exe","python3.exe","pythonw.exe","cmd.exe","powershell.exe")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name,"(?i)python"), 90,
    match(process_name,"(?i)(powershell|cmd)"), 75,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Registry
  where Registry.registry_path="*\\SOFTWARE\\*\\NativeMessagingHosts\\*"
    AND (Registry.registry_value_data="*AppData*"
      OR Registry.registry_value_data="*Temp*"
      OR Registry.registry_value_data="*Downloads*"
      OR Registry.registry_value_data="*Desktop*"
      OR Registry.registry_value_data="*python*")
  by Registry.dest Registry.user Registry.registry_path Registry.registry_value_data Registry.process_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime dest user registry_path registry_value_data process_name risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_host="d3nh8sl98s2554.cloudfront.net"
    OR All_Traffic.dest_host="d2g6dl71gua1qa.cloudfront.net"
    OR All_Traffic.dest_host="d1jp293q9tvi92.cloudfront.net"
    OR All_Traffic.dest_host="d23l50n6ubud7p.cloudfront.net")
  by All_Traffic.src_ip All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_host dest_port app count risk_score
```

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="background.js" OR Filesystem.file_name="manifest.json")
    AND (Filesystem.file_path="*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*"
      OR Filesystem.file_path="*\\AppData\\Local\\Microsoft\\Edge\\Extensions\\*")
    AND Filesystem.process_name!="msedge.exe"
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| where risk_score >= 80
| table firstTime lastTime dest user file_path file_name process_name risk_score
```

---

## 6. Executive Summary

Zscaler ThreatLabz published research in June 2026 describing **Edgecution**, a novel malware family deployed by the **Payouts Kings** ransomware initial access broker (IAB). Edgecution abuses the Chrome Native Messaging protocol to bridge a sandboxed malicious Microsoft Edge browser extension to a Python-based backdoor running on the host OS, bypassing the browser sandbox without requiring any exploit.

The attack begins with a Microsoft Teams vishing call where the attacker impersonates IT support, directing the victim to install a "spam filter update" or "Outlook update" Edge extension from an attacker-controlled portal. Once installed, the extension (`background.js`, SHA256: `a08d8e63...`) establishes a persistent WebSocket connection to attacker-controlled Amazon CloudFront distributions. Commands received from C2 are relayed through the Chrome Native Messaging pipe to the Python backdoor (`SHA256: 3d1158884...`), which executes them on the host OS. The Python process is registered as a Native Messaging host and is invoked by the browser as a subprocess, giving it full host-level access.

Payouts Kings is an IAB that monetizes access by selling it to downstream ransomware operators. Defenders should monitor for Edge spawning Python or interpreter child processes, for suspicious Chrome Native Messaging host registrations pointing to user-writable directories, and for WebSocket connections to the four identified CloudFront C2 distributions. Organizations should also enforce Microsoft Teams external messaging restrictions to limit Teams-based social engineering attack surface.

---

## References

- [Zscaler ThreatLabz: Payouts King IAB Deploys New Edgecution Malware (2026-06)](https://www.zscaler.com/blogs/security-research/payouts-king-ransomware-initial-access-broker-deploys-new-edgecution)
- [BleepingComputer: Malicious Edge Extension Abuses Native Messaging as Bridge to Malware](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)
- [MITRE ATT&CK T1176 - Browser Extensions](https://attack.mitre.org/techniques/T1176/)
- [MITRE ATT&CK T1559 - Inter-Process Communication](https://attack.mitre.org/techniques/T1559/)
- [Chrome Native Messaging Protocol Documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
