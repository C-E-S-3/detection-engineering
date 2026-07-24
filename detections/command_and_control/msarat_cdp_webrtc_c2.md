# msaRAT Browser CDP WebRTC C2

## Description

Detects **msaRAT**, a component of the **Chaos** malware family, that achieves command and control by injecting itself into the victim's own browser process via the Chrome DevTools Protocol (CDP) and routing all implant traffic through the browser's WebRTC stack.

The key technique: msaRAT attaches to a running Chrome or Edge instance on the loopback interface (typically `127.0.0.1:9222`, the CDP debug port) using CDP's `Target.attachToTarget` and `Runtime.evaluate` commands. Once attached, it instructs the browser to create a WebRTC `RTCPeerConnection` and establish a data channel to an attacker-controlled signaling server (observed: `is-01-ast.ols-img-12.workers.dev` on Cloudflare Workers). The data channel is used for bidirectional C2: receiving operator tasking and returning results.

Because the WebRTC DTLS/SRTP traffic exits from the browser process itself — and through the browser's network stack — network-layer controls that inspect originating process identity see `chrome.exe` or `msedge.exe`, not the malicious injector. This sidesteps process-based allowlisting, and proxy TLS inspection has no effect on DTLS (WebRTC's transport).

**Detection approach:** Three complementary signals, weakest to strongest:

1. **CDP loopback connection from non-browser process**: Any process other than a known browser executable establishing a TCP connection to `127.0.0.1:9222` (or the CDP port range `9200-9222`) is anomalous. Legitimate use cases are rare and include remote debuggers.
2. **WebRTC STUN/TURN activity from browser immediately after non-browser loopback**: If a browser initiates ICE STUN/TURN negotiation shortly after a non-browser process connected to the CDP port on the same host, it indicates browser WebRTC was triggered externally.
3. **Browser process connecting to Cloudflare Workers `.workers.dev` signaling domain**: The known IOC `is-01-ast.ols-img-12.workers.dev` is a direct indicator. Generalizing: browser connections to `*.workers.dev` for the purpose of a persistent data channel (not a one-time page load) are anomalous.

**Expected false positives:**
- CDP on port 9222: Developer workstations running Node.js debugger, Puppeteer, or Playwright in debug mode; selenium grid workers. Scope by excluding known developer hosts or build agents.
- `*.workers.dev` browser connections: Extremely common — millions of legitimate sites use Cloudflare Workers. The IOC hostname is specific; do not block the entire TLD. Use the direct IOC rule (Query 2) rather than a wildcard block.
- MSI from unfamiliar IP: System administrators deploying software manually. Correlate with other indicators before escalating.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: One-Way Communication |
| Technique ID | T1102.001 |
| Secondary Technique | Application Layer Protocol: Web Protocols |
| Secondary Technique ID | T1071.001 |
| Tertiary Tactic | Defense Evasion |
| Tertiary Tactic ID | TA0005 |
| Tertiary Technique | Process Injection |
| Tertiary Technique ID | T1055 |
| Supporting Technique | Ingress Tool Transfer |
| Supporting Technique ID | T1105 |
| Supporting Technique | Masquerading |
| Supporting Technique ID | T1036 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |
| Command & Control |

## Splunk Detection Queries

### Query 1: Non-Browser Process Accessing CDP Debug Port (Endpoint)

Detects any process other than known browser executables opening a TCP connection to localhost on the CDP default debug port range (9200–9222). This is the most upstream signal — it fires before the WebRTC C2 channel is established.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="127.0.0.1"
  AND All_Traffic.dest_port >= 9200 AND All_Traffic.dest_port <= 9222
  AND NOT All_Traffic.process_name IN (
    "chrome.exe","msedge.exe","chromium.exe","brave.exe","vivaldi.exe","opera.exe",
    "node.exe","node","python","python3","java","selenium","chromedriver","msedgedriver",
    "playwright")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
   All_Traffic.process_name All_Traffic.process_id All_Traffic.parent_process_name
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)rundll32|regsvr32|mshta|wscript|cscript|powershell|pwsh|cmd\.exe"), 90,
    match(process_name, "(?i)svchost|lsass|services|winlogon"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src dest dest_port process_name process_id parent_process_name risk_score
```

### Query 2: Browser Process DNS Resolution of msaRAT Known C2 Domain

Direct IOC rule: browser process resolving the confirmed msaRAT Cloudflare Workers signaling domain. Near-zero false positive rate for this specific hostname.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query="is-01-ast.ols-img-12.workers.dev"
by DNS.src DNS.query DNS.answer DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=99
| eval note="msaRAT confirmed C2 signaling domain IOC (Talos, 2026-07-23)"
| table firstTime lastTime src query answer record_type risk_score note
```

### Query 3: Outbound HTTPS to Known msaRAT Staging Server IP

Detects connections to `172.86.126.18`, the confirmed msaRAT payload staging server where `update_ms.msi` is served.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest="172.86.126.18"
  AND All_Traffic.dest_port=443
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
   All_Traffic.process_name All_Traffic.bytes_out
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=99
| eval note="msaRAT staging server IOC — MSI payload at /update_ms.msi (Talos, 2026-07-23)"
| table firstTime lastTime src dest dest_port process_name bytes_out risk_score note
```

### Query 4: MSI Download Matching msaRAT Filename Pattern from Suspicious IP

Detects web/proxy log entries showing an MSI download named `update_ms.msi` (or similar update-masquerade patterns) from a non-Microsoft/non-enterprise source.

```spl
index=proxy OR index=web OR index=network
(url="*/update_ms.msi" OR url="*/update_ms.exe" OR url="*/ms_update.msi")
NOT (dest_host IN ("*.microsoft.com","*.windowsupdate.com","*.update.microsoft.com","*.msftncsi.com"))
| eval risk_score=85
| eval note="MSI download with Microsoft Update masquerade naming from non-Microsoft host"
| table _time src dest_host url process_name http_method status risk_score note
```

### Query 5: Correlation — CDP Port Access + Browser WebRTC within 5 Minutes (Same Host)

High-confidence correlation: a non-browser process accessed the CDP debug port AND the browser on the same host established new outbound connections within 5 minutes of the CDP access. Strongly suggests browser was instrumented via CDP to initiate C2.

```spl
(index=network OR index=proxy OR index=endpoint)
| eval event_type=case(
    (dest="127.0.0.1" AND (dest_port >= 9200 AND dest_port <= 9222) AND NOT match(process_name,"(?i)chrome|msedge|chromium|brave|vivaldi|opera|node|python|java|selenium|playwright")), "cdp_loopback",
    (match(process_name,"(?i)chrome|msedge|chromium|brave") AND match(dest_host,"\.workers\.dev$")), "browser_workers_dev",
    1=1, null())
| where isnotnull(event_type)
| eval bucket_time=floor(_time/300)*300
| stats values(event_type) as event_types dc(event_type) as type_count
    values(process_name) as procs values(dest) as dests values(dest_host) as dest_hosts
    by host bucket_time
| where type_count >= 2
| eval confirmed=if(mvfind(event_types,"cdp_loopback") >= 0 AND mvfind(event_types,"browser_workers_dev") >= 0, "msaRAT_CDP_WebRTC_Confirmed", "CDP_Anomaly_Investigate")
| eval risk_score=case(
    confirmed="msaRAT_CDP_WebRTC_Confirmed", 96,
    type_count >= 2, 82,
    1=1, 70)
| table bucket_time host procs dests dest_hosts event_types confirmed risk_score
| sort -risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS resolution of `is-01-ast.ols-img-12.workers.dev` | 99 | Confirmed msaRAT C2 domain IOC; no legitimate use case |
| Connection to `172.86.126.18:443` | 99 | Confirmed msaRAT staging server IOC |
| Correlation: CDP loopback + browser to `*.workers.dev` within 5 min (same host) | 96 | Near-certain msaRAT C2 session; immediate IR |
| Non-browser process to CDP port 9222 (LOLBin: rundll32/mshta/wscript) | 90 | High-confidence malicious CDP attachment attempt |
| Non-browser process to CDP port 9222 (unknown .NET/PE process) | 75 | Investigate; may be automated test tool or attacker |
| MSI download with `update_ms.msi` naming from non-Microsoft source | 85 | Masquerade pattern matches msaRAT delivery |

## Associated Threat Actors

| Actor | Relationship |
|-------|-------------|
| Chaos | Malware family that distributes msaRAT; multiple campaigns documented; attacker identity unknown |

## References

- [Cisco Talos — Chaos/msaRAT Browser CDP WebRTC C2 (2026-07-23)](https://blog.talosintelligence.com/chaos-msarat-browser-cdp-webrtc-c2/)
- [Talos GitHub IOC file — chaos-msarat.txt](https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/07/chaos-msarat.txt)
- [MITRE ATT&CK — T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK — T1102.001: Web Service: One-Way Communication](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK — T1071.001: Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [Google Chrome DevTools Protocol documentation](https://chromedevtools.github.io/devtools-protocol/)
- [WebRTC DTLS transport specification](https://www.rfc-editor.org/rfc/rfc8827)
