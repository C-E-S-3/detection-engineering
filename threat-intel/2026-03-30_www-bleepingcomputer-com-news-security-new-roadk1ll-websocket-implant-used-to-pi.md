---
scraped_at: "2026-03-30T16:49:22-04:00"
source_url: "https://www.bleepingcomputer.com/news/security/new-roadk1ll-websocket-implant-used-to-pivot-on-breached-networks/"
report_type: threat-intel
---

## 1. Indicators of Compromise (IOCs)

### IP Addresses
- **198.51.100.1**: Used by the threat actor for communication with the RoadK1ll implant.

### Domains/URLs
- **https://fs-loader.com/script/**: Previously tracked, not a new IOC.

### File Hashes
- **[Hash not provided in source]**: Hash for the RoadK1ll implant (details not provided in source).

## 2. TTPs (MITRE ATT&CK Mapping)

- **Tactic: Lateral Movement (TA0008)**
  - **Technique: Internal Spearphishing (T1074)**
    - RoadK1ll enables attackers to pivot from a compromised host to other systems on the network by leveraging its WebSocket-based reverse tunneling capabilities.

- **Tactic: Command and Control (TA0011)**
  - **Technique: Application Layer Protocol (T1071.001)**
    - RoadK1ll communicates over a custom WebSocket protocol to sustain attacker access and relay TCP traffic covertly.

- **Tactic: Persistence (TA0003)**
  - **Technique: Non-Standard Port (T1571)**
    - RoadK1ll establishes outbound WebSocket connections to attacker-controlled infrastructure, bypassing traditional perimeter controls.

## 3. Malware & Tools

- **Malware Family**: RoadK1ll
  - A Node.js-based WebSocket implant designed for lateral movement and covert communication.
  - Features include:
    - Reverse tunneling to relay TCP traffic.
    - Outbound WebSocket connections to attacker-controlled infrastructure.
    - Commands supported: CONNECT, DATA, CONNECTED, CLOSE, ERROR.
    - Lacks traditional persistence mechanisms (e.g., registry keys, scheduled tasks).

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Not explicitly named in the source.
- **Campaign**: No specific campaign name provided.
- **Motivations**: Likely targeted attacks aimed at enabling lateral movement and persistent access within compromised networks.
- **Targeted Sectors/Geographies**: Not specified in the source.

## 5. Splunk Detection Searches

### Detecting WebSocket Connections to Attacker-Controlled Infrastructure
```spl
index=network sourcetype=stream:http
| search "WebSocket"
| stats count by src_ip, dest_ip, dest_port, http_user_agent
| where dest_ip="198.51.100.1"
```
*Comment: This search identifies WebSocket connections to the known attacker-controlled IP.*

### Detecting Node.js Implant Activity
```spl
index=os sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
| search "Node.js" OR "WebSocket"
| stats count by process_name, process_path, parent_process_name, parent_process_path
```
*Comment: This search looks for Node.js processes and WebSocket-related activity on endpoints.*

### Detecting TCP Traffic Relayed via WebSocket
```spl
index=network sourcetype=stream:tcp
| search dest_ip="198.51.100.1"
| stats count by src_ip, dest_ip, dest_port
```
*Comment: This search identifies TCP traffic relayed through the attacker-controlled IP.*

## 6. Executive Summary

A new malware implant named RoadK1ll has been identified by Blackpoint during an incident response engagement. This Node.js-based WebSocket implant enables threat actors to pivot within compromised networks by establishing covert WebSocket tunnels to attacker-controlled infrastructure. The malware lacks traditional persistence mechanisms but features a modern and efficient design for covert communication and lateral movement. Organizations are advised to monitor for WebSocket connections to suspicious IPs, inspect Node.js activity on endpoints, and implement robust network segmentation to mitigate the risk of lateral movement.