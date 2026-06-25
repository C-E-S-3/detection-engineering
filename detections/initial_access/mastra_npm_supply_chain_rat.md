# Mastra npm easy-day-js Supply Chain RAT — C2 Network Detection

## Description

Detects network connections to command-and-control infrastructure used by the easy-day-js Mastra npm supply chain attack (June 17, 2026). A threat actor (attributed with moderate confidence to Sapphire Sleet / DPRK / BlueNoroff based on C2 infrastructure and cryptocurrency theft targeting) hijacked a dormant contributor account with publish access to the `@mastra` npm scope and republished 144 packages with a malicious `easy-day-js@1.11.22` dependency. The malicious version runs a `postinstall` hook that contacts a dropper C2 server (23.254.164.92:8000) to fetch an obfuscated 41KB JavaScript cryptocurrency-stealing RAT. The RAT beacons every 10 minutes to 23.254.164.123:443 and exfiltrates cloud provider keys, LLM API keys, CI/CD secrets, SSH keys, database credentials, and cryptocurrency wallets. Any environment that ran `npm install` on an affected `@mastra/*` package between June 17 2026 01:12–02:39 UTC and the removal of the malicious versions is potentially compromised.

**Expected false positives:** None — these IPs have no legitimate use and are uniquely associated with this attack.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Credential Access | Credentials from Password Stores: Credentials from Web Browsers | T1555.003 |
| Collection | Data from Local System | T1005 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

## Lockheed Martin Kill Chain Phase

Delivery (supply chain), Exploitation, Installation, C2, Actions on Objectives

## Wazuh Rule IDs

- **103001** — Outbound connection to dropper C2 23.254.164.92 (T1195.002, level 14)
- **103002** — Outbound connection to RAT beacon C2 23.254.164.123 (T1071.001, level 15)
- **103030/103031** — Suricata detection on src/dest matching either IOC IP (level 14)

## IOC Network Indicators

| IP | Port | Role | Notes |
|----|------|------|-------|
| 23.254.164.92 | 8000 | Dropper C2 | First-stage; postinstall hook GETs /update/49890878; Hostwinds ASN hwsrv-1327786 |
| 23.254.164.123 | 443 | RAT C2 | Second-stage; 10-minute beacon; hwsrv-1327785.hostwindsdns.com; same /24 as dropper |

## Splunk SPL Query

```spl
index=wazuh sourcetype=wazuh rule.id IN (103001,103002,103030,103031)
| table _time, agent.name, data.src_ip, data.dest_ip, data.dest_port, rule.description
| sort -_time
```

Network scan for active RAT beacons (if network flow data available):

```spl
index=network_flow (dest_ip="23.254.164.92" OR dest_ip="23.254.164.123")
| stats count by src_ip, dest_ip, dest_port, _time span=10m
| sort -_time
```

## Risk Score Logic

- Level 14 (dropper C2 contact): Host has almost certainly installed a compromised npm package; isolate and investigate.
- Level 15 (RAT beacon): Active RAT present; incident response required immediately.

## Associated Threat Actors

- **Sapphire Sleet / DPRK / BlueNoroff** (moderate confidence): DPRK-affiliated threat group targeting developer credentials and cryptocurrency; consistent with prior npm supply chain attacks by this actor. Trademark indicators: cryptocurrency-stealing payload, CI/CD secret targeting, Hostwinds infrastructure.

## References

- https://www.aikido.dev/blog/over-140-popular-mastra-npm-packages-hit-by-supply-chain-attack
- https://attack.mitre.org/techniques/T1195/002/
- https://attack.mitre.org/techniques/T1071/001/
