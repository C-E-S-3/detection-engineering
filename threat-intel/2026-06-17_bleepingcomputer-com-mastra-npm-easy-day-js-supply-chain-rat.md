---
scraped_at: 2026-06-18T00:00:00Z
source_url: https://www.aikido.dev/blog/over-140-popular-mastra-npm-packages-hit-by-supply-chain-attack
report_type: threat-intel
severity: high
title: "easy-day-js Mastra npm Supply Chain Attack: 144 Packages Backdoored with Cryptocurrency-Stealing RAT"
---

## 1. IOCs

### Domains
None attributed (attacker C2 operates via IP only).

### IP Addresses
| Indicator | Context |
|-----------|---------|
| 23.254.164[.]92:8000 | easy-day-js dropper C2; first-stage: dropper contacts /update/49890878 to retrieve second-stage RAT binary |
| 23.254.164[.]123:443 | easy-day-js RAT C2; cryptocurrency-stealing RAT beacons here every 10 minutes; Hostwinds ASN (hwsrv-1327785.hostwindsdns.com) |

### File Hashes
| Hash | Type | Description |
|------|------|-------------|
| (full hash not publicly released; 41KB obfuscated JS) | SHA256 | easy-day-js second-stage RAT payload — multi-platform cryptocurrency stealer; retrieved from 23.254.164.92:8000 with standard Node.js User-Agent |

### Package Indicators
| Package | Version | Status |
|---------|---------|--------|
| easy-day-js | 1.11.22 | MALICIOUS — postinstall hook dropper; typosquat of legitimate dayjs library |
| easy-day-js | 1.11.21 | Clean (no postinstall hook) |
| @mastra/core | Versions published June 17 2026 01:12–02:39 UTC | Injected malicious easy-day-js@^1.11.21 dependency (npm resolves to 1.11.22) |
| @mastra/* (141 packages) | Versions republished June 17 2026 | All packages in @mastra scope republished with malicious easy-day-js dependency |

---

## 2. TTPs

| Tactic | Technique ID | Technique | Usage |
|--------|-------------|-----------|-------|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Hijacked dormant contributor account (ehindero) with retained @mastra publish scope access |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | postinstall hook runs obfuscated JS dropper on every `npm install` |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | RAT C2 via HTTP to 23.254.164.92:8000; 10-minute beacon interval |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Cryptocurrency wallet harvesting |
| Collection | T1005 | Data from Local System | Cloud provider keys, LLM API keys, CI/CD secrets, SSH keys, database credentials, cryptocurrency wallets |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Stolen credentials exfiltrated to RAT C2 at 23.254.164.123:443 |
| Defense Evasion | T1027 | Obfuscated Files or Information | Second-stage payload is a heavily obfuscated 41KB JavaScript script |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Dropper performs self-delete after deploying RAT payload |

---

## 3. Malware & Tools

| Malware | Type | Notes |
|---------|------|-------|
| easy-day-js postinstall dropper | npm postinstall hook | First stage; TLS off, spawns detached process, self-deletes; Hostwinds C2 |
| Unnamed cryptocurrency-stealing RAT | Multi-platform RAT | 41KB obfuscated JavaScript; steals crypto wallets, cloud keys, LLM API keys, CI/CD secrets; 10-minute beacon; configurable via C2 |

---

## 4. Threat Actor / Campaign Attribution

- **Threat Actor**: Likely **Sapphire Sleet (BlueNoroff)** — DPRK-linked cybercrime unit focused on cryptocurrency theft
- **Attribution Confidence**: Medium — Hostwinds hosting, clean-then-armed typosquat pattern, postinstall dropper with TLS-off/detached-spawn/self-delete, and crypto-wallet-stealing payload all match the Axios npm compromise Microsoft attributed to Sapphire Sleet in early 2026 (see `2026-04-01_cloud-google-com-blog-topics-threat-intelligence-north-korea-threat-actor-targets-axios-npm-package`)
- **Attack Timeline**: 
  - June 16, 2026: Account sergey2016 publishes clean easy-day-js@1.11.21 (establishing legitimacy)
  - June 17, 2026 01:12–02:39 UTC: 88-minute automated campaign republishes 142 @mastra packages injecting easy-day-js dependency
  - June 17, 2026: easy-day-js@1.11.22 published with malicious postinstall hook, tagged `latest`
- **Impact**: @mastra scope has 1.1M+ combined weekly downloads; @mastra/core alone ~918K weekly downloads; 144 packages compromised
- **Vector**: Hijacked former Mastra contributor account (ehindero) whose npm publish access was never revoked after they left the project
- **Remediation**: Roll back to pre-incident @mastra versions; treat any machine that installed affected packages since June 16, 2026, as compromised; rotate all cloud/LLM/CI/CD/cryptocurrency credentials

---

## 5. Splunk Detection Searches

```spl
| comment "easy-day-js Mastra supply chain: detect npm install processes making outbound connections to C2 IPs (post-install hook execution)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("23.254.164.92", "23.254.164.123")
     OR All_Traffic.dest IN ("23.254.164.92", "23.254.164.123")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_port app risk_score
```

```spl
| comment "easy-day-js: detect npm/node processes spawning download or exec children consistent with postinstall hook dropper"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("node", "npm", "npx")
    AND (Processes.process_name IN ("curl", "wget", "powershell", "cmd")
      OR Processes.process LIKE "%-e %"
      OR Processes.process LIKE "%http%")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "23\.254\.164"), 95,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

```spl
| comment "easy-day-js: search proxy/firewall logs for outbound node connections to Hostwinds 23.254.164.0/24 block"
`fortigate` OR `paloalto`
| search dest_ip="23.254.164.*"
| eval risk_score=90
| stats count min(_time) as firstTime max(_time) as lastTime values(src_ip) as src_ips by dest_ip dest_port
| where count > 0
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ips dest_ip dest_port count risk_score
```

---

## 6. Executive Summary

On June 17, 2026 (01:12–02:39 UTC), attackers using a hijacked former contributor account (ehindero) republished 142 packages across the @mastra npm scope — an AI application framework with 1.1M+ weekly downloads — injecting a malicious dependency (easy-day-js@1.11.22). The attack is a textbook "clean-then-arm" typosquat: the attacker first published a clean copy of the legitimate dayjs library as easy-day-js@1.11.21 (establishing legitimacy), then released @1.11.22 with a malicious postinstall hook. Since the @mastra packages specify `^1.11.21`, npm's semver resolution automatically selects the malicious 1.11.22 version.

The postinstall hook drops a second-stage cryptocurrency-stealing RAT that beacons to C2 servers at 23.254.164.92 and 23.254.164.123 (Hostwinds, same /24 block). The RAT harvests cryptocurrency wallets, cloud provider keys (AWS/Azure/GCP), LLM API keys, npm tokens, GitHub tokens, CI/CD secrets, SSH keys, and database credentials. Attribution confidence is medium-high to Sapphire Sleet (DPRK/BlueNoroff) based on TTP overlap with the January 2026 Axios npm compromise.

Any developer who ran `npm install` involving an affected @mastra package between June 16-17, 2026, should treat their workstation as compromised and rotate all credentials immediately.
