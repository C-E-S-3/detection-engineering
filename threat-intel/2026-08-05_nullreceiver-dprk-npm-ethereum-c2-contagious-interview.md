---
scraped_at: 2026-08-10T00:00:00Z
source_url: https://thehackernews.com/2026/08/trojanized-npm-packages-decode-c2-ip.html
report_type: threat-intel
severity: high
title: "NullReceiver: DPRK Contagious Interview Campaign Uses Zero-Value Ethereum Transfers to Encode C2 IP — Trojanized npm Packages"
---

# NullReceiver: DPRK Trojanized npm Packages Decode C2 IP from Ethereum Blank Transfers

**Source:** The Hacker News / OpenSourceMalware  
**Published:** 2026-08-05  
**Severity:** High  

## Executive Summary

Researchers at OpenSourceMalware identified two malicious npm packages published on 2026-07-28 as part of the ongoing **DPRK Contagious Interview** campaign. The packages introduce a novel C2 IP delivery technique named **NullReceiver**: the malware queries a public Ethereum RPC endpoint and decodes the C2 server's IP address directly from the **recipient address field** of a zero-value, zero-data Ethereum transfer — a cheaper and more covert evolution of the previously documented EtherHiding technique (which used smart contract storage). Approximately $0 in crypto is moved per query, making the dead-drop essentially free and difficult to block without also blocking legitimate Ethereum RPC access.

## Technical Details

### Malicious npm Packages

| Package | Version | Publisher | Published |
|---------|---------|-----------|-----------|
| `bianira-ui` | 1.27.0 | npmuser1101 | 2026-07-28 |
| `fluid-type-ui` | 2.0.8 | npmuser3002 | 2026-07-28 |

Both packages present as UI component libraries. The malicious payload is embedded in a postinstall script that executes at `npm install` time.

### NullReceiver Technique

**How it works:**

1. The postinstall script queries a public Ethereum JSON-RPC endpoint (`1rpc.io` or `eth.drpc.org`) for the transaction history of a controlled wallet address.
2. It retrieves the most recent **outgoing zero-value, zero-data transfer** (a blank send that costs only the minimum gas fee).
3. It extracts the **recipient address** of that transfer, which is a 20-byte Ethereum address (40 hex characters).
4. The last **8 hex characters** of the recipient address encode a 4-byte IPv4 address (big-endian). The malware decodes this to obtain the current C2 IP.
5. The malware then connects to that IP on a hardcoded port to retrieve the next-stage payload.

**Comparison to EtherHiding:**

| Attribute | EtherHiding (prior) | NullReceiver (new) |
|-----------|---------------------|-------------------|
| Storage method | Smart contract storage slot | Recipient address of blank transfer |
| Cost per update | ~$0.01–$0.05 gas | Minimum gas (~$0.001) |
| Detection surface | Contract call/read | eth_getTransactionByHash on wallet |
| Blocking difficulty | Block contract address | Block Ethereum RPC entirely |

**Dead-drop wallet:** `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a`

**Ethereum RPC endpoints queried:**
- `1rpc.io`
- `eth.drpc.org`

### C2 Infrastructure

| Indicator | Type | Context |
|-----------|------|---------|
| `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a` | Ethereum address | NullReceiver dead-drop wallet; encodes C2 IP in outgoing transfer recipient address |
| `166.88.134.62` | IP | Active C2 server (encoded in NullReceiver dead drop as of 2026-07-28); previously tracked June 2026 |
| `1rpc.io` | Domain | Public Ethereum RPC used by malware to resolve dead-drop |
| `eth.drpc.org` | Domain | Public Ethereum RPC used by malware to resolve dead-drop |

### Detection String

The string `A10-npm3!` appears as a campaign tag/beacon marker in the postinstall script payload.

### Payload Behavior

After resolving the C2 IP via NullReceiver, the malware:
1. Downloads and executes **InvisibleFerret** — a Python-based infostealer (consistent with prior Contagious Interview toolchain)
2. Targets: source code, SSH/API keys, browser-stored credentials, cryptocurrency wallet files
3. Exfiltrates via the resolved C2 over HTTP POST

## IOCs

### Ethereum / Blockchain
| Indicator | Context |
|-----------|---------|
| `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a` | NullReceiver Ethereum dead-drop wallet address |

### npm Packages (malicious — do not install)
| Package | Version | Context |
|---------|---------|---------|
| `bianira-ui` | 1.27.0 | Trojanized npm package; NullReceiver loader in postinstall |
| `fluid-type-ui` | 2.0.8 | Trojanized npm package; NullReceiver loader in postinstall |

### Network
| Indicator | Context |
|-----------|---------|
| `166.88.134.62` | C2 IP (tracked since June 2026) |

### String Artifacts
| Indicator | Context |
|-----------|---------|
| `A10-npm3!` | Campaign tag in postinstall payload |

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Supply Chain Compromise: Compromise Software Dependencies and Development Tools | T1195.001 | Malicious packages published to npm registry masquerading as UI libraries |
| Command and Scripting Interpreter: JavaScript | T1059.007 | Postinstall script executes at npm install time without user interaction |
| Web Service: Dead Drop Resolver | T1102.001 | Ethereum wallet transaction history used as dead-drop C2 resolver |
| Obfuscated Files or Information | T1027 | C2 IP encoded in Ethereum recipient address hex field |
| Credentials from Web Browsers | T1555.003 | InvisibleFerret harvests browser-stored credentials |
| Credentials from Password Stores | T1555 | SSH keys, API tokens, wallet files targeted |
| Exfiltration Over C2 Channel | T1041 | Stolen data exfiltrated via HTTP POST to resolved C2 IP |

## Kill Chain

| Phase | Activity |
|-------|----------|
| Weaponization | DPRK operator publishes trojanized npm packages with NullReceiver postinstall loader |
| Delivery | Developer installs `bianira-ui` or `fluid-type-ui` via `npm install` |
| Exploitation | Postinstall script queries Ethereum RPC, decodes C2 IP from recipient address of blank transfer |
| Installation | InvisibleFerret Python stealer downloaded and executed from resolved C2 |
| Actions on Objectives | Credential theft, source code exfiltration, cryptocurrency wallet draining |

## Attribution

**DPRK Contagious Interview** campaign (also tracked as Famous Chollima, DEV-0139 adjacent):
- Ongoing since at least 2022; escalated in 2025–2026 with npm-based supply chain attacks
- Previously used EtherHiding (smart contract C2 dead drop) and Socket.io C2 servers
- `166.88.134.62` C2 IP previously attributed to this campaign (June 2026 html-to-gutenberg/fetch-page-assets supply chain attack)
- InvisibleFerret Python stealer is a known Contagious Interview second-stage tool
- Targeting pattern: developers working on cryptocurrency and DeFi projects (via fake job interviews)

## Remediation

| Action | Priority |
|--------|----------|
| Remove `bianira-ui@1.27.0` and `fluid-type-ui@2.0.8` from all environments immediately | Critical |
| Treat any host that installed these packages as compromised; rotate all secrets/credentials | Critical |
| Audit `package.json` and lock files across all repositories for these package names | Critical |
| Block or alert on outbound HTTP/HTTPS to `1rpc.io` and `eth.drpc.org` from non-approved hosts | High |
| Block outbound traffic to `166.88.134.62` | High |
| Search for Ethereum wallet `0xa322e5f3d311d3080e6f0121063e9adc2490ef1a` in postinstall scripts, process memory, and logs | High |
| Search for string `A10-npm3!` in npm package files and process command lines | High |
| Configure npm audit hooks or OSSReview to block unvetted postinstall scripts in CI/CD | High |

## Splunk Hunting Queries

### Ethereum RPC Query to Known Dead-Drop Resolvers
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("1rpc.io","eth.drpc.org")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### npm Postinstall Script Spawning Node.js Network Process
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name="node" Processes.process="*postinstall*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### NullReceiver Dead-Drop Wallet in Web Traffic
```spl
index=* sourcetype=* "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a"
| stats count min(_time) as firstTime max(_time) as lastTime by host src dest uri
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

## References

- [The Hacker News — Trojanized npm Packages Decode C2 IP from Ethereum Transfers](https://thehackernews.com/2026/08/trojanized-npm-packages-decode-c2-ip.html)
- [OpenSourceMalware — NullReceiver Analysis](https://opensourcemalware.com/2026/08/nullreceiver-ethereum-blank-transfer-c2)
- [MITRE ATT&CK — T1102.001: Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/001/)
- [Prior EtherHiding detection: etherhiding_ethereum_smart_contract_c2.md](../detections/command_and_control/etherhiding_ethereum_smart_contract_c2.md)
