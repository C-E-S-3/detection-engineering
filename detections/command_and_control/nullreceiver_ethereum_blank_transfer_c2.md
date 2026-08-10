# NullReceiver Ethereum Blank Transfer C2 Dead-Drop Resolution

## Description

Detects the **NullReceiver** technique used by DPRK Contagious Interview campaign malware embedded in trojanized npm packages (`bianira-ui@1.27.0`, `fluid-type-ui@2.0.8`). NullReceiver is an evolution of EtherHiding: instead of reading a smart contract storage slot, the malware queries a public Ethereum JSON-RPC endpoint for the most recent outgoing zero-value, zero-data transfer from a controlled wallet, then decodes the current C2 IP address from the last 8 hex characters of the recipient address.

The technique is cheaper than smart contract C2 (costs only minimum gas), harder to block than EtherHiding (no contract address to blocklist), and leaves no on-chain footprint distinguishable from legitimate transfers without knowing the controlled wallet address.

This detection targets: (1) DNS resolution of public Ethereum RPC endpoints from non-browser processes, (2) the known malicious dead-drop wallet address appearing in network traffic or process arguments, (3) npm postinstall scripts making outbound network connections, and (4) the campaign-specific string `A10-npm3!`.

**False positives:** Web3 developers and blockchain tooling that legitimately query `1rpc.io` or `eth.drpc.org` via `node`, `npm`, or `python`. Tune by excluding known developer hosts or enriching with the specific wallet address. The wallet address and campaign string rules have near-zero false positive potential.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Dead Drop Resolver |
| Technique ID | T1102.001 |

Secondary techniques: T1195.001 (Supply Chain Compromise: Software Dependencies), T1059.007 (JavaScript), T1027 (Obfuscated Files or Information)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("1rpc.io","eth.drpc.org")
    AND NOT DNS.src_category IN ("browser","proxy")
  by DNS.src DNS.query DNS.answer DNS.process
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(node|npm|python|pip)"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src query answer process risk_score
```

### NullReceiver Dead-Drop Wallet in Web Traffic or Process Arguments

```spl
index=* "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a"
| stats count min(_time) as firstTime max(_time) as lastTime by host source sourcetype
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 90
| table firstTime lastTime host source sourcetype count risk_score
```

### npm Postinstall Network Activity (Broad Supply Chain Signal)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("node","npm","npm.cmd")
    AND Processes.process IN ("*postinstall*","*install.js*","*setup.js*")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process,"(?i)(1rpc\.io|eth\.drpc\.org|0xa322e5)"), 95,
    match(process,"(?i)(curl|wget|invoke-webrequest|invoke-restmethod)"), 75,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

### Campaign String Detection

```spl
index=* "A10-npm3!"
| stats count min(_time) as firstTime max(_time) as lastTime by host source sourcetype
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host source sourcetype count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Dead-drop wallet address found anywhere in logs | 90 | Unique malicious indicator; no legitimate use |
| Campaign string `A10-npm3!` found in logs | 90 | Campaign-specific marker; no legitimate use |
| Ethereum RPC query from node/npm/python process | 85 | Unusual for non-blockchain-dev environments; specific to NullReceiver delivery mechanism |
| npm postinstall script referencing Ethereum RPC or wallet | 95 | Near-certain malicious postinstall activity |
| npm postinstall script spawning download utility (curl/wget/PowerShell) | 75 | Suspicious postinstall behavior; supply chain signal |
| Ethereum RPC query from unclassified process | 65 | Broader but lower-confidence signal for non-developer hosts |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| DPRK Contagious Interview (Famous Chollima) | [MITRE ATT&CK G0032 — Lazarus Group](https://attack.mitre.org/groups/G0032/) |
| ViteVenom / PolinRider (DPRK — related blockchain C2 technique) | [MITRE ATT&CK T1102.001](https://attack.mitre.org/techniques/T1102/001/) |

## References

- [The Hacker News — Trojanized npm Packages Decode C2 IP from Ethereum Transfers](https://thehackernews.com/2026/08/trojanized-npm-packages-decode-c2-ip.html)
- [MITRE ATT&CK — T1102.001: Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [MITRE ATT&CK — T1195.001: Supply Chain Compromise: Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [Related detection — EtherHiding Ethereum Smart Contract C2](etherhiding_ethereum_smart_contract_c2.md)
- [Related detection — SmartLoader Polygon Blockchain C2](smartloader_polygon_blockchain_c2.md)
- [Threat Intel Report — threat-intel/2026-08-05_nullreceiver-dprk-npm-ethereum-c2-contagious-interview.md](../../threat-intel/2026-08-05_nullreceiver-dprk-npm-ethereum-c2-contagious-interview.md)
