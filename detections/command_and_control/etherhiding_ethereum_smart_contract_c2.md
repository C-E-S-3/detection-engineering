# EtherHiding — Ethereum Smart Contract C2 Dead Drop

## Description

Detects EtherHiding, a technique where malware retrieves its current C2 domain at runtime by calling `eth_call` against an attacker-controlled Ethereum smart contract using a public JSON-RPC endpoint. Because the C2 address lives in blockchain state rather than DNS, it cannot be sinkholed by seizing a domain — the actor simply updates the contract's storage slot. First documented in 2023 (WeedHack MaaS), EtherHiding was adopted by Sandworm (UAC-0145, July 2026) in a campaign targeting Ukraine and appears in blockchain-C2-resilient implants from multiple threat actor clusters (ViteVenom/PolinRider npm supply chain July 2026; UAT-11795 Starland RAT Polygon variant July 2026). The detection targets non-browser processes making HTTPS connections to known public Ethereum JSON-RPC endpoints — this pattern has no legitimate use on enterprise endpoints (wallets and DApps use browser extensions or dedicated apps, not powershell.exe or wscript.exe). Expected false positives: blockchain developer tools, Ethereum node operators, DApp development environments; scope with asset group filters to exclude developer workstations where appropriate.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Web Service: Bidirectional Communication |
| Technique ID | T1102.002 |

Secondary techniques: T1008 (Fallback Channels — blockchain provides fallback when primary C2 is unavailable), T1573.001 (Encrypted Channel — Ethereum RPC over HTTPS)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host IN (
      "cloudflare-eth.com",
      "mainnet.infura.io",
      "eth-mainnet.g.alchemy.com",
      "rpc.ankr.com",
      "ethereum.publicnode.com",
      "rpc.flashbots.net",
      "eth.llamarpc.com",
      "rpc.mevblocker.io",
      "api.mycryptoapi.com",
      "gateway.tenderly.co",
      "rpc-ethereum.g.allthatnode.com",
      "eth-mainnet.public.blastapi.io",
      "1rpc.io",
      "endpoints.omniatech.io",
      "rpc.payload.de"
    )
    AND NOT All_Traffic.app IN (
      "chrome", "firefox", "msedge", "brave", "safari",
      "chromium", "opera", "vivaldi", "iexplore"
    )
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port
     All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| eval risk_score=case(
    match(process_name, "(?i)powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32"), 90,
    match(process_name, "(?i)python|node|node\.exe|npm"), 75,
    match(process_name, "(?i)curl|wget|certutil|bitsadmin"), 80,
    match(app, "(?i)powershell|wscript|cscript|mshta"), 90,
    1=1, 65)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src dest dest_host dest_port app process_name risk_score
```

**Supplemental: DNS Query to Ethereum RPC Provider Domains from Endpoint**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN (
      "cloudflare-eth.com", "mainnet.infura.io", "eth-mainnet.g.alchemy.com",
      "rpc.ankr.com", "ethereum.publicnode.com", "rpc.flashbots.net",
      "eth.llamarpc.com", "rpc.mevblocker.io", "api.mycryptoapi.com",
      "gateway.tenderly.co", "rpc-ethereum.g.allthatnode.com",
      "eth-mainnet.public.blastapi.io", "1rpc.io",
      "endpoints.omniatech.io", "rpc.payload.de"
    )
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime src query answer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| PowerShell / wscript / cscript / mshta connecting to Ethereum RPC | 90 | Script interpreters have no legitimate reason to query Ethereum nodes; near-certain malware activity |
| certutil / bitsadmin / curl connecting to Ethereum RPC | 80 | LOLBin-based C2 key retrieval; unusual but slightly more ambiguous than script interpreter |
| python / node / npm connecting to Ethereum RPC | 75 | Could be blockchain developer tools on developer workstations; correlate with process ancestry |
| Unknown process connecting to Ethereum RPC | 65 | Anomalous; investigate to determine if a legitimate blockchain application |
| DNS query to Ethereum RPC provider domain | 70 | Enrichment-level IOC; insufficient alone but raises score when correlated with non-browser DNS source |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Sandworm / UAC-0145 (GRU Unit 74455) | Adopted EtherHiding for FluidLeech/LoadLoop C2 domain resolution in July 2026 ClickFix campaign targeting Ukraine; Ethereum contract stores current C2 domain; SCOUTCURL resolves via `eth_call` |
| ViteVenom / PolinRider (DPRK-attributed) | Uses TRON and Aptos blockchain for XOR decryption key delivery in malicious npm package `postinstall` hooks; related blockchain C2 technique (TRON rather than Ethereum) |
| UAT-11795 (Starland RAT campaign) | Uses Polygon blockchain smart contract as fallback C2 when primary HTTP endpoints are unreachable; Polygon is EVM-compatible and uses the same JSON-RPC `eth_call` API |
| WeedHack MaaS | First documented EtherHiding adopter (2023); commodity malware used Ethereum to store C2 domains, originating the technique name |

## References

- [CERT-UA — Advisory #6318437: UAC-0145 ClickFix Campaign with EtherHiding C2 (2026-07-17)](https://cert.gov.ua/article/6318437)
- [GuardioLabs — EtherHiding: Hiding Web2 Malicious Code in Web3 Smart Contracts (2023)](https://labs.guard.io/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1008: Fallback Channels](https://attack.mitre.org/techniques/T1008/)
- [MITRE ATT&CK — Sandworm Team (G0034)](https://attack.mitre.org/groups/G0034/)
- [Threat Intel Report — UAC-0145 Sandworm ClickFix Ukraine (2026-07-17)](../../threat-intel/2026-07-17_cert-gov-ua-uac-0145-sandworm-clickfix-ukraine.md)
