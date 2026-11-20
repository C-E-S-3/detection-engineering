---
scraped_at: "2026-11-20T00:00:00Z"
source_url: "https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/"
report_type: threat-intel
severity: high
title: "UAT-12643: Suspected North Korea-Aligned Actor Uses Solana Blockchain Transaction Memos for Resilient C2"
---

# UAT-12643: Suspected North Korea-Aligned Actor Uses Solana Blockchain Transaction Memos for Resilient C2

**Source:** Cisco Talos  
**Published:** 2026-11-18  
**Severity:** High  
**Threat Actor:** UAT-12643 (suspected North Korea-aligned)

> **Data Availability Note:** The Talos blog domain (`blog.talosintelligence.com`) was inaccessible from the collection environment during this run. The below content is derived from web search result summaries. Specific IOCs (file hashes, C2 IPs, domains) from the Talos article could not be retrieved; check the source URL directly for the complete IOC list. This report documents the novel TTP.

## Summary

Cisco Talos published research on UAT-12643, a suspected North Korea-aligned threat actor, describing a novel command-and-control technique that embeds C2 server addresses in Solana blockchain transaction memos. This approach provides high availability and censorship resistance for C2 infrastructure — blockchain transactions cannot be taken down by traditional blocklist-based defenses or domain seizures — representing an evolution of the blockchain dead-drop technique beyond previously observed TRON-based approaches.

UAT-12643 delivers a Go-based remote access trojan (RAT) and a Python-based infostealer. The infostealer is designed for targeted credential and sensitive data collection consistent with North Korean intelligence-gathering operations.

## Novel TTP: Solana Transaction Memo as C2 Dead-Drop

UAT-12643's C2 resolution technique works as follows:

1. The implant queries the Solana blockchain for transactions associated with a specific wallet address controlled by the actor.
2. The memo field of the most recent (or specific) transaction contains the encoded C2 server address.
3. The implant decodes and connects to the C2 address retrieved from the blockchain.

This technique eliminates the need for traditional DNS-based C2 resolution. Law enforcement or service providers cannot take down or sinkhole the C2 address by targeting DNS, since the address lives permanently in an immutable blockchain ledger. The only mitigation is to block access to Solana RPC endpoints (e.g., `api.mainnet-beta.solana.com`) or identify and block the wallet address used for the dead-drop.

This technique is distinct from, but closely related to, previously documented blockchain C2 methods:
- **EtherHiding** (2023) — encoded payloads in Ethereum/Binance Smart Chain contract state
- **TRON blockchain dead-drop** — observed in PolinRider/viteVenom campaigns (July 2026, tracked in this repo)
- **ENS TXT record C2** — Dysphoria botnet (tracked in this repo)

UAT-12643's approach using Solana transaction *memos* (the `memo` instruction field on Solana transfers) is newly documented and shifts the detection surface to Solana-specific RPC traffic.

## Toolset

| Tool | Type | Description |
|------|------|-------------|
| Go RAT | Remote Access Trojan | Go-language implant; C2 address resolved via Solana transaction memo dead-drop |
| Python Infostealer | Infostealer | Python-based credential and data collection; targeted collection consistent with DPRK intelligence priorities |

## MITRE ATT&CK TTPs

| Technique | ID | Description |
|-----------|-----|-------------|
| Web Service: Dead Drop Resolver | T1102.001 | Solana blockchain transaction memo used as dead-drop to store and retrieve C2 server address |
| Exfiltration Over C2 Channel | T1041 | Stolen credentials and files exfiltrated via Go RAT C2 channel |
| Steal Web Session Cookie / Credentials from Browser | T1539 / T1555 | Python infostealer harvests browser credentials and session tokens (inferred from DPRK infostealer tradecraft) |

**Primary Tactic:** Command and Control (TA0011)  
**Secondary Tactics:** Credential Access (TA0006), Collection (TA0009)  
**Kill Chain Phase:** C2, Actions on Objectives

## Indicators of Compromise

No specific IOCs (hashes, IPs, domains, Solana wallet addresses) could be retrieved from the source article during this collection run. See the Talos source URL directly:

- https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/
- Talos GitHub IOC repository: https://github.com/Cisco-Talos/IOCs (search for UAT-12643)

## Detection Opportunities

1. **Solana RPC connections from non-cryptocurrency endpoints** — Endpoints that are not cryptocurrency nodes or wallets should rarely connect to `api.mainnet-beta.solana.com` (TCP 443) or other Solana JSON-RPC endpoints. Connections from servers, workstations, or VMs to these endpoints warrant investigation.

2. **Blockchain RPC methods from enterprise hosts** — `getSignaturesForAddress`, `getTransaction`, or `getParsedTransaction` JSON-RPC calls originating from internal enterprise hosts are high-confidence unusual behavior.

3. **Go runtime HTTP connections to blockchain RPC endpoints** — Go binaries (`GOARCH`/`GOOS` in User-Agent, or identified by process inspection) making connections to blockchain RPC APIs from non-developer endpoints.

4. **Python infostealer file access patterns** — Browser credential database access (`Login Data`, `Cookies`, `Web Data`) combined with key ring / credential manager access from a Python interpreter process.

## Splunk Detection Queries

### Query 1 — Connections to Solana RPC Endpoints

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port=443
  AND (All_Traffic.query="api.mainnet-beta.solana.com"
       OR All_Traffic.query="solana-mainnet.g.alchemy.com"
       OR All_Traffic.query="mainnet.helius-rpc.com")
by All_Traffic.src All_Traffic.dest All_Traffic.query All_Traffic.process
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime src dest query process risk_score
```

### Query 2 — Python Process Accessing Multiple Browser Credential Stores

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.process_name IN ("python.exe","python3","python3.exe")
  AND (Filesystem.file_path="*Login Data*"
       OR Filesystem.file_path="*Web Data*"
       OR Filesystem.file_path="*Cookies*"
       OR Filesystem.file_path="*wallet*")
by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| stats dc(file_path) as credential_file_types values(file_path) as files by dest user process_name firstTime lastTime
| where credential_file_types >= 2
| eval risk_score=80
| table firstTime lastTime dest user process_name credential_file_types files risk_score
```

## Associated Threat Actors

| Actor | Type | References |
|-------|------|-----------|
| UAT-12643 | Suspected DPRK-aligned APT | [Cisco Talos (2026-11-18)](https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/) |
| Lazarus Group / DPRK APT Clusters | Nation-State APT (DPRK) | [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) |

## References

- [Cisco Talos — UAT-12643 Blockchain C2 (2026-11-18)](https://blog.talosintelligence.com/uat-12643-suspected-north-korea-aligned-actor-blends-blockchain-resilience-with-targeted-infostealing/)
- [Cisco Talos IOC Repository (GitHub)](https://github.com/Cisco-Talos/IOCs)
- [MITRE ATT&CK — T1102.001 Web Service: Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/)
- [EtherHiding — Blockchain C2 Prior Art (2023)](https://labs.guard.io/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16)
