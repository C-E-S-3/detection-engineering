---
scraped_at: 2026-07-24T08:00:00Z
source_url: https://www.huntress.com/blog/fakeagent-sectoprat-claude-ai-malvertising-etherhiding
report_type: threat-intel
severity: high
title: "FakeAgent / SectopRAT: Claude AI Malvertising Campaign with EtherHiding Blockchain C2"
---

# FakeAgent / SectopRAT — Claude AI Malvertising with EtherHiding

**Source:** Huntress Labs  
**Published:** 2026-07-23  
**Severity:** High  

## Summary

Huntress Labs published research on a new **SectopRAT** (also tracked as FakeAgent) campaign using malicious Google Ads to redirect users searching for "Claude AI" to a typosquatting download portal. The landing page impersonates Anthropic's Claude AI desktop application and delivers a trojanized installer that drops SectopRAT.

This campaign is notable for using **EtherHiding** — the technique of storing the live C2 domain in an Ethereum smart contract — making the C2 infrastructure sinkhole-resistant and immune to DNS takedowns.

### Attack Flow

1. **Malvertising**: Victim searches Google for "Claude AI" or "download Claude AI". A sponsored ad leads to a redirect chain.
2. **Redirect**: The victim passes through `claude.ai.download-app.us`, a typosquatting domain designed to appear as an official Anthropic download endpoint.
3. **Payload Delivery**: The landing page serves a signed installer that drops SectopRAT.
4. **C2 Resolution via EtherHiding**: SectopRAT queries a public Ethereum JSON-RPC endpoint (`eth_call`) targeting an attacker-controlled smart contract. The live C2 server address is read from a contract storage slot and decoded. The implant then establishes its primary C2 channel to the resolved address.
5. **Persistence**: SectopRAT establishes persistence via the Windows registry Run key and begins credential and browser session theft.

### EtherHiding C2 Mechanism

EtherHiding was previously documented in Guardio Labs research (2023) and has since been adopted by multiple threat actors including Sandworm/UAC-0145 (CERT-UA advisory, July 2026) and the SmartLoader FakeGit gang (Polygon variant). SectopRAT is now the third confirmed RAT family to adopt this technique in 2026, underscoring the mainstreaming of blockchain-based C2 dead drops.

The key operational advantage: removing or changing the C2 server does not require recompiling the malware — the attacker updates a single transaction on the Ethereum blockchain.

## IOCs

### Domains

| Indicator | Type | Context |
|-----------|------|---------|
| `claude.ai.download-app.us` | Domain | FakeAgent typosquatting redirect portal; impersonates Anthropic Claude AI download page; intermediate redirect to payload delivery |

## MITRE ATT&CK TTPs

| Technique | ID | Notes |
|-----------|----|-------|
| Drive-by Compromise / Malvertising | T1189 | Google Ads used to redirect search traffic to typosquatting download portal |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Domain `claude.ai.download-app.us` mimics Anthropic Claude branding |
| User Execution: Malicious File | T1204.002 | Victim downloads and runs trojanized installer |
| Web Service: Bidirectional Communication | T1102.002 | EtherHiding: smart contract storage queried via `eth_call` to obtain live C2 address |
| Fallback Channels | T1008 | Ethereum smart contract update allows instant C2 pivot without malware recompile |
| Credential from Password Stores: Web Browsers | T1555.003 | SectopRAT browser credential and session cookie theft |
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | SectopRAT registry persistence |

## Kill Chain

- **Delivery** — Malvertising via Google Ads → typosquatting portal
- **Exploitation** — Trojanized installer execution
- **Installation** — SectopRAT persistence via registry
- **Command & Control** — EtherHiding Ethereum smart contract C2 resolution

## Attribution

**SectopRAT / FakeAgent** — Commercially distributed or rented RAT; exact threat actor identity not specified. Campaign attributed to financially motivated threat actors targeting credential theft.

## Detection Notes

The existing **EtherHiding Ethereum Smart Contract C2 Dead Drop** detection (`detections/command_and_control/etherhiding_ethereum_smart_contract_c2.md`) covers the core C2 mechanism used by this campaign. No new detection file created; the redirect domain `claude.ai.download-app.us` is added to IOC tracking.

## References

- [Huntress — FakeAgent SectopRAT Claude AI Malvertising (2026-07-23)](https://www.huntress.com/blog/fakeagent-sectoprat-claude-ai-malvertising-etherhiding)
- [MITRE ATT&CK — T1102.002: Web Service: Bidirectional Communication](https://attack.mitre.org/techniques/T1102/002/)
- [MITRE ATT&CK — T1008: Fallback Channels](https://attack.mitre.org/techniques/T1008/)
- [Guardio Labs — EtherHiding (2023, original research)](https://labs.guard.io/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16)
- [CERT-UA Advisory #6318437 — Sandworm EtherHiding (2026-07-17)](https://cert.gov.ua/article/6318437)
