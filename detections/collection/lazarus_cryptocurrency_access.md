# Lazarus Cryptocurrency Wallet and Exchange Access

## Description

Detects Lazarus Group targeting of cryptocurrency infrastructure by correlating DNS queries to cryptocurrency exchanges/wallets (blockchain, binance, coinbase, metamask, etc.) with endpoint process activity referencing cryptocurrency-related keywords. Lazarus is known for conducting operations targeting cryptocurrency exchanges and individual wallets for financial gain to fund DPRK operations.

False positive sources: Legitimate cryptocurrency usage by employees. Tuning: adjust the unique_crypto_queries threshold and correlate with HR-approved crypto activity.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Data from Local System |
| Technique ID | T1005 |
| Secondary Technique | Automated Collection (T1119) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
`zscaler_dns` OR `infoblox_dns`
| search query IN ("*blockchain*", "*binance*", "*coinbase*", "*kraken*", "*bitstamp*",
                   "*crypto*", "*wallet*", "*metamask*", "*ledger*")
| stats count dc(query) as unique_crypto_queries by src_ip
| where unique_crypto_queries > 10
| join src_ip [
    search `crowdstrike`
    (FileName="*wallet*" OR ProcessCommandLine="*wallet*" OR ProcessCommandLine="*crypto*" OR ProcessCommandLine="*bitcoin*")
]
| table src_ip, ComputerName, unique_crypto_queries, ProcessCommandLine
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| >10 unique crypto DNS queries + matching process activity | High | DNS and process correlation strongly indicates cryptocurrency targeting |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Lazarus Group (HIDDEN COBRA) | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |

## References

- [CISA - AppleJeus: Analysis of North Korea's Cryptocurrency Malware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a)
- [FBI - TraderTraitor: North Korean State-Sponsored APT Targets Blockchain Companies](https://www.ic3.gov/Media/News/2022/220418.pdf)
- [MITRE ATT&CK - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/)
